//! Independent verification of Multimmit's canonical producer-block order.
//!
//! A consumer pins an epoch's protocol and certificate-verification keys, then supplies an L-QC,
//! its oldest-first tip-history openings, and the producer headers needed to resolve ancestry.
//! [`Verifier`] authenticates the certificate and reconstructs the same order as marshal without
//! storage, networking, or a runtime. It works on native and WASM targets.
//!
//! [`crate::multimmit::types::Activity::ProtocolAccepted`] exposes L-QCs and
//! [`crate::multimmit::types::Activity::HistoryAccepted`] exposes history openings. These
//! best-effort events are transport inputs, not proofs by themselves. A server must retain or
//! retrieve any missing openings and headers before a client can advance.
//!
//! Returned references authenticate producer headers and their application-body commitments.
//! They do not verify application execution, state roots, or availability. Consumers must check
//! body commitments themselves. A node's claimed output index is never an input to verification.

#[cfg(any(test, feature = "mocks"))]
pub(crate) mod fuzz;
pub(crate) mod order;

use self::order::{FinalSweep, HistoryState, Reconciliation, SlotStream};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        config::Protocol,
        scheme::bls12381_threshold::Scheme,
        types::{BlockRef, Lqc, TipRecord, TransactionBlockHeader, genesis_history},
    },
    types::{Height, View},
};
use commonware_cryptography::{Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_parallel::Strategy;
use rand_core::CryptoRng;
use std::{collections::BTreeMap, marker::PhantomData};

/// Bounds on one verification call, including repeated ancestry work.
///
/// Decode certificates with the pinned protocol's codec configuration and impose a byte limit
/// before decoding. These bounds apply to already-decoded inputs and do not bound transport
/// buffers or certificate decoding.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum supplied history records.
    pub histories: usize,
    /// Maximum supplied producer headers.
    pub headers: usize,
    /// Maximum emitted references.
    pub outputs: usize,
    /// Maximum ancestry edges and ordering slots examined, including duplicates.
    pub steps: usize,
}

/// An independent ordering proof could not be accepted.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The configured keys and protocol disagree.
    #[error("certificate verifier parameters do not match the pinned protocol")]
    Parameters,
    /// A resource bound was exceeded.
    #[error("ordering proof exceeds a resource limit")]
    Limit,
    /// The L-QC is invalid or belongs to another epoch.
    #[error("invalid leader quorum certificate")]
    Certificate,
    /// A certificate precedes the accepted view.
    #[error("ordering proof regresses the accepted view")]
    View,
    /// The supplied history does not extend the pinned history to the certificate commitment.
    #[error("ordering proof has invalid tip history")]
    History,
    /// A required producer header is missing or malformed.
    #[error("ordering proof has missing or invalid ancestry")]
    Ancestry,
    /// The proof's frontiers cannot be reconciled with the accepted stream.
    #[error("ordering proof conflicts with the accepted stream")]
    Order,
}

/// A runtime-independent, incremental ordering verifier for one pinned epoch.
///
/// Failed calls leave the accepted state unchanged. Proofs may skip views but must open every
/// history link back to the accepted commitment. Repeated certificates emit no duplicate blocks.
/// Keep this verifier across calls; reconstructing it from an untrusted node's frontier would
/// replace independent verification with trust in that node.
pub struct Verifier<H: Hasher, P: PublicKey, V: Variant> {
    protocol: Protocol<H::Digest>,
    scheme: Scheme<P, V>,
    state: HistoryState<H::Digest>,
    view: View,
    limits: Limits,
    _hasher: PhantomData<H>,
}

impl<H: Hasher, P: PublicKey, V: Variant> Verifier<H, P, V> {
    /// Pins the trusted protocol, including genesis, and the trusted certificate keys.
    pub fn new(
        protocol: Protocol<H::Digest>,
        scheme: Scheme<P, V>,
        limits: Limits,
    ) -> Result<Self, Error> {
        if protocol.parameters() != scheme.parameters() {
            return Err(Error::Parameters);
        }
        let genesis = protocol.genesis();
        let state = HistoryState::new(
            genesis_history::<H>(genesis),
            genesis.tips().to_vec(),
            genesis.tips().to_vec(),
        )
        .map_err(|_| Error::Order)?;
        Ok(Self {
            protocol,
            scheme,
            state,
            view: View::zero(),
            limits,
            _hasher: PhantomData,
        })
    }

    /// Returns the accepted history commitment for requesting subsequent openings.
    pub const fn history(&self) -> H::Digest {
        self.state.history()
    }

    /// Returns the last independently emitted producer reference on each chain.
    pub fn emitted(&self) -> &[BlockRef<H::Digest>] {
        self.state.emitted()
    }

    /// Authenticates a certificate and advances the canonical stream atomically.
    ///
    /// `history` is oldest first and ends at the certificate's history commitment. `headers`
    /// supplies the hash-linked ancestry required for both reconciliation and emitted blocks;
    /// order is immaterial. The RNG must provide fresh, unpredictable cryptographic randomness
    /// for certificate batch verification, independent of the untrusted proof.
    pub fn verify(
        &mut self,
        rng: &mut impl CryptoRng,
        certificate: &Lqc<V, H::Digest>,
        history: &[TipRecord<H::Digest>],
        headers: &[TransactionBlockHeader<H::Digest>],
        strategy: &impl Strategy,
    ) -> Result<Vec<BlockRef<H::Digest>>, Error> {
        if history.len() > self.limits.histories || headers.len() > self.limits.headers {
            return Err(Error::Limit);
        }
        if certificate.view() < self.view {
            return Err(Error::View);
        }
        if self
            .scheme
            .verify_lqc::<_, H, _>(rng, certificate, strategy)
            .is_none()
        {
            return Err(Error::Certificate);
        }
        let mut paths = Paths::<H> {
            headers: BTreeMap::new(),
            resolved: BTreeMap::new(),
            steps: self.limits.steps,
        };
        for header in headers {
            if header.epoch() != self.protocol.epoch() {
                return Err(Error::Ancestry);
            }
            paths.headers.insert(header.block_ref::<H>(), header);
        }
        // Authenticate the entire history chain before deriving any output.
        let mut commitment = self.state.history();
        for record in history {
            if record.parent() != commitment
                || record.tips().len() != self.protocol.producers().len()
            {
                return Err(Error::History);
            }
            commitment = record.commitment::<H>();
        }
        if commitment != certificate.leader().history() {
            return Err(Error::History);
        }
        let mut next = self.state.clone();
        let mut outputs = Vec::new();
        for record in history {
            let common = paths.common(record.tips(), next.emitted())?;
            next.validate_opening::<H>(record.commitment::<H>(), record, &common)
                .map_err(|_| Error::Order)?;
            let stream = SlotStream::new(next.ordered(), record.tips(), record.proposed())
                .map_err(|_| Error::Order)?;
            paths.emit(&mut next, stream, &mut outputs, self.limits.outputs)?;
            next.finish_opening::<H>(record.commitment::<H>(), record)
                .map_err(|_| Error::Order)?;
        }
        // Final extraction and both ordering passes are shared with marshal.
        let stream =
            FinalSweep::from_lqc::<H, V>(next.ordered(), certificate, self.protocol.codec_config())
                .map_err(|_| Error::Order)?
                .into_stream();
        let common = paths.common(stream.target(), next.emitted())?;
        next.validate_reconciliation(stream.target(), &common)
            .map_err(|_| Error::Order)?;
        paths.emit(&mut next, stream, &mut outputs, self.limits.outputs)?;
        self.state = next;
        self.view = certificate.view();
        Ok(outputs)
    }
}

type Resolved<D> = BTreeMap<(BlockRef<D>, Height), BlockRef<D>>;

struct Paths<'a, H: Hasher> {
    headers: BTreeMap<BlockRef<H::Digest>, &'a TransactionBlockHeader<H::Digest>>,
    resolved: Resolved<H::Digest>,
    steps: usize,
}

impl<H: Hasher> Paths<'_, H> {
    fn step(&mut self) -> Result<(), Error> {
        self.steps = self.steps.checked_sub(1).ok_or(Error::Limit)?;
        Ok(())
    }

    fn ancestor(
        &mut self,
        mut tip: BlockRef<H::Digest>,
        height: Height,
    ) -> Result<BlockRef<H::Digest>, Error> {
        if tip.height() < height {
            return Err(Error::Ancestry);
        }
        let root = tip;
        if let Some(reference) = self.resolved.get(&(root, height)) {
            return Ok(*reference);
        }
        while tip.height() > height {
            self.step()?;
            self.resolved.insert((root, tip.height()), tip);
            let header = self.headers.get(&tip).ok_or(Error::Ancestry)?;
            tip = header.parent_ref();
        }
        self.resolved.insert((root, tip.height()), tip);
        Ok(tip)
    }

    fn common(
        &mut self,
        target: &[BlockRef<H::Digest>],
        emitted: &[BlockRef<H::Digest>],
    ) -> Result<Vec<BlockRef<H::Digest>>, Error> {
        if target.len() != emitted.len() {
            return Err(Error::Order);
        }
        target
            .iter()
            .zip(emitted)
            .map(|(target, emitted)| {
                if target.chain() != emitted.chain() {
                    return Err(Error::Order);
                }
                let (high, low) = if target.height() > emitted.height() {
                    (*target, *emitted)
                } else {
                    (*emitted, *target)
                };
                self.ancestor(high, low.height())
            })
            .collect()
    }

    fn emit(
        &mut self,
        state: &mut HistoryState<H::Digest>,
        stream: SlotStream<H::Digest>,
        outputs: &mut Vec<BlockRef<H::Digest>>,
        limit: usize,
    ) -> Result<(), Error> {
        for slot in stream {
            self.step()?;
            let reference = self.ancestor(slot.tip(), slot.height())?;
            if state.reconcile(slot, reference).map_err(|_| Error::Order)? == Reconciliation::Emit {
                if outputs.len() == limit {
                    return Err(Error::Limit);
                }
                outputs.push(reference);
            }
        }
        Ok(())
    }
}
