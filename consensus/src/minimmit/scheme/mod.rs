//! Signing scheme implementations for `minimmit`.
//!
//! # Attributable Schemes and Fault Evidence
//!
//! Signing schemes differ in whether per-validator activities can be used as evidence of either
//! liveness or of committing a fault. See [`crate::simplex::scheme`] for details on attributable
//! vs non-attributable schemes.

use crate::minimmit::types::Subject;
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::{Digest, certificate};
use commonware_utils::union;

pub mod bls12381_multisig;
pub mod bls12381_threshold;
pub mod ed25519;
pub mod secp256r1;

/// Pre-computed namespaces for minimmit voting subjects.
///
/// This struct holds the pre-computed namespace bytes for each vote type.
/// Unlike Simplex, Minimmit has no finalize namespace since finalization
/// uses the same notarize votes (just with a higher threshold).
///
/// Unlike Simplex, Minimmit does not use seed signatures for VRF-based leader
/// election. The BLS threshold scheme uses aggregated signatures for M-quorum
/// and threshold recovery for L-quorum, prioritizing security over random election.
#[derive(Clone, Debug)]
pub struct Namespace {
    /// Namespace for notarize votes/certificates.
    pub notarize: Vec<u8>,
    /// Namespace for nullify votes/certificates.
    pub nullify: Vec<u8>,
}

impl Namespace {
    /// Creates a new Namespace from a base namespace.
    pub fn new(namespace: &[u8]) -> Self {
        Self {
            notarize: notarize_namespace(namespace),
            nullify: nullify_namespace(namespace),
        }
    }
}

impl certificate::Namespace for Namespace {
    fn derive(namespace: &[u8]) -> Self {
        Self::new(namespace)
    }
}

impl<'a, D: Digest> certificate::Subject for Subject<'a, D> {
    type Namespace = Namespace;

    fn namespace<'b>(&self, derived: &'b Self::Namespace) -> &'b [u8] {
        match self {
            Self::Notarize { .. } => &derived.notarize,
            Self::Nullify { .. } => &derived.nullify,
        }
    }

    fn message(&self) -> Bytes {
        match self {
            Self::Notarize { proposal } => proposal.encode(),
            Self::Nullify { round } => round.encode(),
        }
    }
}

/// Marker trait for signing schemes compatible with `minimmit`.
///
/// This trait binds a [`certificate::Scheme`] to the [`Subject`] subject type
/// used by the minimmit protocol. It is automatically implemented for any scheme
/// whose subject type matches `Subject<'a, D>`.
pub trait Scheme<D: Digest>:
    QuorumScheme + for<'a> certificate::Scheme<Subject<'a, D> = Subject<'a, D>>
{
}

impl<D: Digest, S> Scheme<D> for S where
    S: QuorumScheme + for<'a> certificate::Scheme<Subject<'a, D> = Subject<'a, D>>
{
}

/// Certificate operations with an explicit Minimmit quorum. The current
/// Commonware certificate API fixes one fault model per scheme; Minimmit must
/// distinguish progress certificates from finalization certificates.
pub trait QuorumScheme: certificate::Scheme {
    fn assemble_quorum<I, F>(
        &self,
        attestations: I,
        strategy: &impl commonware_parallel::Strategy,
    ) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = certificate::Attestation<Self>>,
        I::IntoIter: Send,
        F: commonware_utils::Faults;
    fn verify_quorum<R, D, F>(
        &self,
        rng: &mut R,
        subject: Self::Subject<'_, D>,
        certificate: &Self::Certificate,
        strategy: &impl commonware_parallel::Strategy,
    ) -> bool
    where
        R: rand_core::CryptoRng,
        D: Digest,
        F: commonware_utils::Faults;
    fn verify_quorums<'a, R, D, I, F>(
        &self,
        rng: &mut R,
        certificates: I,
        strategy: &impl commonware_parallel::Strategy,
    ) -> bool
    where
        R: rand_core::CryptoRng,
        D: Digest,
        I: Iterator<Item = (Self::Subject<'a, D>, &'a Self::Certificate)>,
        F: commonware_utils::Faults,
    {
        certificates.into_iter().all(|(subject, certificate)| {
            self.verify_quorum::<_, D, F>(rng, subject, certificate, strategy)
        })
    }
}

// Constants for domain separation in signature verification
// These are used to prevent cross-protocol attacks and message-type confusion
const NOTARIZE_SUFFIX: &[u8] = b"_MINIMMIT_NOTARIZE";
const NULLIFY_SUFFIX: &[u8] = b"_MINIMMIT_NULLIFY";

/// Creates a namespace for notarize messages by appending the NOTARIZE_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
pub(crate) fn notarize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NOTARIZE_SUFFIX)
}

/// Creates a namespace for nullify messages by appending the NULLIFY_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
pub(crate) fn nullify_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NULLIFY_SUFFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_creation() {
        let ns = Namespace::new(b"test");
        assert_eq!(ns.notarize, b"test_MINIMMIT_NOTARIZE");
        assert_eq!(ns.nullify, b"test_MINIMMIT_NULLIFY");
    }

    #[test]
    fn test_namespace_domain_separation() {
        // Ensure minimmit namespaces don't collide with simplex
        let minimmit_ns = Namespace::new(b"app");
        let simplex_ns = crate::simplex::scheme::Namespace::new(b"app");

        assert_ne!(minimmit_ns.notarize, simplex_ns.notarize);
        assert_ne!(minimmit_ns.nullify, simplex_ns.nullify);
    }

    // The 2026.9 certificate API fixes one fault model per scheme. Exercise the
    // port's explicit quorum boundary for every supported implementation.
    fn assert_quorum_boundary<S>(fixture: certificate::mocks::Fixture<S>)
    where
        S: Scheme<commonware_cryptography::sha256::Digest>,
    {
        use crate::{
            minimmit::types::{Finalization, MNotarization, Notarize, Proposal},
            types::{Epoch, Round, View},
        };
        use commonware_cryptography::sha256::Digest;
        use commonware_parallel::Sequential;
        let mut rng = commonware_utils::TestRng::new(71);
        let proposal = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            Digest::from([0; 32]),
            Digest::from([1; 32]),
        );
        let votes: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let mini = MNotarization::from_notarizes(&fixture.verifier, votes[..3].iter(), &Sequential)
            .unwrap();
        assert!(mini.verify(&mut rng, &fixture.verifier, &Sequential));
        let forged_finalization = Finalization {
            proposal: mini.proposal,
            certificate: mini.certificate,
        };
        assert!(!forged_finalization.verify(&mut rng, &fixture.verifier, &Sequential));
        assert!(
            Finalization::from_notarizes(&fixture.verifier, votes[..4].iter(), &Sequential)
                .is_none()
        );
        let full = Finalization::from_notarizes(&fixture.verifier, votes[..5].iter(), &Sequential)
            .unwrap();
        assert!(full.verify(&mut rng, &fixture.verifier, &Sequential));
    }

    #[test]
    fn progress_certificates_cannot_be_used_as_finalizations() {
        use commonware_cryptography::bls12381::primitives::variant::{MinPk, MinSig};
        let mut rng = commonware_utils::TestRng::new(70);
        let ns = b"minimmit-port-quorum-regression";
        assert_quorum_boundary(ed25519::fixture(&mut rng, ns, 6));
        assert_quorum_boundary(secp256r1::fixture(&mut rng, ns, 6));
        assert_quorum_boundary(bls12381_multisig::fixture::<MinPk, _>(&mut rng, ns, 6));
        assert_quorum_boundary(bls12381_multisig::fixture::<MinSig, _>(&mut rng, ns, 6));
        assert_quorum_boundary(bls12381_threshold::fixture::<MinPk, _>(&mut rng, ns, 6));
        assert_quorum_boundary(bls12381_threshold::fixture::<MinSig, _>(&mut rng, ns, 6));
    }
}
