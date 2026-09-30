//! Ed25519 implementation of the [`Scheme`] trait for `minimmit`.
//!
//! [`Scheme`] is **attributable**: individual signatures can be safely
//! presented to some third party as evidence of either liveness or of committing a fault. Certificates
//! contain signer indices alongside individual signatures, enabling secure
//! per-validator activity tracking and fault detection.

use crate::minimmit::{scheme::Namespace, types::Subject};
use commonware_cryptography::impl_certificate_ed25519;

impl_certificate_ed25519!(Subject<'a, D>, Namespace, crate::minimmit::M5f1);

mod full {
    use super::*;
    impl_certificate_ed25519!(Subject<'a, D>, Namespace, commonware_utils::N5f1);
}
impl super::QuorumScheme for Scheme {
    fn assemble_quorum<I, F>(
        &self,
        attestations: I,
        _strategy: &impl commonware_parallel::Strategy,
    ) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = commonware_cryptography::certificate::Attestation<Self>>,
        I::IntoIter: Send,
        F: commonware_utils::Faults,
    {
        use commonware_utils::{Faults, iter::NonEmpty};
        let mut attestations = attestations.into_iter();
        let first = attestations.next()?;
        let n = self.generic.participants.len() as u32;
        if F::quorum(n) == commonware_utils::N5f1::quorum(n) {
            let convert = |a: commonware_cryptography::certificate::Attestation<Self>| {
                commonware_cryptography::certificate::Attestation {
                    signer: a.signer,
                    signature: a.signature,
                }
            };
            self.generic
                .assemble::<full::Scheme, _>(NonEmpty::new(
                    convert(first),
                    attestations.map(convert),
                ))
                .ok()
        } else if F::quorum(n) == crate::minimmit::M5f1::quorum(n) {
            self.generic
                .assemble::<Self, _>(NonEmpty::new(first, attestations))
                .ok()
        } else {
            None
        }
    }
    fn verify_quorum<R, D, F>(
        &self,
        rng: &mut R,
        subject: Subject<'_, D>,
        certificate: &Self::Certificate,
        strategy: &impl commonware_parallel::Strategy,
    ) -> bool
    where
        R: rand_core::CryptoRng,
        D: commonware_cryptography::Digest,
        F: commonware_utils::Faults,
    {
        use commonware_utils::Faults;
        let n = self.generic.participants.len() as u32;
        if F::quorum(n) == commonware_utils::N5f1::quorum(n) {
            self.generic.verify_certificate::<full::Scheme, _, D>(
                rng,
                subject,
                certificate,
                strategy,
            )
        } else if F::quorum(n) == crate::minimmit::M5f1::quorum(n) {
            self.generic
                .verify_certificate::<Self, _, D>(rng, subject, certificate, strategy)
        } else {
            false
        }
    }
}
