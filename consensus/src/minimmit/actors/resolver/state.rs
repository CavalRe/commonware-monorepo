//! State management for the minimmit resolver actor.
//!
//! The minimmit resolver tracks certificates to enable view progression.
//! Unlike simplex, minimmit has no certification phase - MNotarizations
//! and Finalizations come from the same notarize votes at different thresholds.

use crate::{Viewable, minimmit::types::Certificate, types::View};
use commonware_cryptography::{Digest, certificate::Scheme};
use commonware_resolver::Resolver;
use commonware_utils::sequence::U64;
use std::collections::BTreeMap;

/// Tracks all known certificates from the floor to the current view.
///
/// Unlike simplex, minimmit has simpler state:
/// - No certification callbacks (MNotarization/Finalization are directly usable)
/// - Floor is set by MNotarization or Finalization
/// - Nullifications are tracked for views above the floor
pub struct State<S: Scheme, D: Digest> {
    /// Highest seen view.
    current_view: View,
    /// Most recent MNotarization or Finalization.
    floor: Option<Certificate<S, D>>,
    /// Nullifications for any view greater than the floor.
    nullifications: BTreeMap<View, Certificate<S, D>>,
    /// Window of requests to send to the resolver.
    fetch_concurrent: usize,
    /// Next view to consider when fetching. Avoids re-scanning
    /// views we've already requested or have nullifications for.
    fetch_floor: View,
}

impl<S: Scheme, D: Digest> State<S, D> {
    /// Create a new instance of [State].
    pub const fn new(fetch_concurrent: usize) -> Self {
        Self {
            current_view: View::zero(),
            floor: None,
            nullifications: BTreeMap::new(),
            fetch_concurrent,
            fetch_floor: View::zero(),
        }
    }

    /// Handle a new certificate and update the [Resolver] accordingly.
    pub fn handle(
        &mut self,
        certificate: Certificate<S, D>,
        resolver: &mut impl Resolver<Key = U64, Subscriber = ()>,
    ) {
        match &certificate {
            Certificate::Nullification(nullification) => {
                let view = nullification.view();
                if self.encounter_view(view) {
                    self.nullifications.insert(view, certificate);
                    resolver.retain(move |key, _| *key != U64::from(view));
                }
            }
            Certificate::MNotarization(m_notarization) => {
                let view = m_notarization.view();
                if self.encounter_view(view) {
                    // MNotarization can set the floor directly (no certification needed)
                    self.floor = Some(certificate);
                    self.prune(resolver);
                }
            }
            Certificate::Finalization(finalization) => {
                let view = finalization.view();
                if self.encounter_view(view) || self.can_upgrade_floor(view) {
                    // Finalization is stronger than MNotarization
                    self.floor = Some(certificate);
                    self.prune(resolver);
                }
            }
        }

        // Request missing nullifications
        self.fetch(resolver);
    }

    /// Get the best certificate for a given view (or the floor
    /// if the view is below the floor).
    pub fn get(&self, view: View) -> Option<&Certificate<S, D>> {
        // If view is <= floor, return the floor
        if let Some(floor) = &self.floor
            && view <= floor.view()
        {
            return Some(floor);
        }

        // Otherwise, return the nullification for the view if it exists
        self.nullifications.get(&view)
    }

    /// Updates the current view if the new view is greater.
    ///
    /// Returns true if the view is "interesting" (i.e. greater than the floor).
    fn encounter_view(&mut self, view: View) -> bool {
        self.current_view = self.current_view.max(view);
        view > self.floor_view()
    }

    /// Get the view of the floor.
    fn floor_view(&self) -> View {
        self.floor
            .as_ref()
            .map(|floor| floor.view())
            .unwrap_or(View::zero())
    }

    /// Returns true if the floor can be upgraded at the given view.
    ///
    /// A Finalization can upgrade an MNotarization at the same view since
    /// Finalization is a stronger proof than MNotarization.
    fn can_upgrade_floor(&self, view: View) -> bool {
        matches!(
            self.floor.as_ref(),
            Some(Certificate::MNotarization(m)) if m.view() == view
        )
    }

    /// Inform the [Resolver] of any missing nullifications.
    fn fetch(&mut self, resolver: &mut impl Resolver<Key = U64, Subscriber = ()>) {
        // We must either receive a nullification at the current view or an
        // MNotarization/Finalization at the current view or higher, so we
        // don't need to worry about getting stuck.
        let start = self.fetch_floor.max(self.floor_view().next());
        let views: Vec<_> = View::range(start, self.current_view)
            .filter(|view| !self.nullifications.contains_key(view))
            .take(self.fetch_concurrent)
            .collect();

        // Update the fetch floor to reduce duplicate iteration in the future.
        if let Some(&last) = views.last() {
            self.fetch_floor = last.next();
        }

        // Send the requests to the resolver.
        let requests = views.into_iter().map(U64::from).collect();
        resolver.fetch_all(requests);
    }

    /// Prune stored certificates and requests that are not higher than the floor.
    fn prune(&mut self, resolver: &mut impl Resolver<Key = U64, Subscriber = ()>) {
        let floor = self.floor_view();
        self.nullifications.retain(|view, _| *view > floor);
        resolver.retain(move |key, _| *key > floor.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        minimmit::{
            scheme::ed25519,
            types::{Finalization, MNotarization, Notarize, Nullification, Nullify, Proposal},
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_parallel::Sequential;
    use commonware_utils::{sync::Mutex, test_rng};
    use std::{collections::BTreeSet, sync::Arc};

    const NAMESPACE: &[u8] = b"minimmit-resolver-state";
    const EPOCH: Epoch = Epoch::new(9);

    type TestScheme = ed25519::Scheme;

    #[derive(Clone, Default)]
    struct MockResolver {
        outstanding: Arc<Mutex<BTreeSet<U64>>>,
    }

    impl MockResolver {
        fn outstanding(&self) -> Vec<u64> {
            self.outstanding
                .lock()
                .iter()
                .map(|key| key.into())
                .collect()
        }
    }

    impl Resolver for MockResolver {
        type Key = U64;
        type Subscriber = ();
        fn fetch<F: Into<commonware_resolver::Fetch<U64, ()>> + Send>(
            &mut self,
            request: F,
        ) -> commonware_actor::Feedback {
            self.outstanding.lock().insert(request.into().key);
            commonware_actor::Feedback::Ok
        }
        fn fetch_all<F: Into<commonware_resolver::Fetch<U64, ()>> + Send>(
            &mut self,
            requests: Vec<F>,
        ) -> commonware_actor::Feedback {
            for request in requests {
                self.fetch(request);
            }
            commonware_actor::Feedback::Ok
        }
        fn retain(
            &mut self,
            predicate: impl Fn(&Self::Key, &()) -> bool + Send + 'static,
        ) -> commonware_actor::Feedback {
            self.outstanding.lock().retain(|key| predicate(key, &()));
            commonware_actor::Feedback::Ok
        }
    }

    fn ed25519_fixture() -> (Vec<TestScheme>, TestScheme) {
        let mut rng = test_rng();
        // n=6 for 5f+1 model (f=1, so 2f+1=3 for M-quorum, n-f=5 for L-quorum)
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, NAMESPACE, 6);
        (schemes, verifier)
    }

    fn build_nullification(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        view: View,
    ) -> Nullification<TestScheme> {
        let round = Round::new(EPOCH, view);
        // Need 2f+1 = 3 votes for M-quorum
        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).unwrap())
            .collect();
        Nullification::from_nullifies(verifier, &votes, &Sequential).expect("nullification quorum")
    }

    fn build_m_notarization(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        view: View,
    ) -> MNotarization<TestScheme, Sha256Digest> {
        let parent_view = view.previous().unwrap_or(View::zero());
        // Parent payload uses a deterministic value based on parent view
        let parent_payload = Sha256Digest::from([parent_view.get() as u8; 32]);
        let proposal = Proposal::new(
            Round::new(EPOCH, view),
            parent_view,
            parent_payload,
            Sha256Digest::from([view.get() as u8; 32]),
        );
        // Need 2f+1 = 3 votes for M-quorum
        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        MNotarization::from_notarizes(verifier, &votes, &Sequential).expect("m-notarization quorum")
    }

    fn build_finalization(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        view: View,
    ) -> Finalization<TestScheme, Sha256Digest> {
        let parent_view = view.previous().unwrap_or(View::zero());
        // Parent payload uses a deterministic value based on parent view
        let parent_payload = Sha256Digest::from([parent_view.get() as u8; 32]);
        let proposal = Proposal::new(
            Round::new(EPOCH, view),
            parent_view,
            parent_payload,
            Sha256Digest::from([view.get() as u8; 32]),
        );
        // Need n-f = 5 votes for L-quorum
        let votes: Vec<_> = schemes
            .iter()
            .take(5)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Finalization::from_notarizes(verifier, &votes, &Sequential).expect("finalization quorum")
    }

    #[test]
    fn handle_nullification_requests_missing_views() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(2);
        let mut resolver = MockResolver::default();

        let nullification_v4 = build_nullification(&schemes, &verifier, View::new(4));
        state.handle(
            Certificate::Nullification(nullification_v4.clone()),
            &mut resolver,
        );
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == &nullification_v4)
        );
        assert_eq!(resolver.outstanding(), vec![1, 2]); // limited to concurrency

        let nullification_v2 = build_nullification(&schemes, &verifier, View::new(2));
        state.handle(
            Certificate::Nullification(nullification_v2.clone()),
            &mut resolver,
        );
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Nullification(n)) if n == &nullification_v2)
        );
        assert_eq!(resolver.outstanding(), vec![1, 3]); // limited to concurrency

        let nullification_v1 = build_nullification(&schemes, &verifier, View::new(1));
        state.handle(
            Certificate::Nullification(nullification_v1.clone()),
            &mut resolver,
        );
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Nullification(n)) if n == &nullification_v1)
        );
        assert_eq!(resolver.outstanding(), vec![3]);
    }

    #[test]
    fn m_notarization_sets_floor_and_prunes() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(10);
        let mut resolver = MockResolver::default();

        // Add some nullifications
        for view in 4..=6 {
            let nullification = build_nullification(&schemes, &verifier, View::new(view));
            state.handle(Certificate::Nullification(nullification), &mut resolver);
        }
        assert_eq!(state.current_view, View::new(6));
        assert_eq!(resolver.outstanding(), vec![1, 2, 3]);

        // MNotarization sets floor and prunes (unlike simplex, no certification needed)
        let m_notarization = build_m_notarization(&schemes, &verifier, View::new(5));
        state.handle(
            Certificate::MNotarization(m_notarization.clone()),
            &mut resolver,
        );

        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::MNotarization(m)) if m == &m_notarization)
        );
        // Nullifications at/below floor should be pruned
        assert_eq!(state.nullifications.len(), 1); // only v6 remains
        // Requests below floor should be cancelled
        assert!(resolver.outstanding().is_empty());
    }

    #[test]
    fn finalization_sets_floor() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(10);
        let mut resolver = MockResolver::default();

        let finalization = build_finalization(&schemes, &verifier, View::new(3));
        state.handle(
            Certificate::Finalization(finalization.clone()),
            &mut resolver,
        );
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Finalization(f)) if f == &finalization)
        );
    }

    #[test]
    fn finalization_upgrades_m_notarization_at_same_view() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(10);
        let mut resolver = MockResolver::default();

        // MNotarization at view 5
        let m_notarization = build_m_notarization(&schemes, &verifier, View::new(5));
        state.handle(
            Certificate::MNotarization(m_notarization.clone()),
            &mut resolver,
        );

        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::MNotarization(m)) if m == &m_notarization)
        );

        // Finalization at same view should upgrade the floor
        let finalization = build_finalization(&schemes, &verifier, View::new(5));
        state.handle(
            Certificate::Finalization(finalization.clone()),
            &mut resolver,
        );

        // Floor should now be the finalization (stronger proof)
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Finalization(f)) if f == &finalization)
        );
    }

    #[test]
    fn get_returns_floor_for_views_at_or_below() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(2);
        let mut resolver = MockResolver::default();

        // Finalization sets floor
        let finalization = build_finalization(&schemes, &verifier, View::new(3));
        state.handle(
            Certificate::Finalization(finalization.clone()),
            &mut resolver,
        );
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Finalization(f)) if f == &finalization)
        );
        assert!(
            matches!(state.get(View::new(3)), Some(Certificate::Finalization(f)) if f == &finalization)
        );

        // New nullification above floor is kept
        let nullification_v4 = build_nullification(&schemes, &verifier, View::new(4));
        state.handle(
            Certificate::Nullification(nullification_v4.clone()),
            &mut resolver,
        );
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == &nullification_v4)
        );
        // Views at/below floor still return floor
        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Finalization(f)) if f == &finalization)
        );

        // Old nullification below floor is ignored
        let nullification_v1 = build_nullification(&schemes, &verifier, View::new(1));
        state.handle(Certificate::Nullification(nullification_v1), &mut resolver);
        // Still returns floor for view 1
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Finalization(f)) if f == &finalization)
        );
    }
}
