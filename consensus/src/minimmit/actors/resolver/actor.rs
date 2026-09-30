//! Resolver actor implementation.

use super::{
    Config,
    ingress::{Handler, HandlerMessage, Mailbox, MailboxMessage},
    state::State,
};
use crate::{
    Epochable, Viewable,
    minimmit::{actors::voter, scheme::Scheme, types::Certificate},
    types::{Epoch, View},
};
use bytes::Bytes;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Sender, utils::StaticProvider};
use commonware_parallel::Strategy;
use commonware_resolver::{Resolver, p2p};
use commonware_runtime::{BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::{
    channel::{fallible::OneshotExt, mpsc},
    ordered::Quorum,
    sequence::U64,
};
use rand_core::CryptoRng;
use std::time::Duration;
use tracing::debug;

/// Resolver actor for Minimmit consensus.
///
/// The resolver fetches missing certificates from peers to enable view progression.
/// Unlike simplex, minimmit has no certification phase - MNotarizations and
/// Finalizations can be used directly without additional verification.
pub struct Actor<E, S, B, D, T>
where
    E: Clock + CryptoRng + Spawner + Metrics + commonware_runtime::Supervisor,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    T: Strategy,
{
    context: ContextCell<E>,
    scheme: S,
    blocker: Option<B>,
    strategy: T,

    epoch: Epoch,
    mailbox_size: usize,
    fetch_timeout: Duration,

    state: State<S, D>,

    mailbox_receiver: mpsc::Receiver<MailboxMessage<S, D>>,
}

impl<E, S, B, D, T> Actor<E, S, B, D, T>
where
    E: BufferPooler + Clock + CryptoRng + Spawner + Metrics + commonware_runtime::Supervisor,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    T: Strategy,
{
    /// Create a new resolver actor.
    pub fn new(context: E, cfg: Config<S, B, T>) -> (Self, Mailbox<S, D>) {
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                scheme: cfg.scheme,
                blocker: Some(cfg.blocker),
                strategy: cfg.strategy,

                epoch: cfg.epoch,
                mailbox_size: cfg.mailbox_size,
                fetch_timeout: cfg.fetch_timeout,

                state: State::new(cfg.fetch_concurrent),

                mailbox_receiver: receiver,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the resolver actor.
    pub fn start(
        mut self,
        voter: voter::Mailbox<S, D>,
        sender: impl Sender<PublicKey = S::PublicKey>,
        receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(voter, sender, receiver))
    }

    async fn run(
        mut self,
        mut voter: voter::Mailbox<S, D>,
        sender: impl Sender<PublicKey = S::PublicKey>,
        receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) {
        let participants = self.scheme.participants().clone();
        let me = self
            .scheme
            .me()
            .and_then(|index| participants.key(index))
            .cloned();

        let (handler_tx, mut handler_rx) = mpsc::channel(self.mailbox_size);
        let handler = Handler::new(handler_tx);

        let (resolver_engine, mut resolver) = p2p::Engine::new(
            self.context.child("resolver"),
            p2p::Config {
                peer_provider: StaticProvider::new(self.epoch.get(), participants),
                blocker: self.blocker.take().expect("blocker must be set"),
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: std::num::NonZeroUsize::new(self.mailbox_size)
                    .expect("nonzero mailbox"),
                me,
                timeout: self.fetch_timeout,
                fetch_retry_timeout: self.fetch_timeout,
                priority_requests: true,
                priority_responses: false,
            },
        );
        let mut resolver_task = resolver_engine.start((sender, receiver));

        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping resolver");
            },
            _ = &mut resolver_task => {
                break;
            },
            Some(message) = self.mailbox_receiver.recv() else break => {
                match message {
                    MailboxMessage::Certificate(certificate) => {
                        self.state.handle(certificate, &mut resolver);
                    }
                }
            },
            Some(message) = handler_rx.recv() else break => {
                self.handle_resolver(message, &mut voter, &mut resolver);
            },
        }
    }

    /// Validates an incoming message, returning the parsed message if valid.
    fn validate(&mut self, view: View, data: Bytes) -> Option<Certificate<S, D>> {
        // Decode message
        let incoming =
            Certificate::<S, D>::decode_cfg(data, &self.scheme.certificate_codec_config()).ok()?;

        // Validate message
        match incoming {
            Certificate::MNotarization(m_notarization) => {
                let m_notarization_view = m_notarization.view();
                if m_notarization_view < view {
                    debug!(%view, received = %m_notarization_view, "m-notarization below view");
                    return None;
                }
                if m_notarization.epoch() != self.epoch {
                    debug!(
                        epoch = %m_notarization.epoch(),
                        expected = %self.epoch,
                        "rejecting m-notarization from different epoch"
                    );
                    return None;
                }
                if !m_notarization.verify(&mut self.context, &self.scheme, &self.strategy) {
                    debug!(%view, "m-notarization failed verification");
                    return None;
                }
                debug!(%view, received = %m_notarization_view, "received m-notarization for request");
                Some(Certificate::MNotarization(m_notarization))
            }
            Certificate::Finalization(finalization) => {
                if finalization.view() < view {
                    debug!(%view, received = %finalization.view(), "finalization below view");
                    return None;
                }
                if finalization.epoch() != self.epoch {
                    debug!(
                        epoch = %finalization.epoch(),
                        expected = %self.epoch,
                        "rejecting finalization from different epoch"
                    );
                    return None;
                }
                if !finalization.verify(&mut self.context, &self.scheme, &self.strategy) {
                    debug!(%view, "finalization failed verification");
                    return None;
                }
                debug!(%view, received = %finalization.view(), "received finalization for request");
                Some(Certificate::Finalization(finalization))
            }
            Certificate::Nullification(nullification) => {
                if nullification.view() != view {
                    debug!(%view, received = %nullification.view(), "nullification view mismatch");
                    return None;
                }
                if nullification.epoch() != self.epoch {
                    debug!(
                        epoch = %nullification.epoch(),
                        expected = %self.epoch,
                        "rejecting nullification from different epoch"
                    );
                    return None;
                }
                if !nullification.verify::<_, D>(&mut self.context, &self.scheme, &self.strategy) {
                    debug!(%view, "nullification failed verification");
                    return None;
                }
                debug!(%view, received = %nullification.view(), "received nullification for request");
                Some(Certificate::Nullification(nullification))
            }
        }
    }

    /// Handles a message from the [p2p::Engine].
    fn handle_resolver(
        &mut self,
        message: HandlerMessage,
        voter: &mut voter::Mailbox<S, D>,
        resolver: &mut impl Resolver<Key = U64, Subscriber = ()>,
    ) {
        match message {
            HandlerMessage::Deliver {
                view,
                data,
                response,
            } => {
                // Validate incoming message
                let Some(parsed) = self.validate(view, data) else {
                    // Resolver will block any peers that send invalid responses, so
                    // we don't need to do again here
                    response.send_lossy(commonware_resolver::Outcome::Invalid);
                    return;
                };
                // A valid response is complete only after local handoff. Backpressure
                // asks the resolver to retry without penalizing the serving peer.
                if !voter.resolved_certificate(parsed.clone()) {
                    debug!(%view, "voter mailbox full, re-fetching resolved certificate");
                    response.send_lossy(commonware_resolver::Outcome::Ambiguous);
                    return;
                }

                // Process message
                response.send_lossy(commonware_resolver::Outcome::Complete);
                self.state.handle(parsed, resolver);
            }
            HandlerMessage::Produce { view, response } => {
                // Produce message for view
                let Some(certificate) = self.state.get(view) else {
                    // If we drop the response channel, the resolver will automatically
                    // send an error response to the caller (so they don't need to wait
                    // the full timeout)
                    return;
                };
                response.send_lossy(certificate.encode());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        minimmit::{
            actors::resolver::Config,
            scheme::ed25519,
            types::{Certificate, MNotarization, Notarize, Proposal},
        },
        types::{Epoch, Round, View},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        certificate::mocks::Fixture, ed25519::PublicKey as Ed25519PublicKey,
        sha256::Digest as Sha256Digest,
    };
    use commonware_p2p::Blocker;
    use commonware_parallel::Sequential;
    use commonware_runtime::Supervisor as _;
    use commonware_runtime::{Runner, deterministic};
    use commonware_utils::{
        channel::{mpsc, oneshot},
        sync::Mutex,
        test_rng,
    };
    use std::{collections::BTreeSet, sync::Arc, time::Duration};

    const NAMESPACE: &[u8] = b"minimmit-resolver-actor";
    const EPOCH: Epoch = Epoch::new(9);

    type TestScheme = ed25519::Scheme;

    #[derive(Clone, Default)]
    struct NoopBlocker;

    impl Blocker for NoopBlocker {
        type PublicKey = Ed25519PublicKey;

        fn block(&mut self, _peer: Self::PublicKey) -> commonware_actor::Feedback {
            commonware_actor::Feedback::Ok
        }
        fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
            commonware_utils::channel::ring::channel(commonware_utils::NZUsize!(1)).1
        }
    }

    #[derive(Clone, Default)]
    struct MockResolver {
        fetched: Arc<Mutex<BTreeSet<U64>>>,
    }

    impl MockResolver {
        fn fetched(&self) -> Vec<u64> {
            self.fetched
                .lock()
                .iter()
                .map(|key| key.clone().into())
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
            self.fetched.lock().insert(request.into().key);
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
            self.fetched.lock().retain(|key| predicate(key, &()));
            commonware_actor::Feedback::Ok
        }
    }

    #[derive(Clone, Default)]
    struct CountingResolver {
        fetched: Arc<Mutex<Vec<U64>>>,
    }

    impl CountingResolver {
        fn fetch_count(&self, key: U64) -> usize {
            self.fetched.lock().iter().filter(|k| *k == &key).count()
        }
    }

    impl Resolver for CountingResolver {
        type Key = U64;
        type Subscriber = ();
        fn fetch<F: Into<commonware_resolver::Fetch<U64, ()>> + Send>(
            &mut self,
            request: F,
        ) -> commonware_actor::Feedback {
            self.fetched.lock().push(request.into().key);
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
            self.fetched.lock().retain(|key| predicate(key, &()));
            commonware_actor::Feedback::Ok
        }
    }

    fn ed25519_fixture() -> (Vec<TestScheme>, TestScheme) {
        let mut rng = test_rng();
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, NAMESPACE, 6);
        (schemes, verifier)
    }

    fn build_proposal(view: View) -> Proposal<Sha256Digest> {
        let parent_view = view.previous().unwrap_or(View::zero());
        let parent_payload = Sha256Digest::from([parent_view.get() as u8; 32]);
        Proposal::new(
            Round::new(EPOCH, view),
            parent_view,
            parent_payload,
            Sha256Digest::from([view.get() as u8; 32]),
        )
    }

    fn build_m_notarization(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        view: View,
    ) -> MNotarization<TestScheme, Sha256Digest> {
        let proposal = build_proposal(view);
        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("notarize"))
            .collect();
        MNotarization::from_notarizes(verifier, votes.iter(), &Sequential)
            .expect("m-notarization quorum")
    }

    #[test]
    fn retries_when_voter_mailbox_is_full() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (schemes, verifier) = ed25519_fixture();
            let certificate =
                Certificate::MNotarization(build_m_notarization(&schemes, &verifier, View::new(2)));
            let view = certificate.view();
            let data = certificate.encode();

            let cfg = Config {
                scheme: verifier.clone(),
                blocker: NoopBlocker,
                strategy: Sequential,
                epoch: EPOCH,
                mailbox_size: 8,
                fetch_concurrent: 2,
                fetch_timeout: Duration::from_millis(10),
            };
            let (mut actor, _mailbox) = Actor::new(context.child("resolver_actor"), cfg);

            let (voter_tx, mut voter_rx) = mpsc::channel(1);
            let mut voter = voter::Mailbox::new(voter_tx);
            voter.proposal(build_proposal(View::new(1))).await;

            let mut resolver = MockResolver::default();
            let (response, receiver) = oneshot::channel();

            actor.handle_resolver(
                HandlerMessage::Deliver {
                    view,
                    data,
                    response,
                },
                &mut voter,
                &mut resolver,
            );

            assert_eq!(
                receiver.await.expect("deliver response"),
                commonware_resolver::Outcome::Ambiguous
            );
            assert!(voter_rx.try_recv().is_ok(), "expected pre-filled proposal");
            assert!(
                voter_rx.try_recv().is_err(),
                "resolved certificate must not be enqueued when mailbox is full"
            );
            assert!(
                actor.state.get(view).is_none(),
                "resolver state must not advance on dropped voter delivery"
            );
            assert_eq!(
                resolver.fetched(),
                Vec::<u64>::new(),
                "the resolver retries via Outcome::Ambiguous"
            );
        });
    }

    #[test]
    fn does_not_refetch_same_view_repeatedly_while_voter_full() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (schemes, verifier) = ed25519_fixture();
            let certificate =
                Certificate::MNotarization(build_m_notarization(&schemes, &verifier, View::new(3)));
            let view = certificate.view();
            let data = certificate.encode();

            let cfg = Config {
                scheme: verifier.clone(),
                blocker: NoopBlocker,
                strategy: Sequential,
                epoch: EPOCH,
                mailbox_size: 8,
                fetch_concurrent: 2,
                fetch_timeout: Duration::from_millis(10),
            };
            let (mut actor, _mailbox) = Actor::new(context.child("resolver_actor"), cfg);

            let (voter_tx, _voter_rx) = mpsc::channel(1);
            let mut voter = voter::Mailbox::new(voter_tx);
            voter.proposal(build_proposal(View::new(1))).await;

            let mut resolver = CountingResolver::default();

            for _ in 0..2 {
                let (response, receiver) = oneshot::channel();
                actor.handle_resolver(
                    HandlerMessage::Deliver {
                        view,
                        data: data.clone(),
                        response,
                    },
                    &mut voter,
                    &mut resolver,
                );
                assert_eq!(
                    receiver.await.expect("deliver response"),
                    commonware_resolver::Outcome::Ambiguous
                );
            }

            let key = view.into();
            assert_eq!(
                resolver.fetch_count(key),
                0,
                "the resolver owns retries; do not issue redundant fetch requests"
            );
        });
    }
}
