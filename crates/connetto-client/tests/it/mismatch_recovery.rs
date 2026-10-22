//! What the live pump learns when the server moved to another build while
//! the transport was gone: a reason the build can never attach under ends
//! the pump with the reason named, a live close of that class skips the
//! first redial, a rate-limited refusal sets the floor on the next wait,
//! and everything else keeps the retry the policy gives it.
//!
//! Runs against the fake wire with no server.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use connetto_client::{ClientBuilder, ClientEvent, ReconnectPolicy, SyncSchema};
use connetto_core::messages::{
    BulkMessage, ControlMessage, FatalErrorReason, HandshakeAck, WriterGrant, WriterRequest,
};
use connetto_core::schema::{SchemaBundle, SchemaVersion};
use connetto_core::test_support::{FakeTransport, FakeTransportError};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, Major};

const DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";

/// The major-1 bundle [`super::support::bundle`] builds, as a number.
fn major_one() -> Major {
    Major::new(1).expect("one is a major")
}

/// The major-2 bundle a build ahead of its server carries.
fn bundle_major_2() -> SyncSchema {
    SyncSchema::new(
        SchemaBundle::new(
            "-- connetto:major 2",
            "",
            DDL,
            Vec::<(String, String)>::new(),
            Vec::<String>::new(),
            None::<&str>,
        )
        .expect("the source declares major 2"),
    )
}

/// A dial plan the factory serves in order, with a count of every dial the
/// test can assert. A plan that runs out fails the test loudly rather than
/// hiding a wrong number of dials.
struct Plan<T> {
    ports: Mutex<VecDeque<T>>,
    dials: Arc<AtomicUsize>,
}

impl<T> Plan<T> {
    fn new(ports: Vec<T>) -> Self {
        Self {
            ports: Mutex::new(ports.into()),
            dials: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn dial(&self) -> T {
        self.dials.fetch_add(1, Ordering::Relaxed);
        self.ports
            .lock()
            .expect("the plan lock")
            .pop_front()
            .unwrap_or_else(|| panic!("the test plan ran out of transports"))
    }

    fn dials(&self) -> usize {
        self.dials.load(Ordering::Relaxed)
    }
}

/// A transport that acknowledges the handshake and then looks gone, carrying
/// `version` as the server's schema version. `None` opts the fake server out
/// of the staleness check, as the plain fake does.
struct StaleTransport {
    version: Option<SchemaVersion>,
    inbox: VecDeque<IncomingFrame>,
}

impl StaleTransport {
    fn acking(version: Option<SchemaVersion>) -> Self {
        Self {
            version,
            inbox: VecDeque::new(),
        }
    }
}

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the trait methods are async and the bodies finish without awaiting"
)]
impl Transport for StaleTransport {
    type Error = FakeTransportError;

    async fn send_control(&mut self, message: ControlMessage) -> Result<(), FakeTransportError> {
        if let ControlMessage::Handshake(handshake) = &message {
            self.inbox
                .push_back(IncomingFrame::Control(ControlMessage::HandshakeAck(
                    HandshakeAck {
                        connection_id: "connection-stale".to_owned(),
                        session_token: "00000000-0000-4000-8000-000000000000".to_owned(),
                        resume_token: "run:00000000-0000-4000-8000-000000000000".to_owned(),
                        current_cursor: Cursor::new(Vec::new()),
                        schema_version: self.version.clone(),
                        initial_credits: 64,
                        writer: match &handshake.writer {
                            WriterRequest::Device => None,
                            WriterRequest::Issue | WriterRequest::Number(_) => Some(WriterGrant {
                                number: 1,
                                frontier: 0,
                            }),
                        },
                    },
                )));
        }
        Ok(())
    }

    async fn send_bulk(&mut self, _message: BulkMessage) -> Result<(), FakeTransportError> {
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<IncomingFrame>, FakeTransportError> {
        Ok(self.inbox.pop_front())
    }

    async fn close(&mut self) -> Result<(), FakeTransportError> {
        Ok(())
    }
}

/// The events until the pump ends, so a test reads the whole outcome at once.
async fn collect_until_closed(
    events: &mut tokio::sync::broadcast::Receiver<ClientEvent>,
) -> Vec<ClientEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut seen = Vec::new();
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("the pump ended before the deadline")
            .expect("the event stream stayed open");
        if matches!(event, ClientEvent::Closed) {
            seen.push(event);
            return seen;
        }
        seen.push(event);
    }
}

fn fast_policy(max_attempts: u32) -> ReconnectPolicy {
    ReconnectPolicy::new()
        .with_initial_backoff(Duration::from_millis(1))
        .with_max_backoff(Duration::from_millis(5))
        .with_max_attempts(Some(max_attempts))
}

/// A transport that met a server on a newer major on the way back ends the
/// pump with the update-required reason, since the retry can never attach
/// under it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_transport_meeting_a_newer_major_stops_the_pump() {
    let reason = FatalErrorReason::MajorMismatch {
        server: Major::new(2).expect("two is a major"),
        client: Some(major_one()),
    };
    let plan = Arc::new(Plan::new(vec![
        FakeTransport::accepting(),
        FakeTransport::refusing(reason),
    ]));
    let factory = {
        let plan = Arc::clone(&plan);
        move || {
            let transport = plan.dial();
            async move { Ok::<FakeTransport, FakeTransportError>(transport) }
        }
    };
    let (client, pump) = ClientBuilder::new(super::support::bundle(DDL), factory)
        .with_reconnect(fast_policy(5))
        .with_sleeper(|d| tokio::time::sleep(d))
        .signed_in(super::support::held("token"))
        .connect_with_pump()
        .await
        .expect("initial connect");
    let mut events = client.client().events();
    tokio::spawn(pump);

    let seen = collect_until_closed(&mut events).await;
    let stopped = seen.iter().find_map(|event| match event {
        ClientEvent::Stopped { detail } => Some(detail.clone()),
        _ => None,
    });
    assert_eq!(
        stopped,
        Some("update required: this build speaks major 1, the server major 2".to_owned()),
        "the app is told the reason the fresh open would have used, got the events {seen:?}"
    );
    assert_eq!(seen.last(), Some(&ClientEvent::Closed));
    assert!(
        !seen
            .iter()
            .any(|event| matches!(event, ClientEvent::Reconnected)),
        "the recovery never resumed, got the events {seen:?}"
    );
    assert_eq!(plan.dials(), 2, "one dial per attempt, no more");
    drop(client);
}

/// The same outcome when the build is ahead of the server it reached, since
/// the deployment has not put this major up yet either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_transport_meeting_an_older_major_stops_the_pump() {
    let reason = FatalErrorReason::MajorMismatch {
        server: major_one(),
        client: Some(Major::new(2).expect("two is a major")),
    };
    let plan = Arc::new(Plan::new(vec![
        FakeTransport::accepting(),
        FakeTransport::refusing(reason),
    ]));
    let factory = {
        let plan = Arc::clone(&plan);
        move || {
            let transport = plan.dial();
            async move { Ok::<FakeTransport, FakeTransportError>(transport) }
        }
    };
    let (client, pump) = ClientBuilder::new(bundle_major_2(), factory)
        .with_reconnect(fast_policy(5))
        .with_sleeper(|d| tokio::time::sleep(d))
        .signed_in(super::support::held("token"))
        .connect_with_pump()
        .await
        .expect("initial connect");
    let mut events = client.client().events();
    tokio::spawn(pump);

    let seen = collect_until_closed(&mut events).await;
    let stopped = seen.iter().find_map(|event| match event {
        ClientEvent::Stopped { detail } => Some(detail.clone()),
        _ => None,
    });
    assert_eq!(
        stopped,
        Some("server behind: this build speaks major 2, the server major 1".to_owned()),
        "got the events {seen:?}"
    );
    assert_eq!(seen.last(), Some(&ClientEvent::Closed));
    drop(client);
}

/// A server that moved to another bundle at the same major ends the pump with
/// the stale-schema reason, since the build cannot read the shape it would
/// push.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_transport_meeting_a_newer_bundle_stops_the_pump() {
    let bundle = super::support::bundle(DDL);
    let server_version = SchemaVersion::from_hash(vec![0xAA; 24]);
    let expected = format!(
        "schema outdated: client built for {}, server advertises {server_version}",
        bundle.version()
    );
    let plan = Arc::new(Plan::new(vec![
        StaleTransport::acking(None),
        StaleTransport::acking(Some(server_version)),
    ]));
    let factory = {
        let plan = Arc::clone(&plan);
        move || {
            let transport = plan.dial();
            async move { Ok::<StaleTransport, FakeTransportError>(transport) }
        }
    };
    let (client, pump) = ClientBuilder::new(bundle, factory)
        .with_reconnect(fast_policy(5))
        .with_sleeper(|d| tokio::time::sleep(d))
        .signed_in(super::support::held("token"))
        .connect_with_pump()
        .await
        .expect("initial connect");
    let mut events = client.client().events();
    tokio::spawn(pump);

    let seen = collect_until_closed(&mut events).await;
    let stopped = seen.iter().find_map(|event| match event {
        ClientEvent::Stopped { detail } => Some(detail.clone()),
        _ => None,
    });
    assert_eq!(stopped, Some(expected), "got the events {seen:?}");
    assert_eq!(seen.last(), Some(&ClientEvent::Closed));
    drop(client);
}

/// A refusal the wire version cannot cure ends the pump with the refusal's
/// own reason, since the client's wire version is baked in the build.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_transport_meeting_a_wire_mismatch_stops_the_pump() {
    let reason = FatalErrorReason::ProtocolVersionMismatch {
        expected: 2,
        got: 1,
    };
    let plan = Arc::new(Plan::new(vec![
        FakeTransport::accepting(),
        FakeTransport::refusing(reason.clone()),
    ]));
    let factory = {
        let plan = Arc::clone(&plan);
        move || {
            let transport = plan.dial();
            async move { Ok::<FakeTransport, FakeTransportError>(transport) }
        }
    };
    let (client, pump) = ClientBuilder::new(super::support::bundle(DDL), factory)
        .with_reconnect(fast_policy(5))
        .with_sleeper(|d| tokio::time::sleep(d))
        .signed_in(super::support::held("token"))
        .connect_with_pump()
        .await
        .expect("initial connect");
    let mut events = client.client().events();
    tokio::spawn(pump);

    let seen = collect_until_closed(&mut events).await;
    let stopped = seen.iter().find_map(|event| match event {
        ClientEvent::Stopped { detail } => Some(detail.clone()),
        _ => None,
    });
    assert_eq!(
        stopped,
        Some(format!("handshake refused: {reason:?}")),
        "got the events {seen:?}"
    );
    assert_eq!(seen.last(), Some(&ClientEvent::Closed));
    drop(client);
}

/// A live close that names a reason the build can never attach under skips
/// the first redial, since the server already answered the question the
/// redial would ask again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_close_of_the_terminal_class_skips_the_first_redial() {
    for reason in [
        FatalErrorReason::MajorMismatch {
            server: Major::new(2).expect("two is a major"),
            client: Some(major_one()),
        },
        FatalErrorReason::ProtocolVersionMismatch {
            expected: 2,
            got: 1,
        },
    ] {
        let plan = Arc::new(Plan::new(vec![
            FakeTransport::accepting_then_closing(reason.clone()),
            FakeTransport::accepting(),
        ]));
        let factory = {
            let plan = Arc::clone(&plan);
            move || {
                let transport = plan.dial();
                async move { Ok::<FakeTransport, FakeTransportError>(transport) }
            }
        };
        let (client, pump) = ClientBuilder::new(super::support::bundle(DDL), factory)
            .with_reconnect(fast_policy(5))
            .with_sleeper(|d| tokio::time::sleep(d))
            .signed_in(super::support::held("token"))
            .connect_with_pump()
            .await
            .expect("initial connect");
        let mut events = client.client().events();
        tokio::spawn(pump);

        let seen = collect_until_closed(&mut events).await;
        assert_eq!(
            plan.dials(),
            1,
            "the redial the close already answered was skipped, got the events {seen:?}"
        );
        let closed_because = seen.iter().find_map(|event| match event {
            ClientEvent::ServerClosed { reason } => Some(reason.clone()),
            _ => None,
        });
        assert_eq!(
            closed_because,
            Some(reason),
            "the app hears why the server closed before the outcome, got the events {seen:?}"
        );
        assert!(
            !seen
                .iter()
                .any(|event| matches!(event, ClientEvent::Reconnecting { .. })),
            "no redial at all, got the events {seen:?}"
        );
        assert!(
            !seen
                .iter()
                .any(|event| matches!(event, ClientEvent::Reconnected)),
            "got the events {seen:?}"
        );
        drop(client);
    }
}

/// A rate-limited refusal carries how long the server will take, so the next
/// reconnect wait floors on it instead of probing the answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rate_limited_refusal_floors_the_next_wait() {
    let waits: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));
    let plan = Arc::new(Plan::new(vec![
        FakeTransport::accepting(),
        FakeTransport::refusing(FatalErrorReason::RateLimited {
            retry_after_ms: 5000,
        }),
        FakeTransport::accepting_but_silent(),
    ]));
    let factory = {
        let plan = Arc::clone(&plan);
        move || {
            let transport = plan.dial();
            async move { Ok::<FakeTransport, FakeTransportError>(transport) }
        }
    };
    let (client, pump) = ClientBuilder::new(super::support::bundle(DDL), factory)
        .with_reconnect(fast_policy(5))
        .with_sleeper({
            let waits = Arc::clone(&waits);
            move |d| {
                waits.lock().expect("the waits lock").push(d);
                Box::pin(async {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                })
            }
        })
        .signed_in(super::support::held("token"))
        .connect_with_pump()
        .await
        .expect("initial connect");
    let mut events = client.client().events();
    tokio::spawn(pump);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("the recovery resumed before the deadline")
            .expect("the event stream stayed open");
        if matches!(event, ClientEvent::Reconnected) {
            break;
        }
    }
    let waits = waits.lock().expect("the waits lock").to_vec();
    assert_eq!(waits.len(), 2, "a wait before every dial, got {waits:?}");
    assert!(
        waits[0] < Duration::from_millis(5000),
        "the first wait is the plain backoff, got {waits:?}"
    );
    assert!(
        waits[1] >= Duration::from_millis(5000),
        "the second wait floors on the server's window, got {waits:?}"
    );
    drop(client);
}

/// A refusal the build may attach under after a fix keeps the retry: the
/// pump stays quiet about it, burns the policy's attempts, and ends with the
/// plain close, since the class is not terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_outside_the_terminal_class_keeps_the_retry() {
    let refusal = FatalErrorReason::ProtocolViolation {
        detail: "the tab presents a second handshake".to_owned(),
    };
    let plan = Arc::new(Plan::new(vec![
        FakeTransport::accepting(),
        FakeTransport::refusing(refusal.clone()),
        FakeTransport::refusing(refusal),
    ]));
    let factory = {
        let plan = Arc::clone(&plan);
        move || {
            let transport = plan.dial();
            async move { Ok::<FakeTransport, FakeTransportError>(transport) }
        }
    };
    let (client, pump) = ClientBuilder::new(super::support::bundle(DDL), factory)
        .with_reconnect(fast_policy(2))
        .with_sleeper(|d| tokio::time::sleep(d))
        .signed_in(super::support::held("token"))
        .connect_with_pump()
        .await
        .expect("initial connect");
    let mut events = client.client().events();
    tokio::spawn(pump);

    let seen = collect_until_closed(&mut events).await;
    assert!(
        !seen
            .iter()
            .any(|event| matches!(event, ClientEvent::Stopped { .. })),
        "a non-terminal refusal says nothing, it just retries, got the events {seen:?}"
    );
    assert_eq!(
        seen.iter()
            .filter(|event| matches!(event, ClientEvent::Reconnecting { .. }))
            .count(),
        2,
        "every attempt the policy allows, got the events {seen:?}"
    );
    assert_eq!(seen.last(), Some(&ClientEvent::Closed));
    assert_eq!(plan.dials(), 3);
    drop(client);
}
