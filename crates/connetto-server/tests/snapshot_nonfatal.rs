//! A snapshot failure must not kill the session: it surfaces as a
//! `NonFatalError` scoped to the one subscription, the registration is
//! rolled back, and the session keeps serving (the pong after the failure
//! proves the run loop is alive).
//!
//! And a refusal discloses nothing. Whatever the cause, the caller gets the
//! same bytes with nothing sent ahead of them, so a socket cannot be used to
//! enumerate which tables exist or which carry row-level security. The cause
//! goes to the structured log for the operator.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::codec::encode_control;
use connetto_core::messages::{
    ControlMessage, Handshake, Ping, SUBSCRIPTION_REFUSED, Subscribe, SubscriptionSpec,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::{
    InMemoryOplog, Materializer, NoConnector, OplogConfig, PermissiveAuth, RequestGuard,
    SessionConfig, SessionManager, Snapshot, SnapshotSource, loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture};
use subql::backend::CdcEvent;
use subql::{CdcSource, PgSqliteEmuSource};

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";

/// A snapshot source that always fails, standing in for an unreachable or
/// misbehaving backing store.
struct BrokenSnapshot;

impl SnapshotSource for BrokenSnapshot {
    type Error = String;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _auth: &connetto_core::Principal,
    ) -> Result<Snapshot, Self::Error> {
        Err("backing store unreachable".to_owned())
    }
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    loop {
        match transport.recv().await.expect("recv") {
            Some(IncomingFrame::Control(msg)) => return msg,
            Some(IncomingFrame::Bulk(_)) => {}
            None => panic!("connection closed while waiting for a control frame"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn snapshot_failure_is_nonfatal_and_the_session_survives() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        BrokenSnapshot,
        PermissiveAuth,
        Arc::new(TestGrantChecker),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    let (server_end, mut client) = loopback();
    let server = Arc::clone(&manager);
    let serve = tokio::spawn(async move { server.serve(server_end).await });

    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "nonfatal-client")
                .with_grant(connetto_core::messages::Grant::new("user:nonfatal-client")),
        ))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "broken".to_owned(),
            spec: SubscriptionSpec::new(QUERY),
        }))
        .await
        .expect("send subscribe");

    // The snapshot begins, fails inside the source, and the failure comes
    // back scoped to the subscription instead of ending the session. Nothing
    // precedes it: a `SnapshotBegin` ahead of the refusal would mark it as
    // one that passed registration.
    match next_control(&mut client).await {
        ControlMessage::NonFatalError(err) => {
            assert_eq!(err.related_to.as_deref(), Some("broken"));
            assert_eq!(
                err.detail, SUBSCRIPTION_REFUSED,
                "the refusal carries the fixed text and not the cause"
            );
        }
        other => panic!("the refusal must be the first reply: {other:?}"),
    }

    // The run loop is alive: control frames still round-trip in order.
    client
        .send_control(ControlMessage::Ping(Ping { nonce: 7 }))
        .await
        .expect("send ping");
    let ControlMessage::Pong(pong) = next_control(&mut client).await else {
        panic!("expected pong after the non-fatal error");
    };
    assert_eq!(pong.nonce, 7);

    // A clean close ends the session without an error.
    client.close().await.expect("close");
    serve
        .await
        .expect("serve task")
        .expect("session ends cleanly after a non-fatal snapshot failure");
}

/// Subscribe under `sub_id` to `query` and return the first control frame the
/// server answers with.
async fn first_reply<T: Transport>(client: &mut T, sub_id: &str, query: &str) -> ControlMessage {
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: sub_id.to_owned(),
            spec: SubscriptionSpec::new(query),
        }))
        .await
        .expect("send subscribe");
    next_control(client).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn refusals_are_byte_identical_across_causes() {
    let logs = logging::install_once();
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        BrokenSnapshot,
        PermissiveAuth,
        Arc::new(TestGrantChecker),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    let (server_end, mut client) = loopback();
    let server = Arc::clone(&manager);
    let serve = tokio::spawn(async move { server.serve(server_end).await });

    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "probe-client")
                .with_grant(connetto_core::messages::Grant::new("user:probe-client")),
        ))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    // Three causes under one sub id. A table that does not exist is refused
    // at registration. A table that does exist fails in the snapshot source.
    // An aggregate on that table fails at bootstrap, this manager having no
    // connector. The caller must not be able to tell them apart.
    let unknown = first_reply(
        &mut client,
        "probe",
        "SELECT * FROM nosuch WHERE quantity > 0",
    )
    .await;
    let broken = first_reply(&mut client, "probe", QUERY).await;
    let aggregate = first_reply(&mut client, "probe", "SELECT COUNT(*) FROM orders").await;

    for refusal in [&unknown, &broken, &aggregate] {
        let ControlMessage::NonFatalError(err) = refusal else {
            panic!("the refusal must be the first and only reply: {refusal:?}");
        };
        assert_eq!(err.related_to.as_deref(), Some("probe"));
        assert_eq!(err.detail, SUBSCRIPTION_REFUSED);
    }
    let unknown_bytes = encode_control(&unknown).expect("encode");
    assert_eq!(
        unknown_bytes,
        encode_control(&broken).expect("encode"),
        "a missing table and a failed snapshot must refuse identically"
    );
    assert_eq!(
        unknown_bytes,
        encode_control(&aggregate).expect("encode"),
        "a failed aggregate bootstrap must refuse identically too"
    );

    // What the caller lost, the operator keeps: each cause reaches the log.
    let lines = logs.lines();
    let named = |message: &str, cause: &str| {
        lines.iter().any(|line| {
            line["message"] == message
                && line["error"]
                    .as_str()
                    .is_some_and(|error| error.contains(cause))
        })
    };
    assert!(
        named("subscription registration refused", "nosuch"),
        "the log names the unknown table"
    );
    assert!(
        named("snapshot failed", "backing store unreachable"),
        "the log names the snapshot cause"
    );
    assert!(
        lines.iter().any(|line| {
            (line["message"] == "aggregate bootstrap failed"
                || line["message"] == "delta aggregate bootstrap failed")
                && line["error"]
                    .as_str()
                    .is_some_and(|error| error.contains("multi-column aggregate seeds"))
        }),
        "the log names the bootstrap cause"
    );

    client.close().await.expect("close");
    serve
        .await
        .expect("serve task")
        .expect("session ends cleanly after three refusals");
}

/// The resync path must be as silent as the fresh one. `FullResyncRequired`
/// is what makes the client discard its rows, so a notice ahead of a failing
/// read would both mark the name as registered and cost the client its data.
/// No frame may precede the refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn a_resuming_refusal_is_as_bare_as_a_fresh_one() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    // A tiny window: after four inserts the oldest two are pruned, so a
    // cursor at the first event is outside retention and the subscription
    // takes the resync path rather than oplog catchup.
    let oplog = InMemoryOplog::new(OplogConfig {
        max_entries: 2,
        max_age: Duration::from_secs(72 * 60 * 60),
    });
    let manager = SessionManager::with_oplog(
        materializer,
        BrokenSnapshot,
        PermissiveAuth,
        Arc::new(TestGrantChecker),
        NoConnector,
        oplog,
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    let mut first_lsn = None;
    for id in 1..=4 {
        let sql = format!(
            "INSERT INTO orders (id, price, quantity, status) VALUES ({id}, 1.0, {id}, 'row')"
        );
        source.execute_sql(&sql).expect("execute dml");
        while let Some(event) = source.next_event().await.expect("poll source") {
            manager
                .dispatch_event(&event)
                .await
                .expect("dispatch event");
            if first_lsn.is_none() {
                first_lsn = Some(event.checkpoint().expect("row event has a checkpoint").0);
            }
        }
    }
    let resume = Cursor::new(
        first_lsn
            .expect("at least one event")
            .to_be_bytes()
            .to_vec(),
    );

    let (server_end, mut client) = loopback();
    let server = Arc::clone(&manager);
    let serve = tokio::spawn(async move { server.serve(server_end).await });
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "resume-probe")
                .with_grant(connetto_core::messages::Grant::new("user:resume-probe"))
                .with_cursor(resume),
        ))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    // The same probe pair as the fresh-session proof, on the resync path.
    let unknown = first_reply(
        &mut client,
        "probe",
        "SELECT * FROM nosuch WHERE quantity > 0",
    )
    .await;
    let broken = first_reply(&mut client, "probe", QUERY).await;
    for refusal in [&unknown, &broken] {
        let ControlMessage::NonFatalError(err) = refusal else {
            panic!("the refusal must be the first and only reply: {refusal:?}");
        };
        assert_eq!(err.related_to.as_deref(), Some("probe"));
        assert_eq!(err.detail, SUBSCRIPTION_REFUSED);
    }
    assert_eq!(
        encode_control(&unknown).expect("encode"),
        encode_control(&broken).expect("encode"),
        "a resuming refusal must not disclose the resync decision"
    );

    client.close().await.expect("close");
    serve
        .await
        .expect("serve task")
        .expect("session ends cleanly after resumed refusals");
}

/// The process-global log destination, installed once and read back.
mod logging {
    use std::io::Write;
    use std::sync::{Arc, LazyLock, Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    pub struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Buffer {
        /// Every line written so far, each parsed as one JSON object.
        pub fn lines(&self) -> Vec<serde_json::Value> {
            String::from_utf8_lossy(&self.0.lock().expect("buffer poisoned"))
                .lines()
                .filter(|line| !line.trim().is_empty())
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect()
        }
    }

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("buffer poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Buffer {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// A subscriber is process-global, so it is installed exactly once, on
    /// the first read of the buffer.
    static BUFFER: LazyLock<Buffer> = LazyLock::new(|| {
        let buffer = Buffer::default();
        connetto_core::logging::install(buffer.clone(), "warn");
        buffer
    });

    /// Install the destination the first time and hand back the buffer.
    pub fn install_once() -> Buffer {
        BUFFER.clone()
    }
}
