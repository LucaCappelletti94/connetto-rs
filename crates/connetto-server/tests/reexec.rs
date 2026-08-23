//! Phase 4b acceptance test: re-execution and aggregate delivery.
//!
//! Docker-free: a MIN aggregate subscription is bootstrapped through a fake
//! connector (canned scalar responses), an in-process fold delivers a lower
//! value without touching the connector, and deleting the current extreme
//! forces a re-execution that consults the connector. Each step asserts the
//! `AggregateUpdate` the client receives. The real-connector bootstrap is
//! covered by the Docker-gated test in `pg_async.rs`.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use connetto_core::PROTOCOL_VERSION;
use connetto_core::messages::{ControlMessage, Handshake, Subscribe, SubscriptionSpec};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::{
    Materializer, PageSpec, ReadBudget, RequestGuard, SessionConfig, SessionManager,
    SnapshotEstimate, SnapshotPage, SnapshotSource, loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, RosterAuth, WITHHELD_ID};
use subql::backend::{Postgres, ScalarKindOf, Value as PgValue};
use subql::reexec::{AsyncConnector, Snapshot as ConnectorRead};
use subql::{CdcSource, PgLsn, PgSqliteEmuSource};

const PG_DDL: &str = "CREATE TABLE orders (id INT PRIMARY KEY, amount INT);";

/// A connector that answers `execute_scalar` from a queue of canned integers.
struct QueuedConnector {
    responses: Mutex<VecDeque<i64>>,
}

impl QueuedConnector {
    fn new(responses: impl IntoIterator<Item = i64>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
        }
    }
}

#[allow(clippy::manual_async_fn)]
impl AsyncConnector for QueuedConnector {
    type AuthContext = ReadBudget;
    type Error = std::io::Error;
    type Checkpoint = PgLsn;
    type Backend = Postgres;

    fn execute_scalar(
        &self,
        _sql: &str,
        _kind: ScalarKindOf<Postgres>,
        _budget: &ReadBudget,
    ) -> impl core::future::Future<
        Output = Result<(PgValue<Postgres>, Option<PgLsn>), std::io::Error>,
    > + Send {
        let next = self.responses.lock().expect("queue poisoned").pop_front();
        async move {
            next.map(|n| (PgValue::Int(n), Some(PgLsn(1))))
                .ok_or_else(|| std::io::Error::other("no more canned responses"))
        }
    }

    fn execute_rows(
        &self,
        _sql: &str,
        _budget: &ReadBudget,
    ) -> impl core::future::Future<
        Output = Result<ConnectorRead<Vec<Vec<PgValue<Postgres>>>, PgLsn>, std::io::Error>,
    > + Send {
        async {
            Err(std::io::Error::other(
                "execute_rows not used in reexec tests",
            ))
        }
    }
}

/// Aggregate subscriptions never snapshot, so this is never invoked.
struct NoSnapshot;

impl SnapshotSource for NoSnapshot {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn estimate(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _caller: &connetto_core::Principal,
    ) -> Result<SnapshotEstimate, Self::Error> {
        Ok(SnapshotEstimate {
            rows: 0.0,
            width: 0,
        })
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot_page(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _auth: &connetto_core::Principal,
        _page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error> {
        Ok(SnapshotPage {
            patchset: Vec::new(),
            cursor: connetto_core::Cursor::new(Vec::new()),
            next: None,
            filled: false,
            widest_row: 0,
            rows: 0,
            bytes: 0,
        })
    }
}

type Manager = SessionManager<NoSnapshot, RosterAuth, ConnettoWatermark, QueuedConnector>;

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    match transport.recv().await.expect("recv frame") {
        Some(IncomingFrame::Control(msg)) => msg,
        other => panic!("expected control frame, got {other:?}"),
    }
}

fn aggregate_value(msg: ControlMessage) -> String {
    match msg {
        ControlMessage::AggregateUpdate(update) => {
            assert_eq!(update.sub_id, "cheapest");
            assert!(update.is_full_result);
            update.result_json
        }
        other => panic!("expected aggregate update, got {other:?}"),
    }
}

async fn drive(source: &mut PgSqliteEmuSource, manager: &Manager, sql: &str) {
    source.execute_sql(sql).expect("execute dml");
    while let Some(event) = source.next_event().await.expect("poll source") {
        manager
            .dispatch_event(&event)
            .await
            .expect("dispatch event");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reexec_bootstraps_folds_and_retriggers() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    // Bootstrap answers 10, the re-execution after the delete answers 20.
    let connector = QueuedConnector::new([10, 20]);
    let target = pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
        .expect("build write target");
    let manager = SessionManager::with_connector(
        materializer,
        NoSnapshot,
        // Aggregate results never go through the policy.
        RosterAuth::granting_nobody().withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        connector,
        target,
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));

    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "aggregator")
                .with_grant(connetto_core::messages::Grant::new("user:aggregator")),
        ))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    // Subscribe to MIN(amount): bootstrap runs the query through the connector.
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "cheapest".to_owned(),
            spec: SubscriptionSpec::new("SELECT MIN(amount) FROM orders"),
        }))
        .await
        .expect("send subscribe");
    assert_eq!(aggregate_value(next_control(&mut client).await), "10");

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");

    // A lower value folds in-process: the connector is not consulted.
    drive(
        &mut source,
        &manager,
        "INSERT INTO orders (id, amount) VALUES (1, 5)",
    )
    .await;
    assert_eq!(aggregate_value(next_control(&mut client).await), "5");

    // Deleting the current extreme forces a re-execution through the connector.
    drive(&mut source, &manager, "DELETE FROM orders WHERE id = 1").await;
    assert_eq!(aggregate_value(next_control(&mut client).await), "20");

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}
