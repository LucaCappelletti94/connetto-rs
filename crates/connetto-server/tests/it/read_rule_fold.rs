//! Read-rule fold acceptance test.
//!
//! A query naming no caller term still carries the table's caller-bound read
//! rule into the engine, because the registration states the caller's
//! identity and subject set. A change the row's rule admits for no watcher
//! then reaches none, and a change it admits for one watcher is routed to
//! that watcher alone, with the two-check form still answering delivery for
//! the callers it names.
use std::sync::Arc;
use std::time::Duration;

use connetto_core::auth::{DEFAULT_USER_SETTING, Principal};
use connetto_core::messages::{
    BulkMessage, ControlMessage, Grant, Handshake, Subscribe, SubscriptionSpec,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::counters;
use connetto_server::{
    LoopbackTransport, ManagerBuilder, Materializer, NoConnector, PageSpec, RuntimeWritableCatalog,
    SessionError, SessionManager, SnapshotEstimate, SnapshotPage, SnapshotSource, loopback,
    pg_write_target,
};
use connetto_test_harness::fanout::caller_mapping;
use connetto_test_harness::{ConnettoDefaults, Fixture};
use diesel::prelude::*;
use diesel::sql_query;
use subql::backend::{Postgres, Value};
use subql::visibility::{RowView, RowWrite, Verdict, VisibilityPolicy};
use subql::{CdcSource, PgSqliteEmuSource, SourceItem};

const PG_DDL: &str =
    "CREATE TABLE items (id INT PRIMARY KEY, owner TEXT NOT NULL, label TEXT NOT NULL);";

/// The policy every connetto table carries: the caller's identity, or a key
/// the caller holds.
const POLICIES: &str = "ALTER TABLE items ENABLE ROW LEVEL SECURITY;\n\
     CREATE POLICY items_p ON items FOR ALL USING (\n\
     owner = current_setting('app.user_id', true)\n\
     OR owner = ANY(string_to_array(current_setting('app.subjects', true), ','))\n\
     );";

const SQLITE_DDL: &str =
    "CREATE TABLE items (id INTEGER PRIMARY KEY, owner TEXT NOT NULL, label TEXT NOT NULL);";

/// Allows reads of the `items` row to the watcher the row's owner names,
/// allows every write. The owner is read straight off the row view, which is
/// how the row-level-security policy reads it too.
struct OwnerPolicy;

impl VisibilityPolicy for OwnerPolicy {
    type Watcher = Arc<Principal>;
    type Error = std::convert::Infallible;
    type Backend = Postgres;

    fn may_see<R>(
        &self,
        row: &R,
        watchers: &[Self::Watcher],
        verdicts: &mut [Verdict],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        let owner = match row.value_at(1) {
            Ok(Value::String(owner)) => owner,
            _ => String::new(),
        };
        async move {
            for (watcher, verdict) in watchers.iter().zip(verdicts.iter_mut()) {
                let admitted = watcher
                    .identity()
                    .is_some_and(|identity| identity.user_id == owner);
                if admitted {
                    *verdict = Verdict::Allow;
                }
            }
            Ok(())
        }
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn may_write<R>(
        &self,
        _write: RowWrite<'_, R>,
        _watcher: &Self::Watcher,
    ) -> Result<Verdict, Self::Error>
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        Ok(Verdict::Allow)
    }
}

/// A snapshot source with no initial rows.
struct EmptySnapshot;

impl SnapshotSource for EmptySnapshot {
    type Error = std::convert::Infallible;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn estimate(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _caller: &Principal,
    ) -> Result<SnapshotEstimate, Self::Error> {
        Ok(SnapshotEstimate {
            rows: 0.0,
            width: 0,
        })
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn snapshot_page(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _auth: &Principal,
        _page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error> {
        Ok(SnapshotPage {
            patchset: Vec::new(),
            cursor: Cursor::new(Vec::new()),
            next: None,
            filled: false,
            widest_row: 0,
            rows: 0,
            bytes: 0,
        })
    }
}

diesel::table! {
    /// Row from the items test fixture.
    items (id) {
        /// Item identifier, the primary key.
        id -> diesel::sql_types::Integer,
        /// The caller the row's rule admits.
        owner -> diesel::sql_types::Text,
        /// A label the rule never reads.
        label -> diesel::sql_types::Text,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq)]
#[diesel(table_name = items)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Item {
    id: i32,
    owner: String,
    label: String,
}

fn item(id: i32, owner: &str, label: &str) -> Item {
    Item {
        id,
        owner: owner.to_owned(),
        label: label.to_owned(),
    }
}

fn client_replica() -> SqliteConnection {
    let mut conn = SqliteConnection::establish(":memory:").expect("open sqlite");
    sql_query(SQLITE_DDL)
        .execute(&mut conn)
        .expect("create table");
    conn
}

fn items(conn: &mut SqliteConnection) -> Vec<Item> {
    items::table
        .select(Item::as_select())
        .order(items::id)
        .load(conn)
        .expect("load items")
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    match transport.recv().await.expect("recv frame") {
        Some(IncomingFrame::Control(msg)) => msg,
        other => panic!("expected control frame, got {other:?}"),
    }
}

/// The manager with the deployment's own wiring over the one table: the
/// engine's catalog carries the policy beside the DDL, the translator
/// classifies it, and the caller pairing carries the identity and the
/// subject set to the replica.
type Manager = Arc<SessionManager<EmptySnapshot, OwnerPolicy, ConnettoDefaults>>;

async fn connected_clients(
    fixture: &Fixture,
    grants: [&str; 2],
) -> (
    Manager,
    Vec<(
        LoopbackTransport,
        tokio::task::JoinHandle<Result<(), SessionError>>,
    )>,
) {
    let translated =
        connetto_server::openfga::Translated::of::<String, connetto_core::bots::TextIds>(
            PG_DDL,
            POLICIES,
            DEFAULT_USER_SETTING,
        )
        .expect("the policy translates");
    let (_, translator, _) = translated.into_parts();
    let materializer = Materializer::builder(&format!("{PG_DDL}\n{POLICIES}"))
        .with_write_catalog(RuntimeWritableCatalog::default())
        .with_translator(translator)
        .with_caller(caller_mapping())
        .build()
        .expect("build materializer");
    let manager = ManagerBuilder::new(
        materializer,
        EmptySnapshot,
        OwnerPolicy,
        Arc::new(TestGrantChecker),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
    )
    .build();

    let mut clients = Vec::new();
    for (n, grant) in grants.iter().enumerate() {
        let (server_transport, mut client) = loopback();
        let server = tokio::spawn(manager.clone().serve(server_transport));
        client
            .send_control(ControlMessage::Handshake(
                Handshake::new(PROTOCOL_VERSION, format!("client-{n}"))
                    .with_grant(Grant::new(*grant)),
            ))
            .await
            .expect("send handshake");
        // The server leads every connection with a challenge a person ignores (R91).
        let ControlMessage::Challenge(_) = next_control(&mut client).await else {
            panic!("expected the leading challenge");
        };
        let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
            panic!("expected handshake ack");
        };
        client
            .send_control(ControlMessage::Subscribe(Subscribe {
                sub_id: "items".to_owned(),
                spec: SubscriptionSpec::new("SELECT * FROM items"),
            }))
            .await
            .expect("send subscribe");
        // Drain the empty snapshot (begin, patch, end).
        let ControlMessage::SnapshotBegin(_) = next_control(&mut client).await else {
            panic!("expected snapshot begin");
        };
        let BulkMessage::SnapshotPatch(_) = (match client.recv().await.expect("recv") {
            Some(IncomingFrame::Bulk(msg)) => msg,
            other => panic!("expected snapshot patch, got {other:?}"),
        }) else {
            panic!("expected snapshot patch");
        };
        let ControlMessage::SnapshotEnd(_) = next_control(&mut client).await else {
            panic!("expected snapshot end");
        };
        clients.push((client, server));
    }
    (manager, clients)
}

/// Live patches from `client` until the stream goes idle, applied to
/// `replica`. Live patches flow through the session's async outbound queue,
/// so a control-plane ping could overtake them, and the loop waits out a
/// short idle window for each frame.
async fn drain_live(
    applier: &Materializer,
    client: &mut LoopbackTransport,
    replica: &mut SqliteConnection,
) -> usize {
    let mut live = 0usize;
    loop {
        match tokio::time::timeout(Duration::from_millis(500), client.recv()).await {
            Ok(Ok(Some(IncomingFrame::Bulk(BulkMessage::LivePatch(patch))))) => {
                applier
                    .apply_diffset(&patch.patchset_zstd, replica)
                    .expect("apply live patch");
                live += 1;
            }
            Ok(Ok(Some(other))) => panic!("unexpected frame: {other:?}"),
            Ok(Err(err)) => panic!("recv failed: {err:?}"),
            Ok(Ok(None)) | Err(_) => break,
        }
    }
    live
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_folded_rule_routes_only_to_the_callers_the_row_admits() {
    let fixture = Fixture::acquire_exclusive().await;
    let (manager, mut clients) = connected_clients(&fixture, ["user:alice", "user:bob"]).await;
    let applier = Materializer::builder(PG_DDL)
        .build()
        .expect("build applier");
    let mut alice_replica = client_replica();
    let mut bob_replica = client_replica();

    let before = counters::snapshot();

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO items (id, owner, label) VALUES (1, 'alice', 'x')")
        .expect("execute dml");
    while let Some(item) = source.next_item().await.expect("poll source") {
        let SourceItem::Event(event) = item else {
            continue;
        };
        manager
            .dispatch_event(&event)
            .await
            .expect("dispatch event");
    }

    // The rule admitted the row to alice alone, so the dispatch routed one
    // patch, not one per subscribed watcher.
    let after = counters::snapshot();
    let since = after.since(&before);
    assert_eq!(
        since.fanout_route_clones, 1,
        "the row admits one watcher, so it was routed once"
    );

    let alice_live = drain_live(&applier, &mut clients[0].0, &mut alice_replica).await;
    assert_eq!(alice_live, 1, "the admitted watcher receives the row");
    assert_eq!(
        items(&mut alice_replica),
        vec![item(1, "alice", "x")],
        "the replica holds the row"
    );

    let bob_live = drain_live(&applier, &mut clients[1].0, &mut bob_replica).await;
    assert_eq!(
        bob_live, 0,
        "the watcher the rule admits nothing receives nothing"
    );
    assert!(
        items(&mut bob_replica).is_empty(),
        "the other replica holds no row"
    );

    for (client, _) in &mut clients {
        client.close().await.expect("close client");
    }
    for (_, server) in &mut clients {
        server.await.expect("join server").expect("session ok");
    }
}
