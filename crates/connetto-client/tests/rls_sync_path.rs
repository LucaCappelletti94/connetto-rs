//! R40: a synced table carrying a row-level-security policy, on the production
//! sync path rather than in a hand-built fixture.
//!
//! `crates/connetto-client/tests/rls_name_mapping.rs` is the sibling of this
//! file and stays the regression guard on the mechanism: it builds the split by
//! hand, pins the silent loss, and proves `ParsedDiffSet::rename_tables` in
//! isolation. This file drives the same split through
//! [`ConnettoConnection`], so what is asserted is what an application sees.
//!
//! The failure being prevented is silent. `sqlite3changeset_apply` resolves a
//! policy view through `PRAGMA table_xinfo`, synthesizes an implicit rowid key
//! because a view declares no primary key, passes its shape checks, and then
//! fails every row as a per-row `Constraint` conflict, which the client's
//! `server_wins` policy maps to Omit. Apply reports success and delivers
//! nothing. So every assertion here counts rows rather than trusting a
//! returned `Ok`, and each test names both what must be there and what must
//! not, since "applied nothing" and "applied everything" are otherwise
//! indistinguishable.

use connetto_client::{
    ClientConfig, ClientError, ClientEvent, ConnettoConnection, PolicyTables, Replica,
};
use connetto_core::Cursor;
use connetto_core::messages::{
    BulkMessage, ControlMessage, FullResyncReason, FullResyncRequired, HandshakeAck, MutationPatch,
    SnapshotBegin, SnapshotEnd, SnapshotPatch, SubscriptionPriority,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::{LoopbackTransport, loopback};
use diesel::prelude::*;
use pg2sqlite::prelude::{Pg2Sqlite, Pg2SqliteOptions, SessionVariableMapping, WrapperKind};
use pg2sqlite::traits::TranslationOptions;
use sqlite_diff_rs::{DiffOps, Insert, ParsedDiffSet, PatchSet, SimpleTable, Value};

/// The Postgres source document, shaped like the demo's: one policy-bearing
/// table whose policy names the caller.
const PG_DDL: &str = "
CREATE TABLE orders (
    id BIGINT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    quantity BIGINT NOT NULL
);

ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

CREATE POLICY orders_p ON orders
    FOR ALL
    USING (owner_id = current_setting('app.user_id', true));
";

/// The signed-in caller for every test here. The replica is named from the
/// identity that opened it, so this value is fixed for its whole life.
const ALICE: &str = "alice";

/// The replica's local name for `current_setting('app.user_id')`. The
/// generated view and the three `INSTEAD OF` triggers all call it, and
/// connetto registers it from [`ClientConfig::with_caller`].
const CALLER_FUNCTION: &str = "current_app_user";

diesel::table! {
    /// The logical table, which the translation turned into a policy view.
    orders (id) {
        /// Order identifier, the primary key.
        id -> BigInt,
        /// Who the row belongs to.
        owner_id -> Text,
        /// How many units.
        quantity -> BigInt,
    }
}

diesel::table! {
    /// The backing table the rows physically live in, read directly so a test
    /// can tell "hidden by the policy" apart from "never arrived".
    orders_rls (id) {
        /// Order identifier, the primary key.
        id -> BigInt,
        /// Who the row belongs to.
        owner_id -> Text,
        /// How many units.
        quantity -> BigInt,
    }
}

diesel::table! {
    /// The audit trail the translation emits beside a split table. Its monitor
    /// triggers record a row that reached the backing table without becoming
    /// visible through the view, which every server patch for another owner
    /// does.
    rls_audit (id) {
        /// Audit row identifier, the primary key.
        id -> BigInt,
        /// The logical table the entry is about.
        table_name -> Text,
    }
}

fn options() -> Pg2SqliteOptions {
    Pg2SqliteOptions::default()
        .with_session_variable(SessionVariableMapping::current_setting(
            "app.user_id",
            CALLER_FUNCTION,
        ))
        .with_rls_audit_table_name("rls_audit".to_string())
}

/// The two artifacts a build emits from one source document: the SQLite DDL,
/// and the map plus view list the client is configured with.
///
/// The view list is read from a throwaway database the DDL is applied to,
/// which is what the example builds do, because a translation emits views of
/// its own beside the one carrying the logical name and only the built
/// database knows all of them.
fn translation() -> (String, PolicyTables) {
    let statements = Pg2Sqlite::default()
        .sql(PG_DDL)
        .expect("parse the Postgres document")
        .translate_to_sql(&options())
        .expect("translate to SQLite");
    let mut ddl = statements.join(";\n");
    ddl.push(';');

    let manifest = Pg2Sqlite::default()
        .sql(PG_DDL)
        .expect("parse the Postgres document")
        .translation_manifest(&options())
        .expect("manifest");
    let pairs: Vec<(String, String)> = manifest
        .iter()
        .filter(|entry| entry.wrapper == WrapperKind::RlsView)
        .map(|entry| (entry.logical.clone(), entry.physical.clone()))
        .collect();
    assert_eq!(
        pairs,
        vec![("orders".to_owned(), "orders_rls".to_owned())],
        "the translation splits exactly the policy-bearing table",
    );

    // No caller function is registered on the probe, and none is needed:
    // SQLite resolves a function name when a statement is prepared, not when a
    // view or trigger is created. This is exactly what the example builds do.
    let mut probe = SqliteConnection::establish(":memory:").expect("open the probe database");
    diesel::connection::SimpleConnection::batch_execute(&mut probe, &ddl)
        .expect("SQLite accepts the translated DDL");
    let views: Vec<String> = sqlite_catalog::table
        .select(sqlite_catalog::name)
        .filter(sqlite_catalog::kind.eq("view"))
        .load::<String>(&mut probe)
        .expect("list the views the translation created");

    (ddl, PolicyTables::from_translation(pairs, views))
}

diesel::table! {
    /// SQLite's own catalogue, read the way a build script reads it.
    #[sql_name = "sqlite_schema"]
    sqlite_catalog (name) {
        /// The object kind: `table`, `view`, `index` or `trigger`.
        #[sql_name = "type"]
        kind -> diesel::sql_types::Text,
        /// The object name.
        name -> diesel::sql_types::Text,
    }
}

fn client_config(tables: PolicyTables) -> ClientConfig {
    ClientConfig::new("r40-rls-sync")
        .with_login(Some(connetto_client::Grant::new("user:alice")))
        .with_caller(CALLER_FUNCTION, ALICE)
        .with_policy_tables(tables)
}

fn orders_wire_table() -> SimpleTable {
    SimpleTable::new("orders", &["id", "owner_id", "quantity"], &[0])
}

/// A snapshot payload naming the logical Postgres table, which is what the
/// server builds from its own catalog and what the wire carries.
fn snapshot_payload(rows: &[(i64, &str, i64)]) -> Vec<u8> {
    let mut patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new();
    for &(id, owner, quantity) in rows {
        let insert = Insert::<_, String, Vec<u8>>::from(orders_wire_table())
            .set(0, Value::Integer(id))
            .expect("set id")
            .set(1, Value::Text(owner.to_owned()))
            .expect("set owner_id")
            .set(2, Value::Integer(quantity))
            .expect("set quantity");
        patchset = patchset.insert(insert);
    }
    zstd::encode_all(patchset.build().as_slice(), 3).expect("compress")
}

async fn ack_handshake(server: &mut LoopbackTransport) {
    let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await else {
        panic!("expected a handshake");
    };
    server
        .send_control(ControlMessage::HandshakeAck(HandshakeAck {
            connection_id: "r40".to_owned(),
            session_token: "r40".to_owned(),
            resume_token: "r40".to_owned(),
            current_cursor: Cursor::new(Vec::new()),
            schema_version: None,
            initial_credits: 64,
            last_applied_seq: None,
        }))
        .await
        .expect("ack");
}

async fn wait_subscribe(server: &mut LoopbackTransport) {
    loop {
        match server.recv().await {
            Ok(Some(IncomingFrame::Control(ControlMessage::Subscribe(_)))) => return,
            Ok(Some(_)) => {}
            _ => panic!("closed before subscribing"),
        }
    }
}

async fn send_snapshot(
    server: &mut LoopbackTransport,
    sub_id: &str,
    rows: &[(i64, &str, i64)],
    cursor: u8,
) {
    server
        .send_control(ControlMessage::SnapshotBegin(SnapshotBegin {
            sub_id: sub_id.to_owned(),
            priority: SubscriptionPriority::default(),
        }))
        .await
        .expect("begin");
    server
        .send_bulk(BulkMessage::SnapshotPatch(SnapshotPatch::new(
            sub_id.to_owned(),
            snapshot_payload(rows),
        )))
        .await
        .expect("patch");
    server
        .send_control(ControlMessage::SnapshotEnd(SnapshotEnd {
            sub_id: sub_id.to_owned(),
            cursor: Cursor::new(vec![0, 0, 0, 0, 0, 0, 0, cursor]),
        }))
        .await
        .expect("end");
}

async fn pump_to_snapshot_end(conn: &mut ConnettoConnection<LoopbackTransport>) {
    loop {
        match conn.pump_one().await.expect("pump") {
            ClientEvent::SnapshotEnd { .. } => return,
            ClientEvent::Closed => panic!("closed before the snapshot ended"),
            _ => {}
        }
    }
}

/// The table names a mutation frame carries, decompressed and parsed as the
/// server's write target would.
fn uploaded_tables(patch: &MutationPatch) -> Vec<String> {
    let bytes = zstd::decode_all(patch.patchset_zstd.as_slice()).expect("decompress the mutation");
    ParsedDiffSet::parse(&bytes)
        .expect("parse the mutation")
        .table_schemas()
        .iter()
        .map(|schema| schema.name().clone())
        .collect()
}

/// A server-sent row lands in the replica and the application can read it
/// through the logical name, with the policy still filtering what it shows.
///
/// The three assertions are one proof and none of them stands alone. Alice's
/// row visible proves rows arrived. Bob's row present in the backing table
/// proves the apply went underneath the policy rather than through it, which
/// is the deliberate choice: the server already decided what this client may
/// hold. Bob's row absent through the view proves the policy is real and the
/// apply did not simply bypass the split.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_row_lands_and_the_view_still_filters() {
    let (ddl, tables) = translation();
    let (mut server, client_end) = loopback();
    tokio::spawn(async move {
        ack_handshake(&mut server).await;
        wait_subscribe(&mut server).await;
        send_snapshot(&mut server, "sub", &[(1, ALICE, 5), (2, "bob", 7)], 1).await;
        while let Ok(Some(_)) = server.recv().await {}
    });

    let mut conn = ConnettoConnection::connect(
        client_end,
        &Replica::in_memory(),
        &ddl,
        &client_config(tables),
        None,
    )
    .await
    .expect("connect");
    conn.subscribe("sub", "SELECT * FROM orders")
        .await
        .expect("subscribe");
    pump_to_snapshot_end(&mut conn).await;

    let visible: Vec<i64> = orders::table
        .select(orders::id)
        .order(orders::id.asc())
        .load(conn.conn())
        .expect("read through the logical name");
    assert_eq!(
        visible,
        vec![1],
        "the application sees its own row through the logical name, and only it",
    );
    let stored: Vec<i64> = orders_rls::table
        .select(orders_rls::id)
        .order(orders_rls::id.asc())
        .load(conn.conn())
        .expect("read the backing table");
    assert_eq!(
        stored,
        vec![1, 2],
        "both server-sent rows landed physically, the policy triggers bypassed",
    );

    // The translation also emits an audit table with monitor triggers that
    // fire when a row lands in the backing table without being visible through
    // the view, which is precisely what bob's row just did. That write is
    // connetto's replica machinery reacting to a server patch, so it must not
    // be captured: uploading it would name a table Postgres does not have.
    let audited: i64 = rls_audit::table
        .count()
        .get_result(conn.conn())
        .expect("read the audit trail");
    assert_eq!(audited, 1, "the monitor trigger fired for the hidden row");
    assert!(
        conn.push().await.expect("push").is_none(),
        "and nothing was captured for upload, because the apply suspends capture",
    );
}

/// The application is told the logical table changed, not the backing one.
///
/// SQLite's update hook never fires for a view, so the apply above reports
/// `orders_rls` unless the boundary maps it back. A live query registers the
/// tables its own SQL names, so the physical name would intersect nothing and
/// no live query over this table would ever refresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_changed_table_is_reported_under_its_logical_name() {
    let (ddl, tables) = translation();
    let (mut server, client_end) = loopback();
    tokio::spawn(async move {
        ack_handshake(&mut server).await;
        wait_subscribe(&mut server).await;
        send_snapshot(&mut server, "sub", &[(1, ALICE, 5)], 1).await;
        while let Ok(Some(_)) = server.recv().await {}
    });

    let mut conn = ConnettoConnection::connect(
        client_end,
        &Replica::in_memory(),
        &ddl,
        &client_config(tables),
        None,
    )
    .await
    .expect("connect");
    conn.subscribe("sub", "SELECT * FROM orders")
        .await
        .expect("subscribe");

    let mut changed: Vec<String> = Vec::new();
    loop {
        let step = conn.next_event().await.expect("step");
        changed.extend(step.changed_tables);
        if matches!(step.event, ClientEvent::SnapshotEnd { .. }) {
            break;
        }
    }
    changed.sort();
    changed.dedup();
    assert_eq!(
        changed,
        vec!["orders".to_owned()],
        "the logical name is reported, and the backing table is not reported beside it",
    );
}

/// A local write goes up under the logical name Postgres knows.
///
/// The write travels through the view's `INSTEAD OF` insert trigger, so the
/// capture session records the backing table. Uploading that name would make
/// the server's write target apply to a Postgres table that does not exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_write_travels_up_under_its_logical_name() {
    let (ddl, tables) = translation();
    let (mut server, client_end) = loopback();
    let uploaded = tokio::spawn(async move {
        ack_handshake(&mut server).await;
        loop {
            match server.recv().await {
                Ok(Some(IncomingFrame::Bulk(BulkMessage::MutationPatch(patch)))) => {
                    return uploaded_tables(&patch);
                }
                Ok(Some(_)) => {}
                _ => panic!("closed before the mutation arrived"),
            }
        }
    });

    let mut conn = ConnettoConnection::connect(
        client_end,
        &Replica::in_memory(),
        &ddl,
        &client_config(tables),
        None,
    )
    .await
    .expect("connect");

    diesel::insert_into(orders::table)
        .values((
            orders::id.eq(9),
            orders::owner_id.eq(ALICE),
            orders::quantity.eq(3),
        ))
        .execute(conn.conn())
        .expect("write through the logical name");
    conn.push().await.expect("push").expect("a sequence number");

    assert_eq!(
        uploaded.await.expect("the upload task"),
        vec!["orders".to_owned()],
        "the wire keeps speaking the Postgres name",
    );
    let stored: Vec<i64> = orders_rls::table
        .select(orders_rls::id)
        .load(conn.conn())
        .expect("read the backing table");
    assert_eq!(
        stored,
        vec![9],
        "and the row itself went through the trigger into the backing table",
    );
}

/// A full resync clears the backing table, so a row the local policy hides is
/// removed too and a sibling subscription's row survives.
///
/// This is the resync half, unverified against real translator output until
/// now. Clearing through the view would fire the generated `INSTEAD OF` delete
/// trigger, which only ever sees rows the policy admits, stranding every
/// hidden row where nothing later removes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resync_clears_hidden_rows_and_spares_a_sibling() {
    let (ddl, tables) = translation();
    let (mut server, client_end) = loopback();
    tokio::spawn(async move {
        ack_handshake(&mut server).await;
        wait_subscribe(&mut server).await;
        // Subscription A: one visible row and one the local policy hides, both
        // of which A must lose on its resync.
        send_snapshot(&mut server, "sub-a", &[(1, ALICE, 20), (3, "bob", 30)], 1).await;
        wait_subscribe(&mut server).await;
        send_snapshot(&mut server, "sub-b", &[(2, ALICE, 5)], 2).await;
        server
            .send_control(ControlMessage::FullResyncRequired(FullResyncRequired {
                sub_id: "sub-a".to_owned(),
                reason: FullResyncReason::CursorOutsideRetention,
            }))
            .await
            .expect("resync");
        send_snapshot(&mut server, "sub-a", &[(1, ALICE, 20)], 3).await;
        while let Ok(Some(_)) = server.recv().await {}
    });

    let mut conn = ConnettoConnection::connect(
        client_end,
        &Replica::in_memory(),
        &ddl,
        &client_config(tables),
        None,
    )
    .await
    .expect("connect");
    conn.subscribe("sub-a", "SELECT * FROM orders WHERE quantity > 10")
        .await
        .expect("subscribe a");
    pump_to_snapshot_end(&mut conn).await;
    conn.subscribe("sub-b", "SELECT * FROM orders WHERE quantity <= 10")
        .await
        .expect("subscribe b");
    pump_to_snapshot_end(&mut conn).await;

    let before: Vec<i64> = orders_rls::table
        .select(orders_rls::id)
        .order(orders_rls::id.asc())
        .load(conn.conn())
        .expect("read the backing table");
    assert_eq!(
        before,
        vec![1, 2, 3],
        "control: every snapshot row is physically present before the resync",
    );

    pump_to_snapshot_end(&mut conn).await;
    let after: Vec<i64> = orders_rls::table
        .select(orders_rls::id)
        .order(orders_rls::id.asc())
        .load(conn.conn())
        .expect("read the backing table");
    assert_eq!(
        after,
        vec![1, 2],
        "row 3 goes even though the policy hid it, and subscription B's row 2 stays",
    );
}

/// A replica whose views the configured map does not account for refuses to
/// open, naming what disagreed.
///
/// The map is application configuration, so the reachable mistake is a schema
/// that grew a policy against a client that was not rebuilt. Allowing the open
/// would restore exactly the silent loss this phase removes.
#[test]
fn an_unaccounted_policy_view_refuses_to_open() {
    let (ddl, _) = translation();
    let refused = ConnettoConnection::<LoopbackTransport>::open(
        &Replica::in_memory(),
        &ddl,
        &client_config(PolicyTables::new()),
        None,
    )
    .err()
    .expect("opening must be refused");
    let ClientError::PolicyTablesStale { unmapped } = refused else {
        panic!("expected a stale-map refusal, got {refused}");
    };
    assert_eq!(
        unmapped,
        vec![
            "orders is a view the build's translation does not account for".to_owned(),
            "orders_rls_violations is a view the build's translation does not account for"
                .to_owned(),
        ],
        "both the policy view and the translation's own view are named",
    );
}
