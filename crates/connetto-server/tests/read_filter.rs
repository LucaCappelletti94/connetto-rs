//! Read-filter acceptance test (Docker-free).
//!
//! The live dispatch path must deliver a row to a session only when the
//! session's auth context may see it, except deletes, which replay as
//! tombstones regardless so a client drops a row it may still hold. This drives
//! CDC through a session whose auth policy denies one primary key and asserts
//! the denied insert is withheld while the later delete for that key still
//! arrives.

#![allow(clippy::too_many_lines)]

use std::time::Duration;

use connetto_core::auth::AuthContext;
use connetto_core::messages::{
    BulkMessage, ControlMessage, Handshake, Subscribe, SubscriptionSpec,
};
use connetto_core::traits::{AuthPolicy, IncomingFrame, MutationOp, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::{
    Materializer, SessionConfig, SessionManager, Snapshot, SnapshotSource, loopback,
    sqlite_write_target,
};
use diesel::prelude::*;
use diesel::sql_query;
use subql::backend::Value;
use subql::{CdcSource, PgSqliteEmuSource};

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";

/// Denies reads of the `orders` row whose primary key is id 2, allows the rest,
/// and allows every write. The materializer encodes the pk with the shared
/// [`connetto_server::pk`] codec, so this decodes the bytes and matches the
/// single `Int(2)` component.
struct DenyId2;

impl AuthPolicy for DenyId2 {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn can_read(
        &self,
        _ctx: &AuthContext,
        table: &str,
        pk: &[u8],
    ) -> Result<bool, Self::Error> {
        if table != "orders" {
            return Ok(true);
        }
        let key = connetto_server::pk::decode(pk).expect("pk decodes");
        Ok(!matches!(key.as_slice(), [Value::Int(2)]))
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn can_write(
        &self,
        _ctx: &AuthContext,
        _table: &str,
        _pk: &[u8],
        _op: MutationOp,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A snapshot source with no initial rows.
struct EmptySnapshot;

impl SnapshotSource for EmptySnapshot {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
        _auth: &AuthContext,
    ) -> Result<Snapshot, Self::Error> {
        Ok(Snapshot {
            patchset: Vec::new(),
            cursor: Cursor::new(Vec::new()),
        })
    }
}

diesel::table! {
    orders (id) {
        id -> diesel::sql_types::BigInt,
        price -> diesel::sql_types::Double,
        quantity -> diesel::sql_types::BigInt,
        status -> diesel::sql_types::Text,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: i64,
    price: f64,
    quantity: i64,
    status: String,
}

fn order(id: i64, price: f64, quantity: i64, status: &str) -> Order {
    Order {
        id,
        price,
        quantity,
        status: status.to_owned(),
    }
}

fn client_replica() -> SqliteConnection {
    let mut conn = SqliteConnection::establish(":memory:").expect("open sqlite");
    sql_query(SQLITE_DDL)
        .execute(&mut conn)
        .expect("create table");
    conn
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    match transport.recv().await.expect("recv frame") {
        Some(IncomingFrame::Control(msg)) => msg,
        other => panic!("expected control frame, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_read_filter_withholds_denied_rows_but_replays_tombstones() {
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        EmptySnapshot,
        DenyId2,
        sqlite_write_target(client_replica()),
        SessionConfig::default(),
    );
    let applier = Materializer::new(PG_DDL).expect("build applier");
    let mut replica = client_replica();

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));

    client
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            "client-a",
            "token",
        )))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "orders".to_owned(),
            spec: SubscriptionSpec::row("SELECT * FROM orders WHERE quantity > 0"),
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

    // Drive three inserts (id 2 is denied) then a delete of the denied id.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    for sql in [
        "INSERT INTO orders (id, price, quantity, status) VALUES (1, 9.5, 3, 'a')",
        "INSERT INTO orders (id, price, quantity, status) VALUES (2, 4.0, 5, 'b')",
        "INSERT INTO orders (id, price, quantity, status) VALUES (3, 2.0, 2, 'c')",
        "DELETE FROM orders WHERE id = 2",
    ] {
        source.execute_sql(sql).expect("execute dml");
        while let Some(event) = source.next_event().await.expect("poll source") {
            manager
                .dispatch_event(&event)
                .await
                .expect("dispatch event");
        }
    }

    // Collect live patches until the stream goes idle. Live patches flow
    // through the session's async outbound queue, so a control-plane ping could
    // overtake them; instead wait out a short idle window for each frame.
    let mut live = 0usize;
    loop {
        match tokio::time::timeout(Duration::from_millis(500), client.recv()).await {
            Ok(Ok(Some(IncomingFrame::Bulk(BulkMessage::LivePatch(patch))))) => {
                applier
                    .apply_diffset(&patch.patchset_zstd, &mut replica)
                    .expect("apply live patch");
                live += 1;
            }
            Ok(Ok(Some(other))) => panic!("unexpected frame: {other:?}"),
            Ok(Err(err)) => panic!("recv failed: {err:?}"),
            Ok(Ok(None)) | Err(_) => break,
        }
    }

    // Two inserts delivered (1 and 3), the denied insert (2) withheld, and the
    // delete of 2 still replayed as a tombstone: three live patches total.
    assert_eq!(live, 3, "denied insert withheld, delete replayed");
    // The replica never saw id 2, and the tombstone delete of the absent row is
    // an idempotent no-op, so it holds exactly the two authorized rows.
    assert_eq!(
        orders(&mut replica),
        vec![order(1, 9.5, 3, "a"), order(3, 2.0, 2, "c")],
        "only authorized rows reached the replica",
    );

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}

fn orders(conn: &mut SqliteConnection) -> Vec<Order> {
    orders::table
        .order(orders::id)
        .select(Order::as_select())
        .load(conn)
        .expect("read orders")
}
