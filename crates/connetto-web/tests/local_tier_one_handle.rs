//! R43: the device-private database has exactly one handle, and it is the
//! replica connection's own attachment.
//!
//! The worker used to hold two at once for its whole life, one from the
//! client's `ATTACH` and one standalone connection the relay served from. The
//! browser's storage pool cannot support that: it keys open files by name, so
//! the two shared a single underlying handle while keeping separate page
//! caches, and closing both tripped the pool's own `DB closed without open`
//! assertion.
//!
//! Runs in a dedicated worker against real OPFS, because the property under
//! test is about the pool's handle bookkeeping and an in-memory VFS has none.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_client::{
    ClientBuilder, ClientError, ConnettoConnection, ContentPlace, Custody, FirstThen, Gate,
    HeldCredential, Located, ReplicaKey, ReplicaPlace, SyncSchema,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::test_support::FakeTransport;
use connetto_core::traits::{ReplicaKeyStore, Transport};
use connetto_web::storage::{ReplicaStorage, tier_db_name};
use diesel::prelude::*;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const REPLICA_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";
const TIER_DDL: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT)";

diesel::table! {
    /// Device-private test table, named bare exactly as an application names it.
    drafts (id) {
        /// Draft identifier, the primary key
        id -> Integer,
        /// Optional draft body
        body -> Nullable<Text>,
    }
}

#[derive(diesel::QueryableByName)]
struct SchemaName {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
}

/// A client schema over `ddl`, with `tier` as its device-private tier.
fn schema(ddl: &str, tier: Option<&str>) -> SyncSchema {
    SyncSchema::new(SchemaBundle::new(
        "",
        "",
        ddl,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        tier,
    ))
}

/// The replica at exactly `url`, fresh or already there as the test says.
struct At {
    url: String,
    exists: bool,
}

impl ReplicaPlace for At {
    fn locate(&self, name: &str) -> Result<Located, ClientError> {
        Ok(Located::new(
            name,
            self.url.clone(),
            self.exists,
            ContentPlace::InMemory,
        ))
    }
}

/// A key store holding one key for every record.
struct Holding(ReplicaKey);

impl ReplicaKeyStore for Holding {
    type Error = ClientError;

    fn load(&self, _name: &str) -> impl Future<Output = Result<Option<ReplicaKey>, ClientError>> {
        core::future::ready(Ok(Some(self.0.clone())))
    }

    fn store(
        &self,
        _name: &str,
        _key: &ReplicaKey,
    ) -> impl Future<Output = Result<(), ClientError>> {
        core::future::ready(Ok(()))
    }

    fn clear(&self, _name: &str) -> impl Future<Output = Result<(), ClientError>> {
        core::future::ready(Ok(()))
    }

    fn protection(&self) -> Custody {
        Custody::Ephemeral
    }
}

/// A dialer handing out `transport` once and nothing after.
fn once<T: Transport + 'static>(
    transport: T,
) -> FirstThen<impl FnMut() -> core::future::Ready<Result<T, &'static str>>> {
    FirstThen::new(transport, || core::future::ready(Err("spent")))
}

/// The replica at `url` under `key`, created when `fresh`, connected to a fake
/// server that acknowledges the handshake and nothing else.
async fn connect_at(
    schema: SyncSchema,
    url: &str,
    key: ReplicaKey,
    fresh: bool,
) -> Result<ConnettoConnection<FakeTransport>, ClientError> {
    ClientBuilder::new(schema, once(FakeTransport::accepting()))
        .signed_in(
            HeldCredential::new(connetto_client::Grant::new("user:tester"), "tester")
                .expect("a string identity serializes"),
        )
        .durable(
            At {
                url: url.to_owned(),
                exists: !fresh,
            },
            Holding(key),
        )
        .with_gate(Gate::off())
        .connect_driven()
        .await
}

/// The replica at `url` under `key`, created when `fresh`, with no transport.
async fn open_at(
    schema: SyncSchema,
    url: &str,
    key: ReplicaKey,
    fresh: bool,
) -> Result<ConnettoConnection<FakeTransport>, ClientError> {
    ClientBuilder::new(schema, once(FakeTransport::accepting()))
        .signed_in(
            HeldCredential::new(connetto_client::Grant::new("user:tester"), "tester")
                .expect("a string identity serializes"),
        )
        .durable(
            At {
                url: url.to_owned(),
                exists: !fresh,
            },
            Holding(key),
        )
        .with_gate(Gate::off())
        .open_driven()
        .await
}

/// The tier is reached through the replica connection, and the pool gets its
/// file back the moment that one connection drops.
#[wasm_bindgen_test]
async fn the_tier_is_attached_to_the_replica_and_frees_with_it() {
    let storage = ReplicaStorage::install().await;
    let replica_name = "r43-one-handle.sqlite";
    let tier_name = tier_db_name(replica_name);
    storage.delete_db(replica_name).expect("clear the replica");
    storage.delete_db(&tier_name).expect("clear the tier");
    storage.reserve(4).await.expect("room in the pool");

    let replica_url = storage.db_url(replica_name);
    let key = ReplicaKey::from_bytes([0x5a; ReplicaKey::LEN]);
    {
        let mut conn = connect_at(schema(REPLICA_DDL, Some(TIER_DDL)), &replica_url, key, true)
            .await
            .expect("connect");

        // The attachment is the mechanism, so say so rather than inferring it.
        let attached: Vec<SchemaName> = diesel::sql_query("PRAGMA database_list")
            .load(conn.conn())
            .expect("list the attached schemas");
        let names: Vec<&str> = attached.iter().map(|row| row.name.as_str()).collect();
        assert!(
            names.contains(&"connetto_local"),
            "the tier is attached to the replica connection, got {names:?}"
        );

        // Reachable by a bare name from that same connection, which is what
        // lets one connection serve both tiers.
        diesel::insert_into(drafts::table)
            .values((drafts::id.eq(1), drafts::body.eq("draft")))
            .execute(conn.conn())
            .expect("write a device-private row");
        assert_eq!(
            conn.push().await.expect("push"),
            None,
            "a device-private write is outside the capture session and can never upload"
        );
    }

    // No await between the drop above and the deletes below. A second live
    // handle on either file would have left the pool holding it, and in this
    // build the pool asserts on the mismatched close rather than reporting it.
    storage
        .delete_db(&tier_name)
        .expect("the tier's handle was released with the connection");
    storage
        .delete_db(replica_name)
        .expect("and so was the replica's");
    let listed = storage.list();
    assert!(
        !listed.iter().any(|entry| entry == &tier_name),
        "the tier file is gone from the pool"
    );
}

/// Reopening finds the row, which is the half a page-cache split would break:
/// two handles can each hold pages the other has superseded.
#[wasm_bindgen_test]
async fn a_device_private_row_survives_a_reopen_through_the_attachment() {
    let storage = ReplicaStorage::install().await;
    let replica_name = "r43-reopen.sqlite";
    let tier_name = tier_db_name(replica_name);
    storage.delete_db(replica_name).expect("clear the replica");
    storage.delete_db(&tier_name).expect("clear the tier");
    storage.reserve(4).await.expect("room in the pool");

    let replica_url = storage.db_url(replica_name);
    let key = ReplicaKey::from_bytes([0x6b; ReplicaKey::LEN]);
    {
        let mut conn = connect_at(
            schema(REPLICA_DDL, Some(TIER_DDL)),
            &replica_url,
            key.clone(),
            true,
        )
        .await
        .expect("connect");
        diesel::insert_into(drafts::table)
            .values((drafts::id.eq(7), drafts::body.eq("kept")))
            .execute(conn.conn())
            .expect("write a device-private row");
    }

    let mut conn = connect_at(
        schema(REPLICA_DDL, Some(TIER_DDL)),
        &replica_url,
        key,
        false,
    )
    .await
    .expect("reopen");
    let seen: Vec<Option<String>> = drafts::table
        .select(drafts::body)
        .load(conn.conn())
        .expect("read the tier back");
    assert_eq!(seen, vec![Some("kept".to_owned())]);
}

/// One epoch-seconds reading from the replica's clock.
#[derive(diesel::QueryableByName)]
struct Now {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    secs: i64,
}

/// The replica's own clock is real under the browser's OPFS VFS.
///
/// R29 measures a watch's grace with `strftime('%s','now')` evaluated by
/// SQLite, because the client library deliberately never calls a host clock:
/// `SystemTime::now` panics on `wasm32-unknown-unknown`. If the VFS did not
/// supply a time, the value would be zero or nonsense and every grace would
/// silently read as unexpired, so this asserts a plausible epoch rather than
/// merely that the query runs.
#[wasm_bindgen_test]
async fn the_replica_clock_works_in_the_browser() {
    let storage = ReplicaStorage::install().await;
    storage.delete_db("r29-clock.sqlite").expect("clear");
    storage.reserve(4).await.expect("room in the pool");
    let key = ReplicaKey::from_bytes([0x29; ReplicaKey::LEN]);
    let replica_url = storage.db_url("r29-clock.sqlite");
    let mut conn = open_at(
        schema("CREATE TABLE t (id INTEGER PRIMARY KEY)", None),
        &replica_url,
        key,
        true,
    )
    .await
    .expect("open");

    let now: Now = diesel::sql_query("SELECT CAST(strftime('%s','now') AS INTEGER) AS secs")
        .get_result(conn.conn())
        .expect("read the replica clock");
    // 2023-01-01, comfortably in the past and far above the zero a missing
    // implementation would hand back.
    assert!(
        now.secs > 1_672_531_200,
        "the replica clock reads {} seconds, which is not a real time",
        now.secs
    );
}
