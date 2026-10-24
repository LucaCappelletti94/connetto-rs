//! R11 slice 3 in the browser: what a late tab reads when the device stores
//! some tables once for every account.
//!
//! Runs in a dedicated worker against real OPFS, because the shared store is
//! one OPFS file behind one page codec handle, and only the sahpool VFS gives
//! two sequential identities that single underlying handle per file. Every
//! connection is scoped so only one is ever live per file, as the pool
//! requires.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use core::time::Duration;

use connetto_client::{
    ClientBuilder, ClientError, ConnettoConnection, ContentPlace, Custody, FirstThen, Gate, Grant,
    HeldCredential, Located, ReplicaKey, ReplicaPlace, SyncSchema,
};
use connetto_core::messages::SubscriptionSpec;
use connetto_core::schema::{SchemaBundle, SharedLayout};
use connetto_core::test_support::FakeTransport;
use connetto_core::traits::{ReplicaKeyStore, Transport};
use connetto_web::MessageTransport;
use connetto_web::storage::ReplicaStorage;
use diesel::prelude::*;
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::MessagePort;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The private table, in every layout.
const ORDERS_DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY, label TEXT)";
/// The reader the layout recreates on every open, a TEMP view over the split
/// shared table's backing table in the attached store.
const TEMP_READER: &str =
    "CREATE TEMP VIEW public AS SELECT id, owner_id FROM connetto_shared.public_rls";
/// The shared file's initialization.
const SHARED_DDL: &str = "CREATE TABLE connetto_shared.entries (id INTEGER PRIMARY KEY, author TEXT); \
     CREATE TABLE connetto_shared.public_rls (id INTEGER PRIMARY KEY, owner_id TEXT NOT NULL)";
/// The main layout a relay tab's mirror runs: every table as an ordinary
/// main-schema table, the split one read through its view.
const MIRROR_DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY, label TEXT); \
     CREATE TABLE entries (id INTEGER PRIMARY KEY, author TEXT); \
     CREATE TABLE public_rls (id INTEGER PRIMARY KEY, owner_id TEXT NOT NULL); \
     CREATE VIEW public AS SELECT id, owner_id FROM public_rls";

diesel::table! {
    /// The private table, in the replica and the mirror alike.
    orders (id) {
        /// Order identifier.
        id -> Integer,
        /// The tab-facing label.
        label -> Text,
    }
}

diesel::table! {
    /// The shared table. Bare, because it resolves to the attached store on
    /// a worker connection and to the tab's own mirror on a tab.
    entries (id) {
        /// Entry identifier.
        id -> Integer,
        /// Which identity wrote the entry.
        author -> Text,
    }
}

diesel::table! {
    /// The logical view over the split shared table.
    public (id) {
        /// Entry identifier.
        id -> Integer,
        /// Which identity wrote the entry.
        owner_id -> Text,
    }
}

diesel::table! {
    /// The physical backing table of the split shared table, which the
    /// layout's reader selects and the server's replay writes.
    public_rls (id) {
        /// Entry identifier.
        id -> Integer,
        /// Which identity wrote the entry.
        owner_id -> Text,
    }
}

diesel::allow_tables_to_appear_in_same_query!(orders, entries);

/// The row shape of a raw count probe, which needs a by-name row type.
#[derive(Debug, diesel::QueryableByName)]
struct RowCount {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
}

/// The record the client locates for the shared store.
fn shared_record() -> String {
    connetto_client::shared_store_name(connetto_client::REPLICA_PREFIX)
}

/// The fixture bundle, shared by the worker, the tab and the control.
fn bundle() -> SchemaBundle {
    SchemaBundle::new(
        "",
        "",
        MIRROR_DDL,
        [("public", "public_rls")],
        ["public"],
        None::<&str>,
    )
    .with_shared_tables(["entries", "public"])
    .with_shared_layout(SharedLayout::new(
        format!("{ORDERS_DDL}; {TEMP_READER}; {SHARED_DDL}"),
        format!("{ORDERS_DDL}; {TEMP_READER}"),
        format!("{SHARED_DDL}; {TEMP_READER}"),
        TEMP_READER,
    ))
}

/// A dialer handing out `transport` once and nothing after.
fn once<T: Transport + 'static>(
    transport: T,
) -> FirstThen<impl FnMut() -> core::future::Ready<Result<T, &'static str>>> {
    FirstThen::new(transport, || core::future::ready(Err("spent")))
}

/// The OPFS pool as the replica place: every name lands in the pool under
/// its own entry.
struct Opfs<'a> {
    storage: &'a ReplicaStorage,
}

impl ReplicaPlace for Opfs<'_> {
    fn locate(&self, name: &str) -> Result<Located, ClientError> {
        Ok(Located::new(
            name,
            self.storage.db_url(name),
            self.storage.exists(name),
            ContentPlace::InMemory,
        ))
    }
}

/// A preprovisioned key store: the identity's key for its replica, the
/// device's key for the shared store, and the browser never mints either.
struct Keys {
    replica: ReplicaKey,
    shared: ReplicaKey,
}

impl ReplicaKeyStore for Keys {
    type Error = ClientError;

    fn load(
        &self,
        name: &str,
    ) -> impl core::future::Future<Output = Result<Option<ReplicaKey>, ClientError>> {
        let key = if name == shared_record() {
            &self.shared
        } else {
            &self.replica
        };
        core::future::ready(Ok(Some(key.clone())))
    }

    fn store(
        &self,
        _name: &str,
        _key: &ReplicaKey,
    ) -> impl core::future::Future<Output = Result<(), ClientError>> {
        core::future::ready(Ok(()))
    }

    fn clear(&self, _name: &str) -> impl core::future::Future<Output = Result<(), ClientError>> {
        core::future::ready(Ok(()))
    }

    fn protection(&self) -> Custody {
        Custody::Ephemeral
    }
}

/// The signed-in identity `id` over the fixture schema, on the OPFS pool, the
/// shared store enabled when `shared`.
async fn connect(
    storage: &ReplicaStorage,
    id: &str,
    key: ReplicaKey,
    shared: bool,
) -> Result<connetto_client::ConnettoConnection<FakeTransport>, ClientError> {
    let schema = SyncSchema::new(bundle()).with_shared_store(shared);
    // A default accepting() closes the upstream after its frames, and the hub's pump would drop the tabs with it.
    ClientBuilder::new(schema, once(FakeTransport::accepting_but_silent()))
        .signed_in(
            HeldCredential::new(Grant::new(format!("user:{id}")), id)
                .expect("a string identity serializes"),
        )
        .durable(
            Opfs { storage },
            Keys {
                replica: key,
                shared: ReplicaKey::from_bytes([0x33; ReplicaKey::LEN]),
            },
            connetto_client::MemoryRefreshStore::default(),
        )
        .with_gate(Gate::off())
        .connect_driven()
        .await
}

/// The join every tab runs against its mirror, private and shared together.
fn join(tab: &mut ConnettoConnection<MessageTransport<MessagePort>>) -> Vec<(String, String)> {
    orders::table
        .inner_join(entries::table.on(orders::id.eq(entries::id)))
        .select((orders::label, entries::author))
        .load(tab.conn())
        .expect("the join reads the tab's mirror")
}

/// A hub over `worker`, the tab end of a real message channel, and a signed-in
/// tab client attached to it.
async fn hub_with_late_tab(
    worker: connetto_client::ConnettoConnection<FakeTransport>,
) -> (
    connetto_web::RelayHub,
    ConnettoConnection<MessageTransport<MessagePort>>,
) {
    let (hub, pump, _notices) = connetto_web::RelayHub::new(worker, ":memory:").expect("hub meta");
    spawn_local(async move {
        pump.await.expect("hub pump");
    });
    let channel = web_sys::MessageChannel::new().expect("message channel");
    hub.attach(MessageTransport::<MessagePort>::new(channel.port1()));
    let mirror = SyncSchema::new(bundle()).relay_mirror();
    let tab = ClientBuilder::new(
        mirror,
        once(MessageTransport::<MessagePort>::new(channel.port2())),
    )
    .with_client_id("r11-late-tab")
    .connect_driven()
    .await
    .expect("the tab connects");
    (hub, tab)
}

/// Alice's run, which writes the shared rows to the one shared file.
async fn seed_alice(storage: &ReplicaStorage) {
    let mut alice = connect(
        storage,
        "alice",
        ReplicaKey::from_bytes([0x11; ReplicaKey::LEN]),
        true,
    )
    .await
    .expect("alice connects");
    diesel::insert_into(entries::table)
        .values((entries::id.eq(1), entries::author.eq("alice")))
        .execute(&mut *alice.conn())
        .expect("alice writes the shared store");
    diesel::insert_into(entries::table)
        .values((entries::id.eq(2), entries::author.eq("second")))
        .execute(&mut *alice.conn())
        .expect("alice writes the shared store");
    diesel::insert_into(public_rls::table)
        .values((public_rls::id.eq(7), public_rls::owner_id.eq("alice")))
        .execute(&mut *alice.conn())
        .expect("alice seeds the split table's backing table");
}

/// The shared store is one OPFS file both identities key with the device key,
/// and the second identity's late tab reads the first identity's rows through
/// the hub, joining them with the second's own private rows.
#[wasm_bindgen_test]
async fn a_second_identitys_late_tab_reads_the_first_identitys_shared_rows() {
    let storage = ReplicaStorage::install().await;
    let alice_name = connetto_client::replica_db_name(connetto_client::REPLICA_PREFIX, "alice")
        .expect("a replica name");
    let bob_name = connetto_client::replica_db_name(connetto_client::REPLICA_PREFIX, "bob")
        .expect("a replica name");
    for name in [
        alice_name.as_str(),
        bob_name.as_str(),
        shared_record().as_str(),
    ] {
        storage.delete_db(name).expect("clear the entry");
    }
    storage.reserve(4).await.expect("room in the pool");

    // Alice writes the shared rows to the one shared file, then her run ends.
    seed_alice(&storage).await;

    // Bob's fresh replica gets the policy object recreated in its own main
    // file, and the shared rows are visible through it while living outside
    // main.
    let mut bob = connect(
        &storage,
        "bob",
        ReplicaKey::from_bytes([0x22; ReplicaKey::LEN]),
        true,
    )
    .await
    .expect("bob connects");
    let count: i64 = entries::table
        .count()
        .get_result(&mut *bob.conn())
        .expect("bob reads the shared store through the reader");
    assert_eq!(count, 2, "alice's rows are visible under the bare name");
    // The DSL cannot probe a schema's catalogue, so the raw read stays.
    let readers: RowCount = diesel::sql_query(
        "SELECT count(*) AS count FROM temp.sqlite_master WHERE type = 'view' AND name = 'public'",
    )
    .get_result(&mut *bob.conn())
    .expect("the temp catalogue reads");
    assert_eq!(
        readers.count, 1,
        "bob's open recreated the reader in its own connection"
    );
    // The DSL cannot name a table absent from a schema, so the absence probe stays raw.
    let absent = diesel::sql_query("SELECT count(*) AS count FROM main.entries")
        .get_result::<RowCount>(&mut *bob.conn())
        .expect_err("main holds no copy of the shared table");
    assert!(
        format!("{absent:?}").contains("no such table"),
        "the absence is a missing table, not a refused read: {absent:?}"
    );
    diesel::insert_into(orders::table)
        .values((orders::id.eq(1), orders::label.eq("one")))
        .execute(&mut *bob.conn())
        .expect("bob writes his private rows");
    diesel::insert_into(orders::table)
        .values((orders::id.eq(2), orders::label.eq("two")))
        .execute(&mut *bob.conn())
        .expect("bob writes his private rows");

    let (_hub, mut tab) = hub_with_late_tab(bob).await;
    tab.subscribe_spec("s1", SubscriptionSpec::new("SELECT id, label FROM orders"))
        .await
        .expect("the tab subscribes");
    tab.subscribe_spec(
        "s2",
        SubscriptionSpec::new("SELECT id, author FROM entries"),
    )
    .await
    .expect("the tab subscribes the shared table");
    let expected = [
        ("one".to_owned(), "alice".to_owned()),
        ("two".to_owned(), "second".to_owned()),
    ];
    let mut got = Vec::new();
    for _ in 0..100 {
        let _ = tab
            .pump_one_or(connetto_web::workers::sleep(Duration::from_millis(50)))
            .await
            .ok();
        got = join(&mut tab);
        if got.len() == expected.len() {
            break;
        }
    }
    assert_eq!(
        got, expected,
        "the join lands private and shared rows together"
    );
}

/// With the shared store disabled the same names are ordinary replica tables
/// and the late tab reads them from the replica, from a fresh name of its own.
#[wasm_bindgen_test]
async fn a_disabled_shared_store_never_serves_store_rows() {
    let storage = ReplicaStorage::install().await;
    let carol_name = connetto_client::replica_db_name(connetto_client::REPLICA_PREFIX, "carol")
        .expect("a replica name");
    storage.delete_db(&carol_name).expect("clear the entry");
    storage.reserve(2).await.expect("room in the pool");

    let mut carol = connect(
        &storage,
        "carol",
        ReplicaKey::from_bytes([0x44; ReplicaKey::LEN]),
        false,
    )
    .await
    .expect("carol connects");
    assert!(
        carol.shared_tables().is_empty(),
        "a disabled store names no shared tables"
    );
    diesel::insert_into(orders::table)
        .values((orders::id.eq(1), orders::label.eq("one")))
        .execute(&mut *carol.conn())
        .expect("carol writes her private rows");
    diesel::insert_into(entries::table)
        .values((entries::id.eq(1), entries::author.eq("carol")))
        .execute(&mut *carol.conn())
        .expect("carol writes her entries");
    let (_hub, mut tab) = hub_with_late_tab(carol).await;
    tab.subscribe_spec("s1", SubscriptionSpec::new("SELECT id, label FROM orders"))
        .await
        .expect("the tab subscribes");
    tab.subscribe_spec(
        "s2",
        SubscriptionSpec::new("SELECT id, author FROM entries"),
    )
    .await
    .expect("the tab subscribes");
    let mut got = Vec::new();
    for _ in 0..100 {
        let _ = tab
            .pump_one_or(connetto_web::workers::sleep(Duration::from_millis(50)))
            .await
            .ok();
        got = join(&mut tab);
        if !got.is_empty() {
            break;
        }
    }
    assert_eq!(
        got,
        [("one".to_owned(), "carol".to_owned())],
        "the same names serve from the replica when the store is off"
    );
}
