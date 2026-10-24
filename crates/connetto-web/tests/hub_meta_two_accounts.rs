//! Browser acceptance for the account switch against the relay hub's own
//! state database, the durable file the `account_switch` suite never opened.
//!
//! That suite proves the replica and the device-private database stay per
//! identity, but it never builds a [`RelayHub`], so the hub meta attach was
//! the one durable open the switch left untested. This suite plays two
//! consecutive worker boots, an A to B switch and the return, against a real
//! OPFS pool. Each boot opens its own account's replica through the same path
//! `boot_db_worker` uses and then builds the hub over the meta name derived
//! from that replica, and each account's hub state must stay its own across
//! the switch.
//! Runs in a dedicated worker for the sahpool VFS.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_client::cipher::{ReplicaKey, UnlockError};
use connetto_client::{
    ClientBuilder, ClientError, ConnettoConnection, ContentPlace, Custody, FirstThen, Gate,
    HeldCredential, Located, ReplicaPlace, SyncSchema,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::test_support::FakeTransport;
use connetto_core::traits::{ReplicaKeyStore, Transport};
use connetto_web::RelayHub;
use connetto_web::auth::{BuilderKeyStore, IdbKeyStore};
use connetto_web::storage::{ReplicaStorage, hub_meta_db_name, replica_name};
use diesel::prelude::*;
use std::rc::Rc;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const SQLITE_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";

/// Distinct from the other suites' names so one OPFS pool holds them all.
const PREFIX: &str = "hubmeta-switch";

/// The marker row in the hub's own state table: the watermark it would keep
/// for one tab, so "the state stays its own" is a claim about a specific row.
const MARKER_READ: &str = "SELECT last_seq FROM _tab_mutations \
    WHERE client_id = X'0123456789abcdef0123456789abcdef'";
const MARKER_WRITE: &str = "INSERT INTO _tab_mutations (client_id, last_seq) \
    VALUES (X'0123456789abcdef0123456789abcdef', 41)";
const MARKER_SEQ: i64 = 41;

/// The client schema over [`SQLITE_DDL`].
fn schema() -> SyncSchema {
    SyncSchema::new(SchemaBundle::new(
        "",
        "",
        SQLITE_DDL,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        None::<&str>,
    ))
}

/// The application's OPFS pool: each replica name is prefixed the way the
/// worker's `OpfsPlace` does, over the credential's own derived name.
struct PrefixPlace<'a> {
    prefix: &'static str,
    storage: &'a ReplicaStorage,
}

impl ReplicaPlace for PrefixPlace<'_> {
    fn locate(&self, name: &str) -> Result<Located, ClientError> {
        let db = connetto_web::storage::replica_entry(self.prefix, name);
        let url = self.storage.db_url(&db);
        let exists = self.storage.exists(&db);
        Ok(Located::new(db, url, exists, ContentPlace::InMemory))
    }
}

/// A key store holding one key for every record, the boot's own.
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

async fn share_store() -> BuilderKeyStore {
    BuilderKeyStore::new(Rc::new(
        IdbKeyStore::open().await.expect("open the key store"),
    ))
}

/// The account's replica, opened the way the worker opens it: the name
/// derived from the credential, the codec URL over the pool VFS, the
/// account's own key, over a fake server that acknowledges the handshake
/// and nothing else.
async fn open_replica(
    storage: &ReplicaStorage,
    identity: &str,
    key: ReplicaKey,
) -> Result<ConnettoConnection<FakeTransport>, ClientError> {
    let place = PrefixPlace {
        prefix: PREFIX,
        storage,
    };
    ClientBuilder::new(schema(), once(FakeTransport::accepting()))
        .signed_in(
            HeldCredential::new(connetto_client::Grant::new("user:tester"), identity)
                .expect("a string identity serializes"),
        )
        .durable(place, Holding(key), share_store().await)
        .with_gate(Gate::off())
        .connect_driven()
        .await
}

fn key_from_byte(byte: u8) -> ReplicaKey {
    ReplicaKey::from_bytes([byte; ReplicaKey::LEN])
}

/// The hub meta file under `key`, opened the way the worker opens the tier:
/// its own connection over the storage seam's URL, the replica key applied
/// explicitly.
fn open_hub_meta(
    storage: &ReplicaStorage,
    name: &str,
    key: &ReplicaKey,
) -> Result<SqliteConnection, UnlockError> {
    let mut conn = SqliteConnection::establish(&storage.db_url(name)).expect("open the file");
    connetto_client::cipher::unlock(&mut conn, key)?;
    Ok(conn)
}

/// The watermark the hub holds for the marker tab, `None` while it holds none.
fn marker_seq(conn: &mut SqliteConnection) -> Option<i64> {
    // The hub keeps its tab watermarks in this file's own `_tab_mutations`;
    // opened directly it is not modeled with `table!`, so raw SQL.
    #[derive(diesel::QueryableByName)]
    struct MarkerRow {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        last_seq: i64,
    }
    let rows: Vec<MarkerRow> = diesel::sql_query(MARKER_READ)
        .load(conn)
        .expect("read the marker row");
    rows.into_iter().next().map(|row| row.last_seq)
}

/// Two consecutive worker boots, an A to B switch and the return: each boot
/// builds its hub over the meta name derived from its own replica, and each
/// hub state stays its own across the switch.
#[wasm_bindgen_test]
async fn an_account_switch_builds_each_accounts_own_hub() {
    let storage = ReplicaStorage::install().await;
    assert_eq!(
        storage.vfs_name(),
        "opfs-sahpool",
        "the suite needs the real OPFS pool, not the in-memory fallback"
    );

    // The pool is shared with the other suites in this origin, so start from
    // a known state rather than from whatever an earlier run left.
    let alice = replica_name(PREFIX, "alice").expect("derive alice");
    let bob = replica_name(PREFIX, "bob").expect("derive bob");
    let alice_hub = hub_meta_db_name(&alice);
    let bob_hub = hub_meta_db_name(&bob);
    // Every database this test will hold at once, plus a rollback journal for
    // each, against a pool that ships six slots. `boot_db_worker` reserves
    // for the same reason.
    storage.reserve(8).await.expect("room in the pool");
    for name in [
        alice.as_str(),
        bob.as_str(),
        alice_hub.as_str(),
        bob_hub.as_str(),
    ] {
        storage.delete_db(name).expect("clear the pool entry");
    }

    // The first boot, as account A. Its hub attaches the meta derived from
    // A's replica name and creates it under A's replica key. The block ends
    // with a clean connection close, which checkpoints the meta's pages into
    // the file.
    {
        let worker = open_replica(&storage, "alice", key_from_byte(0x11))
            .await
            .expect("open alice's replica");
        let (_hub, _pump, _notices) =
            RelayHub::new(worker, &alice_hub).expect("alice's hub attaches its meta");
    }
    assert!(
        storage.exists(&alice_hub),
        "the first boot leaves its hub meta behind"
    );

    // Mark the state the hub left behind through a second connection, so
    // "stays its own" is a claim about a specific row.
    let mut alice_meta = open_hub_meta(&storage, &alice_hub, &key_from_byte(0x11))
        .expect("alice's hub meta opens under alice's key");
    diesel::sql_query(MARKER_WRITE)
        .execute(&mut alice_meta)
        .expect("mark the state");
    drop(alice_meta);

    // The switch. Bob's boot opens his own replica without trouble, because
    // the replica is per account, and then builds his hub over the meta
    // derived from his own replica name.
    {
        let worker = open_replica(&storage, "bob", key_from_byte(0x22))
            .await
            .expect("bob's replica opens: the replica itself is per account");
        let (_hub, _pump, _notices) =
            RelayHub::new(worker, &bob_hub).expect("bob's hub builds over the meta of his boot");
    }

    // Bob's hub state is his own: the hub's schema is there, and the marker
    // row alice left in hers is not in his file.
    let mut bob_meta = open_hub_meta(&storage, &bob_hub, &key_from_byte(0x22))
        .expect("bob's hub meta opens under bob's key");
    assert_eq!(
        marker_seq(&mut bob_meta),
        None,
        "bob's hub state holds none of alice's rows"
    );
    drop(bob_meta);

    // Alice's file stays opaque to bob's key, the way her replica does.
    match open_hub_meta(&storage, &alice_hub, &key_from_byte(0x22)) {
        Err(UnlockError::WrongKey(_)) => {}
        Err(other) => panic!("expected WrongKey, got {other:?}"),
        Ok(_) => panic!("one identity's key must not open another's hub meta"),
    }

    // Switching back to alice. Her boot builds her hub again, and the state
    // she left is still hers.
    {
        let worker = open_replica(&storage, "alice", key_from_byte(0x11))
            .await
            .expect("alice's replica still opens");
        let (_hub, _pump, _notices) =
            RelayHub::new(worker, &alice_hub).expect("switching back re-attaches alice's meta");
    }
    let mut alice_meta = open_hub_meta(&storage, &alice_hub, &key_from_byte(0x11))
        .expect("alice's hub meta still opens");
    assert_eq!(
        marker_seq(&mut alice_meta),
        Some(MARKER_SEQ),
        "alice's hub state survived the switch"
    );
}
