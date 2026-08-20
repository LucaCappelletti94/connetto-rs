//! The logout guard, against work that is genuinely stuck offline.
//!
//! The other logout coverage runs against a live stack, where the replica is always
//! caught up, so the refusal never fires and a forced delete forces past nothing.
//! This suite arranges the opposite: a replica holding a mutation that cannot be
//! uploaded, which is what a user who wrote something on a train and then pressed
//! "delete my data" actually has.
//!
//! Offline is `FakeTransport`, which answers the handshake and acknowledges nothing
//! after it, so an uploaded mutation is never retired. No server of any kind runs
//! here, and none is needed: the guard is consulted before the revoke, so the
//! refusal path never reaches the network.
//!
//! Runs in a dedicated worker for the OPFS sahpool VFS, and drives a real
//! [`ConnettoConnection`] behind a real [`RelayHub`], because the count the guard
//! reads comes out of the hub's pump and nowhere else.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_client::{ClientConfig, ConnettoConnection, Replica};
use connetto_core::test_support::{FakeTransport, replica_key};
use connetto_web::RelayHub;
use connetto_web::auth::{LogoutOutcome, WorkerAuthConfig, request_logout, request_unsynced};
use connetto_web::storage::{ReplicaStorage, take_pending_wipes};
use connetto_web::workers::serve_logout_requests;
use diesel::prelude::*;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const SQLITE_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";

/// Distinct from the other suites' names so one OPFS pool holds them all.
const REPLICA: &str = "e43-refusal.sqlite";
/// Never opened for a credential in this suite, because the refusal comes first.
const AUTH_DB: &str = "e43-refusal-auth.sqlite";

diesel::table! {
    /// Test table for replica contents
    items (id) {
        /// Item identifier, the primary key
        id -> Integer,
        /// Optional item label
        label -> Nullable<Text>,
    }
}

fn config() -> ClientConfig {
    ClientConfig::new(rosetta_uuid::Uuid::new_v4().to_string())
        .with_login(Some(connetto_client::Grant::new("user:tester")))
}

/// An auth base that would fail loudly if anything tried to use it. The refusal
/// path must not reach the network, and a forced logout with no stored credential
/// returns before it would.
fn unused_auth() -> WorkerAuthConfig {
    WorkerAuthConfig::new("http://127.0.0.1:1", "unused", "http://127.0.0.1:1/unused")
}

/// A delete is refused while a write is stranded offline, and forcing it through
/// destroys the replica anyway.
#[wasm_bindgen_test]
async fn a_delete_is_refused_while_a_write_is_stranded_and_force_overrides_it() {
    let storage = ReplicaStorage::install().await;
    storage
        .delete_db(REPLICA)
        .expect("clear an earlier replica");
    storage
        .delete_db(AUTH_DB)
        .expect("clear an earlier auth db");
    take_pending_wipes().await.expect("drain any earlier wipes");

    // Strand a write: the insert is captured, the push uploads it, and the fake
    // upstream never acknowledges it, so its seq stays queued for good.
    let url = storage.db_url(REPLICA);
    let mut worker = ConnettoConnection::connect(
        FakeTransport::accepting_but_silent(),
        &Replica::encrypted_file(&url, Some(replica_key())).expect("a resolved key"),
        SQLITE_DDL,
        &config(),
        None,
    )
    .await
    .expect("connect over an upstream that never acknowledges");
    diesel::insert_into(items::table)
        .values((items::id.eq(1), items::label.eq("written on a train")))
        .execute(worker.conn())
        .expect("write locally");
    worker.push().await.expect("upload the captured mutation");
    let stranded = worker.unsynced();
    assert!(
        !stranded.is_empty(),
        "the fake upstream acknowledges nothing, so the write stays queued"
    );

    // The hub takes the connection, so from here the count is only reachable by
    // asking the pump, which is exactly what the logout service does.
    let (hub, pump, _notices) = RelayHub::new(worker, ":memory:").expect("hub meta");
    wasm_bindgen_futures::spawn_local(async move {
        pump.await.expect("hub pump");
    });
    serve_logout_requests(unused_auth(), AUTH_DB, REPLICA, None, hub.clone())
        .expect("install the logout service");

    // The query reports the stranded work, so a prompt can name it.
    assert_eq!(
        request_unsynced().await.expect("the worker answers"),
        stranded,
        "the query reports exactly what is queued"
    );

    // The delete is refused, and refused without destroying anything, so the write
    // can still be uploaded once the network returns.
    assert_eq!(
        request_logout(true, false)
            .await
            .expect("the worker answers"),
        LogoutOutcome::Refused {
            seqs: stranded.clone()
        },
        "a delete that would lose queued work is refused"
    );
    assert!(
        take_pending_wipes().await.expect("drain").is_empty(),
        "the refusal marks nothing for deletion"
    );

    // Forcing is the user saying they understand. Now it goes through, and the
    // replica is marked for destruction at the next startup.
    assert_eq!(
        request_logout(true, true)
            .await
            .expect("the worker answers"),
        LogoutOutcome::Deleted,
        "force destroys the replica despite the queued work"
    );
    assert_eq!(
        take_pending_wipes().await.expect("drain"),
        vec![REPLICA.to_owned()],
        "the forced delete marks this replica"
    );
}
