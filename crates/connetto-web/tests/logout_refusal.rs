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

use core::cell::Cell;
use core::convert::Infallible;
use core::future::ready;
use std::rc::Rc;

use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{ClientConfig, ConnettoConnection, Replica};
use connetto_core::test_support::{FakeTransport, replica_key};
use connetto_core::{BulkMessage, ControlMessage, IncomingFrame, Transport};
use connetto_file_client::{BrowserStore, ContentArchive};
use connetto_file_core::{EncryptingStore, MimeClass, process_file};
use connetto_web::RelayHub;
use connetto_web::auth::{
    AuthError, LogoutOutcome, PendingWork, WorkerAuthConfig, forget_retired_content,
    request_logout, request_unsynced,
};
use connetto_web::relay::HubReconnect;
use connetto_web::storage::{PendingWipe, ReplicaStorage, take_pending_wipes};
use connetto_web::workers::{LogoutConfig, serve_logout_requests};
use diesel::prelude::*;
use diesel::sql_types::{BigInt, Binary};
use tokio::sync::Notify;
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
struct CountingTransport {
    inner: FakeTransport,
    ticket_requests: Rc<Cell<u32>>,
    ticket_sent: Rc<Notify>,
}

impl CountingTransport {
    fn new(ticket_requests: Rc<Cell<u32>>, ticket_sent: Rc<Notify>) -> Self {
        Self {
            inner: FakeTransport::accepting_but_silent(),
            ticket_requests,
            ticket_sent,
        }
    }
}

impl Transport for CountingTransport {
    type Error = <FakeTransport as Transport>::Error;

    async fn send_control(&mut self, message: ControlMessage) -> Result<(), Self::Error> {
        if matches!(&message, ControlMessage::ContentTicketRequest(_)) {
            self.ticket_requests
                .set(self.ticket_requests.get().saturating_add(1));
            self.ticket_sent.notify_one();
        }
        self.inner.send_control(message).await
    }

    async fn send_bulk(&mut self, message: BulkMessage) -> Result<(), Self::Error> {
        self.inner.send_bulk(message).await
    }

    async fn recv(&mut self) -> Result<Option<IncomingFrame>, Self::Error> {
        self.inner.recv().await
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.inner.close().await
    }
}

async fn stage_pending_content<T: Transport>(
    worker: &mut ConnettoConnection<T>,
) -> ContentArchive<BrowserStore> {
    let store = BrowserStore::ephemeral();
    let root_key = [0x71; 32];
    let encrypted = EncryptingStore::new(store.clone(), &root_key);
    let manifest = process_file(b"stranded photo", MimeClass::Generic, &encrypted)
        .await
        .expect("stage content bytes");
    let [chunk] = manifest.chunks() else {
        panic!("the small fixture must produce one chunk");
    };
    let content = ContentArchive::new(store, root_key);
    content.install(worker).expect("install content tables");
    diesel::sql_query(
        "INSERT INTO _connetto_content_chunks (file_id, ordinal, hash, len) VALUES (?, 0, ?, ?)",
    )
    .bind::<Binary, _>(manifest.file_id().as_bytes().to_vec())
    .bind::<Binary, _>(chunk.hash.as_bytes().to_vec())
    .bind::<BigInt, _>(i64::try_from(chunk.len).expect("fixture length"))
    .execute(worker.conn())
    .expect("record content manifest");
    diesel::sql_query("INSERT INTO _connetto_content_outbox (file_id) VALUES (?)")
        .bind::<Binary, _>(manifest.file_id().as_bytes().to_vec())
        .execute(worker.conn())
        .expect("queue content");
    content
}
async fn stranded_worker(
    storage: &ReplicaStorage,
    ticket_requests: Rc<Cell<u32>>,
    ticket_sent: Rc<Notify>,
) -> (
    ConnettoConnection<CountingTransport>,
    ContentArchive<BrowserStore>,
    Vec<u64>,
) {
    let url = storage.db_url(REPLICA);
    let mut worker = ConnettoConnection::connect(
        CountingTransport::new(ticket_requests, ticket_sent),
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
    assert!(!stranded.is_empty(), "the mutation must remain queued");
    let content = stage_pending_content(&mut worker).await;
    (worker, content, stranded)
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
    let ticket_requests = Rc::new(Cell::new(0));
    let ticket_sent = Rc::new(Notify::new());
    let (worker, content, stranded) = stranded_worker(
        &storage,
        Rc::clone(&ticket_requests),
        Rc::clone(&ticket_sent),
    )
    .await;

    let reconnect_tickets = Rc::clone(&ticket_requests);
    let reconnect_signal = Rc::clone(&ticket_sent);
    let reconnect = HubReconnect {
        factory: move || {
            ready(Ok::<_, Infallible>(CountingTransport::new(
                Rc::clone(&reconnect_tickets),
                Rc::clone(&reconnect_signal),
            )))
        },
        sleeper: |_| ready(()),
        policy: ReconnectPolicy::default(),
        upstream: Vec::new(),
    };
    let (hub, pump, _notices) =
        RelayHub::with_reconnect_and_content(worker, ":memory:", reconnect, content)
            .expect("hub meta");
    wasm_bindgen_futures::spawn_local(async move {
        pump.await.expect("hub pump");
    });
    serve_logout_requests(
        LogoutConfig {
            auth: unused_auth(),
            auth_db_name: AUTH_DB.to_owned(),
            replica_db_name: REPLICA.to_owned(),
            content_namespace: Some("content-wipe-namespace".to_owned()),
            account: None,
        },
        hub.clone(),
    )
    .expect("install the logout service");
    ticket_sent.notified().await;

    let pending = PendingWork {
        mutation_seqs: stranded.clone(),
        content_files: 1,
        retired_files: Vec::new(),
    };
    assert_eq!(
        request_unsynced().await.expect("the worker answers"),
        pending,
        "the query reports both queues"
    );

    // The acknowledgement protocol answers the caller that asked: an identity
    // this build cannot read is refused with a reason rather than left to wait.
    assert!(matches!(
        forget_retired_content(vec!["not-a-file-identity".to_owned()]).await,
        Err(AuthError::Store(_))
    ));
    forget_retired_content(Vec::new())
        .await
        .expect("an acknowledgement of nothing is still answered");

    // The delete is refused, and refused without destroying anything, so the write
    // can still be uploaded once the network returns.
    assert_eq!(
        request_logout(true, false)
            .await
            .expect("the worker answers"),
        LogoutOutcome::Refused {
            pending: pending.clone()
        },
        "a delete that would lose queued work is refused"
    );
    assert_eq!(
        ticket_requests.get(),
        1,
        "local requests resume the pending ticket instead of minting another"
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
        vec![PendingWipe::new(
            REPLICA,
            Some("content-wipe-namespace".to_owned())
        )],
        "the forced delete names both stores"
    );
}
