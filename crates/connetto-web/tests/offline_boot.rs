//! R20 step 3: an unreachable server is a state the worker reports, not an
//! error that ends it.
//!
//! The boot used to open a socket and propagate the failure, so an application
//! whose own local features do not depend on connetto still could not start
//! when connetto could not reach anything. Offline operation is a stated
//! objective of this project, and that was the path violating it.
//!
//! No stack needed: the point is precisely that nothing is listening. The port
//! is one nothing binds, and logins are off so the boot reaches the connect
//! without needing an identity provider either.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_client::ExportScope;
use connetto_file_client::BrowserStore;
use connetto_file_core::{ChunkHash, ChunkStore};
use connetto_web::storage::{PendingWipe, ReplicaStorage, mark_wipe_pending, take_pending_wipes};
use connetto_web::workers::{DbWorkerConfig, boot_db_worker, request_export};
use wasm_bindgen::JsCast;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::DedicatedWorkerGlobalScope;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const REPLICA_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";
const TIER_DDL: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT)";

/// A port nothing in this suite binds, so the connect attempt genuinely fails
/// rather than reaching something unexpected.
const NOWHERE: &str = "ws://127.0.0.1:9/connetto";

fn config() -> DbWorkerConfig {
    DbWorkerConfig::new(connetto_core::SchemaVersion::from_source(REPLICA_DDL))
        .with_ws_url(NOWHERE)
        .with_replica_db_prefix("r20-offline-boot.sqlite")
        .with_replica_ddl(REPLICA_DDL)
        .with_frontend_ddl(TIER_DDL)
        .with_upstream_sub_id("r20-upstream")
        .with_upstream_query("SELECT * FROM items")
        .with_hub_meta_name("r20-offline-boot-hub.sqlite")
        .with_content_namespace("r68-offline-content")
        .with_auth_db_name("r20-offline-boot-auth.sqlite")
}

/// The worker comes up with nothing listening, and says so by completing.
#[wasm_bindgen_test]
async fn the_worker_starts_with_no_server_reachable() {
    let storage = ReplicaStorage::install().await;
    storage.reserve(8).await.expect("room in the pool");
    take_pending_wipes().await.expect("drain old wipes");
    let worker: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    let retry_wipe = PendingWipe::new(
        "r68-offline-retry-replica.sqlite",
        Some("invalid/content/namespace".to_owned()),
    );
    mark_wipe_pending(
        &retry_wipe,
        &connetto_web::auth::PendingWork::default(),
        false,
    )
    .await
    .expect("mark failing wipe");
    assert!(
        boot_db_worker::<String>(&config()).await.is_err(),
        "invalid content namespace must fail the boot"
    );
    assert_eq!(
        take_pending_wipes().await.expect("recover failed wipe"),
        vec![retry_wipe],
        "a failed deletion must remain pending for the next boot"
    );
    let namespace = "r68-offline-doomed-content";
    let hash = ChunkHash::from_bytes([0x68; 32]);
    BrowserStore::remove(&worker, namespace)
        .await
        .expect("clear content namespace");
    let store = BrowserStore::install(&worker, namespace)
        .await
        .expect("open content namespace");
    store
        .write_chunk(&hash, b"doomed content")
        .await
        .expect("write doomed content");
    drop(store);
    mark_wipe_pending(
        &PendingWipe::new(
            "r68-offline-doomed-replica.sqlite",
            Some(namespace.to_owned()),
        ),
        &connetto_web::auth::PendingWork::default(),
        false,
    )
    .await
    .expect("mark content wipe");

    // Returns rather than propagating. Before this phase the connect failure
    // came straight back out of here and the worker never existed.
    let booted = boot_db_worker::<String>(&config())
        .await
        .expect("the worker starts with no server reachable");
    let reopened = BrowserStore::install(&worker, namespace)
        .await
        .expect("reopen content namespace");
    assert!(
        !reopened.has_chunk(&hash).await.expect("probe old chunk"),
        "worker boot must remove the marked content namespace"
    );
    drop(reopened);
    BrowserStore::remove(&worker, namespace)
        .await
        .expect("remove test namespace");
    assert_eq!(
        booted.identity, None,
        "logins are off, so nobody was signed in, which is a separate axis from \
         whether a server answered"
    );
    assert_eq!(booted.session_expires_at, None);
    assert_eq!(booted.account, None);
    assert_eq!(booted.content_persistent, Some(false));
    let archive = request_export(ExportScope::Unsynced)
        .await
        .expect("content-aware worker export");
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive)).expect("archive");
    let has_content = zip.by_name("content/manifests.json").is_ok();
    assert!(has_content);
}
