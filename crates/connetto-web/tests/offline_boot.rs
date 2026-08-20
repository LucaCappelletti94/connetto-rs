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

use connetto_web::storage::ReplicaStorage;
use connetto_web::workers::{DbWorkerConfig, boot_db_worker};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

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
        .with_auth_db_name("r20-offline-boot-auth.sqlite")
}

/// The worker comes up with nothing listening, and says so by completing.
#[wasm_bindgen_test]
async fn the_worker_starts_with_no_server_reachable() {
    let storage = ReplicaStorage::install().await;
    storage.reserve(8).await.expect("room in the pool");

    // Returns rather than propagating. Before this phase the connect failure
    // came straight back out of here and the worker never existed.
    let booted = boot_db_worker::<String>(&config())
        .await
        .expect("the worker starts with no server reachable");
    assert_eq!(
        booted.identity, None,
        "logins are off, so nobody was signed in, which is a separate axis from \
         whether a server answered"
    );
    assert_eq!(booted.session_expires_at, None);
    assert_eq!(booted.account, None);
}
