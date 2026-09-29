//! Browser test worker entry points for the dioxus web demo photo surface.

use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

include!(concat!(env!("OUT_DIR"), "/connetto-schema.rs"));

pub use connetto_demo_deployment::{AUTH_BASE, DEMO_WS_URL, auth_landing};

pub const DEMO_QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
pub const PHOTO_QUERY: &str = "SELECT * FROM photos";

// Each test gets unique OPFS filenames so Chrome's delayed handle release after
// Worker.terminate() never blocks the next worker's file open.
const ALIGN_DB_PREFIX: &str = "connetto-dioxus-align";
const ALIGN_HUB_META: &str = "connetto-dioxus-align-hub-meta.sqlite";
const ALIGN_AUTH_DB: &str = "connetto-dioxus-align-auth.sqlite";

const PHOTO_DB_PREFIX: &str = "connetto-dioxus-photo";
const PHOTO_HUB_META: &str = "connetto-dioxus-photo-hub-meta.sqlite";
const PHOTO_AUTH_DB: &str = "connetto-dioxus-photo-auth.sqlite";

/// The one sync schema the worker and every tab build from.
#[must_use]
pub fn demo_schema() -> connetto_client::SyncSchema {
    connetto_client::SyncSchema::new(connetto_schema_bundle::bundle())
}

/// Worker entry point for the alignment test; uses `connetto-dioxus-align*` OPFS files.
///
/// # Errors
///
/// A string describing the VFS, upstream connect, or subscribe failure.
#[wasm_bindgen]
pub async fn db_worker_boot_align() -> Result<(), JsValue> {
    boot_with(ALIGN_DB_PREFIX, ALIGN_HUB_META, ALIGN_AUTH_DB).await
}

/// Worker entry point for the photo test; uses `connetto-dioxus-photo*` OPFS files.
///
/// # Errors
///
/// A string describing the VFS, upstream connect, or subscribe failure.
#[wasm_bindgen]
pub async fn db_worker_photo_boot() -> Result<(), JsValue> {
    boot_with(PHOTO_DB_PREFIX, PHOTO_HUB_META, PHOTO_AUTH_DB).await
}

async fn boot_with(
    db_prefix: &'static str,
    hub_meta: &'static str,
    auth_db: &'static str,
) -> Result<(), JsValue> {
    connetto_web::logging::init_console();
    connetto_web::builder::WebClientBuilder::new(DEMO_WS_URL, demo_schema())
        .with_hub_meta_name(hub_meta)
        .with_upstream("db-upstream", DEMO_QUERY)
        .with_upstream("db-photos-upstream", PHOTO_QUERY)
        .with_content_namespace("connetto-photo-content")
        .with_content_heal_lost(
            "SELECT content_id FROM photos WHERE content_state = 'lost'",
            "content_id",
        )
        .signed_in(connetto_client::Auth::new(AUTH_BASE, "dev-idp"))
        .with_redirect_uri(auth_landing())
        .with_auth_db_name(auth_db)
        .durable(db_prefix)
        .with_gate(connetto_client::Gate::off())
        .boot::<String>()
        .await
        .map(drop)
        .map_err(JsValue::from)
}
