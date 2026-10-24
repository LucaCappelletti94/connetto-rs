//! Browser test worker entry points for the yew web demo photo surface,
//! plus the status-line wording the window's event loop and the tests share.

use connetto_client::ClientEvent;
use connetto_core::messages::{FatalErrorReason, FullResyncReason, SyncStatus};
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

include!(concat!(env!("OUT_DIR"), "/connetto-schema.rs"));

pub use connetto_demo_deployment::{AUTH_BASE, DEMO_WS_URL, auth_landing};

pub const DEMO_QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
pub const PHOTO_QUERY: &str = "SELECT * FROM photos";

/// The first dash-separated segment of an id, the compact form the screen
/// shows. The whole string when it carries no dash.
#[must_use]
pub fn short_id(id: &str) -> &str {
    id.split_once('-').map(|(head, _)| head).unwrap_or(id)
}

// Distinct names separate test records within the shared pool.
const ALIGN_DB_PREFIX: &str = "connetto-yew-align";
const ALIGN_AUTH_DB: &str = "connetto-yew-align-auth.sqlite";

const PHOTO_DB_PREFIX: &str = "connetto-yew-photo";
const PHOTO_AUTH_DB: &str = "connetto-yew-photo-auth.sqlite";

/// The one sync schema the worker and every tab build from.
#[must_use]
pub fn demo_schema() -> connetto_client::SyncSchema {
    connetto_client::SyncSchema::new(connetto_schema_bundle::bundle())
}

/// A short status line word for one client event, or `None` to ignore it.
///
/// The window's event loop and the tests share this, so the wording the
/// screen shows is the wording the tests pin.
#[must_use]
pub fn status_label(event: &ClientEvent) -> Option<String> {
    match event {
        ClientEvent::Reconnecting { attempt } => Some(format!("reconnecting (attempt {attempt})")),
        ClientEvent::Reconnected => Some("reconnected".to_owned()),
        ClientEvent::SyncStatus(status) => Some(match status {
            SyncStatus::Connected => "online".to_owned(),
            SyncStatus::Offline => "offline".to_owned(),
        }),
        ClientEvent::NonFatal { related_to, detail } => Some(match related_to {
            Some(id) => format!("non-fatal on {id}: {detail}"),
            None => format!("non-fatal: {detail}"),
        }),
        ClientEvent::FullResync { sub_id, reason } => {
            Some(format!("{sub_id}: full resync, {}", resync_reason(reason)))
        }
        ClientEvent::MutationApplied { client_seq } => {
            Some(format!("mutation {client_seq} applied"))
        }
        ClientEvent::MutationRejected {
            client_seq, reason, ..
        } => Some(format!("mutation {client_seq} rejected: {reason}")),
        ClientEvent::MutationConflict {
            client_seq,
            server_row,
            ..
        } => Some(server_row.as_ref().map_or_else(
            || format!("mutation {client_seq} conflicted, the server row is gone"),
            |row| {
                format!(
                    "mutation {client_seq} conflicted, the server holds {}",
                    row.row_json
                )
            },
        )),
        // The reconnect policy uses a fixed backoff and never reads retry_after_ms,
        // so this value is informational only.
        ClientEvent::RateLimited {
            related_to: _,
            retry_after_ms,
        } => Some(format!(
            "rate-limited by server: retry after {retry_after_ms} ms"
        )),
        ClientEvent::ServerClosed {
            reason: FatalErrorReason::RateLimited { retry_after_ms },
        } => Some(format!(
            "connection closed: server rate-limited this client (retry after {retry_after_ms} ms)"
        )),
        ClientEvent::ServerClosed { reason } => {
            Some(format!("server closed the session: {reason:?}"))
        }
        ClientEvent::Stopped { detail } => Some(format!("the client stopped: {detail}")),
        ClientEvent::Closed => Some("connection closed".to_owned()),
        _ => None,
    }
}

/// The human-readable form of why a subscription's rows were replaced
/// wholesale.
fn resync_reason(reason: &FullResyncReason) -> String {
    match reason {
        FullResyncReason::CursorOutsideRetention => {
            "the cursor left the retention window".to_owned()
        }
        FullResyncReason::AuthorizationChange => "a grant moved".to_owned(),
        FullResyncReason::TableTruncated { table } => {
            format!("table {table} was emptied")
        }
        FullResyncReason::SnapshotInterrupted => {
            "the snapshot read failed part way through".to_owned()
        }
        FullResyncReason::CursorBeyondHistory => {
            "the cursor is past the retained history".to_owned()
        }
    }
}

/// Worker entry point for the alignment test; uses `connetto-yew-align*` OPFS files.
///
/// # Errors
///
/// A string describing the VFS, upstream connect, or subscribe failure.
#[wasm_bindgen]
pub async fn db_worker_boot_align() -> Result<(), JsValue> {
    boot_with(ALIGN_DB_PREFIX, ALIGN_AUTH_DB).await
}

/// Worker entry point for the photo test; uses `connetto-yew-photo*` OPFS files.
///
/// # Errors
///
/// A string describing the VFS, upstream connect, or subscribe failure.
#[wasm_bindgen]
pub async fn db_worker_photo_boot() -> Result<(), JsValue> {
    boot_with(PHOTO_DB_PREFIX, PHOTO_AUTH_DB).await
}

async fn boot_with(db_prefix: &'static str, auth_db: &'static str) -> Result<(), JsValue> {
    connetto_web::logging::init_console();
    connetto_web::builder::WebClientBuilder::new(DEMO_WS_URL, demo_schema())
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
