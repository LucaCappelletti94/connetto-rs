//! The one demo's schema rows and shared helpers, on the deployment schema,
//! plus the browser test worker entry points the `photo_flow` suite drives.

use connetto_client::{ClientEvent, SyncSchema};
use connetto_core::messages::{FatalErrorReason, FullResyncReason, SyncStatus};
use connetto_file_core::{FileId, MimeClass};
use diesel::prelude::*;
use rosetta_uuid::Uuid;

include!(concat!(env!("OUT_DIR"), "/connetto-schema.rs"));

pub use connetto_demo_deployment::{AUTH_BASE, DEMO_WS_URL, auth_landing};

pub mod platform;
pub mod ui;

/// The one orders subscription every window drives, the visible rows only.
pub const DEMO_QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
/// The extra upstream subscription for the photos rows.
pub const PHOTO_QUERY: &str = "SELECT * FROM photos";

// The synced tier, as the deployment schema translates it to the replica.
diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        owner_id -> diesel::sql_types::Text,
        quantity -> diesel::sql_types::BigInt,
        created_at -> diesel::sql_types::Timestamp,
    }
}

// The device-private tier, translated from this demo's `frontend.sql`.
diesel::table! {
    notes (id) {
        id -> diesel::sql_types::BigInt,
        body -> diesel::sql_types::Text,
    }
}

diesel::table! {
    photos (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        order_id -> rosetta_uuid::sql_types::Uuid,
        owner_id -> diesel::sql_types::Text,
        content_id -> diesel::sql_types::Binary,
        content_state -> Nullable<diesel::sql_types::Text>,
    }
}

/// One row of the synced `orders` table.
#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Order {
    pub id: Uuid,
    pub owner_id: String,
    pub quantity: i64,
    pub created_at: chrono::NaiveDateTime,
}

/// One row of the device-private `notes` table.
#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Note {
    pub id: i64,
    pub body: String,
}

/// One row of the synced `photos` table.
#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = photos)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Photo {
    pub id: Uuid,
    pub order_id: Uuid,
    pub owner_id: String,
    pub content_id: Vec<u8>,
    pub content_state: Option<String>,
}

/// The one sync schema the worker, every tab and every device build from.
#[must_use]
pub fn demo_schema() -> SyncSchema {
    SyncSchema::new(connetto_schema_bundle::bundle())
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
                    "mutation {client_seq} conflicted, server holds {}",
                    row.row_json
                )
            },
        )),
        // The reconnect policy uses a fixed backoff and never reads retry_after_ms,
        // so this value is informational only.
        ClientEvent::RateLimited { retry_after_ms, .. } => Some(format!(
            "rate limited: server asks {retry_after_ms}ms before retrying \
             (client reconnects on its own fixed schedule)"
        )),
        ClientEvent::ServerClosed {
            reason: FatalErrorReason::RateLimited { retry_after_ms },
        } => Some(format!(
            "connection closed: rate limit exceeded (server suggests {retry_after_ms}ms wait)"
        )),
        ClientEvent::ServerClosed { reason } => {
            Some(format!("server closed the connection: {reason:?}"))
        }
        ClientEvent::Stopped { detail } => Some(format!("the client stopped: {detail}")),
        ClientEvent::Closed => Some("connection closed".to_owned()),
        ClientEvent::AuthenticationRequired => {
            Some("session expired, sign out and sign in again".to_owned())
        }
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

/// A device-unique integer id for a local-only `notes` row. `notes` stays on
/// integer keys (device-private, never synced), so the client authors the id.
/// The id is the millisecond clock above 21 random bits, so notes list in the
/// order they were written and two writers of one device saving in the same
/// millisecond collide about once in two million.
#[must_use]
#[cfg(target_arch = "wasm32")]
pub fn fresh_note_id() -> i64 {
    let span = f64::from(1u32 << 21);
    let now = js_sys::Date::now();
    debug_assert!(now.is_finite() && (0.0..span * span).contains(&now));
    // Deliberate truncation: whole milliseconds, below 2^42 until 2109.
    let millis = now as i64;
    let r = js_sys::Math::random() * span;
    debug_assert!(r.is_finite() && (0.0..span).contains(&r));
    // Deliberate quantization: [0.0, 2^21) -> [0, 2^21 - 1].
    (millis << 21) | r as i64
}

#[must_use]
#[cfg(not(target_arch = "wasm32"))]
pub fn fresh_note_id() -> i64 {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let millis = i64::try_from(millis).unwrap_or(0);
    debug_assert!(millis < 1 << 42, "the shifted clock would overflow an i64");
    let bytes: [u8; 16] = Uuid::new_v4().into();
    // The low 11 bits of a random v4 are version and variant bits, so the tag
    // is 21 bits: a deliberate bit-width reduction, not a cast of the value.
    let tag = u32::from_le_bytes(bytes[0..4].try_into().expect("four bytes")) >> 11;
    (millis << 21) | i64::from(tag)
}

/// The replica's physical footprint, read straight off it: total pages and
/// the free pages a trim can reclaim.
pub async fn replica_footprint<T>(client: &connetto_client::ConnettoClient<T>) -> (i64, i64)
where
    T: connetto_core::traits::Transport + connetto_core::traits::MaybeSend + 'static,
    T::Error: core::fmt::Display,
{
    client
        .with_conn(|conn| {
            let db = conn.conn();
            let pages = db.page_count(None).unwrap_or(0);
            let free = db.freelist_count(None).unwrap_or(0);
            (pages, free)
        })
        .await
        .unwrap_or((0, 0))
}

/// The part of an id before its first `-`, or the whole string when it has
/// none, so a UUID on screen shows its first segment and the full value in
/// its title tooltip.
#[must_use]
pub fn short_id(id: &str) -> &str {
    id.split('-').next().unwrap_or(id)
}

/// First eight hex characters of a byte slice, for display.
#[must_use]
pub fn short_hex(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// MIME class inferred from a file path extension, or `None` for non-images.
#[must_use]
pub fn mime_from_extension(path: &std::path::Path) -> Option<MimeClass> {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .as_deref()
    {
        Some("jpg" | "jpeg") => Some(MimeClass::Jpeg),
        Some("png") => Some(MimeClass::Png),
        _ => None,
    }
}

/// Decode the 32-byte `content_id` column to a `FileId`.
#[must_use]
pub fn photo_file_id(content_id: &[u8]) -> Option<FileId> {
    <[u8; 32]>::try_from(content_id)
        .ok()
        .map(FileId::from_bytes)
}

/// The quantity a new demo order names, 5 to 50, so a couple of clicks on
/// the same millisecond still add different rows to the visible sum.
#[must_use]
pub fn fresh_quantity() -> i64 {
    let millis = current_millis();
    ((millis % 9 + 1) * 5) as i64
}

/// The epoch milliseconds now. A browser has no standard-library clock, so
/// the web build reads the JavaScript clock; the native builds read std.
fn current_millis() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        let v = js_sys::Date::now();
        // `u64::MAX as f64` rounds up to 2^64, so anything below it converts.
        if v.is_finite() && v >= 0.0 && v < u64::MAX as f64 {
            v as u64
        } else {
            0
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64)
    }
}

/// The label the account bar shows for a stored credential key: the
/// decoded identity, or the raw key when the secret is not a decodable one.
#[must_use]
pub fn account_label(key: &str) -> String {
    connetto_client::decode_identity::<String>(key).unwrap_or_else(|_| key.to_owned())
}

/// Inserts a new orders row and a photos row referencing it in the same
/// transaction, using the file identity the content client assigned, and
/// answers with the photo id. The inserts name their `id` and `owner_id` and
/// omit `created_at`, which the orders table's `now()` default mints; the
/// photos row has no such column.
///
/// Called from the pick handler on every platform and from the integration
/// test.
pub fn stage_photo_row(
    conn: &mut diesel::SqliteConnection,
    file_id: FileId,
    owner_id: &str,
) -> Result<Uuid, diesel::result::Error> {
    conn.transaction(|conn| {
        let order_id = Uuid::new_v4();
        let photo_id = Uuid::new_v4();
        diesel::insert_into(orders::table)
            .values((
                orders::id.eq(order_id),
                orders::owner_id.eq(owner_id),
                orders::quantity.eq(1_i64),
            ))
            .execute(conn)?;
        diesel::insert_into(photos::table)
            .values((
                photos::id.eq(photo_id),
                photos::order_id.eq(order_id),
                photos::owner_id.eq(owner_id),
                photos::content_id.eq(file_id.as_bytes().to_vec()),
            ))
            .execute(conn)?;
        Ok(photo_id)
    })
}

// --- Browser test worker entry points --------------------------------------
//
// The photo_flow suite spawns a dedicated worker pointed at the app's glue
// module, which auto-runs `main` in a worker context and then calls one of
// these. Each uses unique OPFS filenames so Chrome's delayed handle release
// after `Worker.terminate()` never blocks the next worker's file open.
#[cfg(target_arch = "wasm32")]
mod worker_tests {
    use wasm_bindgen::JsValue;
    use wasm_bindgen::prelude::wasm_bindgen;

    // Per-test OPFS filenames, the isolation guarantee the suite relies on.
    const ALIGN_DB_PREFIX: &str = "connetto-dioxus-align";
    const ALIGN_AUTH_DB: &str = "connetto-dioxus-align-auth.sqlite";

    const PHOTO_DB_PREFIX: &str = "connetto-dioxus-photo";
    const PHOTO_AUTH_DB: &str = "connetto-dioxus-photo-auth.sqlite";

    /// Worker entry point for the alignment test.
    ///
    /// # Errors
    ///
    /// A string describing the VFS, upstream connect, or subscribe failure.
    #[wasm_bindgen]
    pub async fn db_worker_boot_align() -> Result<(), JsValue> {
        boot_with(ALIGN_DB_PREFIX, ALIGN_AUTH_DB).await
    }

    /// Worker entry point for the photo test.
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
        connetto_web::builder::WebClientBuilder::new(crate::DEMO_WS_URL, crate::demo_schema())
            .with_upstream("db-upstream", crate::DEMO_QUERY)
            .with_upstream("db-photos-upstream", crate::PHOTO_QUERY)
            .with_content_namespace("connetto-photo-content")
            .with_content_heal_lost(
                "SELECT content_id FROM photos WHERE content_state = 'lost'",
                "content_id",
            )
            .signed_in(connetto_client::Auth::new(crate::AUTH_BASE, "dev-idp"))
            .with_redirect_uri(crate::auth_landing())
            .with_auth_db_name(auth_db)
            .durable(db_prefix)
            .with_gate(connetto_client::Gate::off())
            .boot::<String>()
            .await
            .map(drop)
            .map_err(JsValue::from)
    }
}

#[cfg(target_arch = "wasm32")]
pub use worker_tests::{db_worker_boot_align, db_worker_photo_boot};
