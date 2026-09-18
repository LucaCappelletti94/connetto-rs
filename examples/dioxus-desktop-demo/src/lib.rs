//! Shared types and staging logic used by both the desktop application and
//! its integration test.

use connetto_file_client::FileId;
use diesel::prelude::*;
use rosetta_uuid::Uuid;

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        quantity -> diesel::sql_types::BigInt,
        created_at -> diesel::sql_types::Timestamp,
    }
}

diesel::table! {
    photos (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        order_id -> rosetta_uuid::sql_types::Uuid,
        content_id -> diesel::sql_types::Binary,
        content_state -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
    }
}

/// Queryable row from the `orders` table on the replica.
#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Order {
    pub id: Uuid,
    pub quantity: i64,
    pub created_at: chrono::NaiveDateTime,
}

/// Queryable row from the `photos` table on the replica.
#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = photos)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Photo {
    pub id: Uuid,
    pub order_id: Uuid,
    pub content_id: Vec<u8>,
    pub content_state: Option<String>,
}

/// Inserts a new orders row and a photos row referencing it in the same
/// transaction, using the file identity the content client assigned.
///
/// Called from both the desktop UI's pick handler and the integration test.
/// `created_at` is provided explicitly so the changeset carries a concrete
/// TIMESTAMPTZ value that Postgres accepts on replay; relying on the SQLite
/// DEFAULT would leave the column NULL in the changeset.
pub fn stage_photo_row(
    conn: &mut diesel::SqliteConnection,
    file_id: FileId,
) -> Result<(), diesel::result::Error> {
    let order_id = Uuid::new_v4();
    let photo_id = Uuid::new_v4();
    diesel::insert_into(orders::table)
        .values((
            orders::id.eq(order_id),
            orders::quantity.eq(1_i64),
            orders::created_at.eq(chrono::Utc::now().to_rfc3339()),
        ))
        .execute(conn)?;
    diesel::insert_into(photos::table)
        .values((
            photos::id.eq(photo_id),
            photos::order_id.eq(order_id),
            photos::content_id.eq(file_id.as_bytes().to_vec()),
        ))
        .execute(conn)?;
    Ok(())
}

/// MIME class inferred from a file path extension, or `None` for non-images.
pub fn mime_from_extension(path: &std::path::Path) -> Option<connetto_file_client::MimeClass> {
    use connetto_file_client::MimeClass;
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

/// First eight hex characters of a byte slice, for display.
pub fn short_hex(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// Decode the 32-byte `content_id` column to a `FileId`.
pub fn photo_file_id(content_id: &[u8]) -> Option<FileId> {
    <[u8; 32]>::try_from(content_id)
        .ok()
        .map(FileId::from_bytes)
}
