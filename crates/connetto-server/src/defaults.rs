//! The deployment table types the reference server runs on.
//!
//! Each is the crate's default schema over `String` session ids, the
//! deployment id type the reference server and its deployment use.

crate::connetto_schema! {
    pub struct ConnettoDefaults;
    id: String => diesel::sql_types::Text,
    audit_row_key: uuid::Uuid => diesel::sql_types::Uuid,
}
