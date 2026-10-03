//! The deployment table types the reference server runs on.
//!
//! Each is the crate's default schema over `String` session ids, the
//! deployment id type the reference server and its deployment use.

use crate::{
    connetto_audit_table, connetto_auth_tables, connetto_ban_table, connetto_watermark_table,
};

connetto_auth_tables!(String, diesel::sql_types::Text);
connetto_watermark_table!(String);
connetto_audit_table!(
    String,
    diesel::sql_types::Text,
    uuid::Uuid,
    diesel::sql_types::Uuid,
);
connetto_ban_table!(String, diesel::sql_types::Text);
