//! One contract for every deployment-owned table connetto reads through a
//! trait (R98).
//!
//! [`ConnettoSchema`] names one member per table set, each tied to the same
//! `Id`, so a deployment that omits one does not compile and no two disagree
//! on the identity type. [`connetto_schema!`](crate::connetto_schema) emits
//! the default tables and the impl. A deployment with its own tables
//! implements the member traits by hand and names them here.
//!
//! ```
//! connetto_server::connetto_schema! {
//!     pub struct AppSchema;
//!     id: String => diesel::sql_types::Text,
//!     audit_row_key: uuid::Uuid => diesel::sql_types::Uuid,
//! }
//! ```
//!
//! A deployment with device identity maps its own descriptor type, defined
//! once where its client and its server both see it, onto the enrolment
//! table's columns:
//!
//! ```
//! #[derive(Clone, serde::Serialize, serde::Deserialize)]
//! pub struct AppDevice {
//!     pub name: String,
//!     pub model: Option<String>,
//! }
//!
//! connetto_server::connetto_schema! {
//!     pub struct AppSchema;
//!     id: String => diesel::sql_types::Text,
//!     audit_row_key: uuid::Uuid => diesel::sql_types::Uuid,
//!     device_descriptor: AppDevice {
//!         name: diesel::sql_types::Text,
//!         model: diesel::sql_types::Nullable<diesel::sql_types::Text>,
//!     },
//! }
//! ```
//!
//! A field list that disagrees with the type does not compile:
//!
//! ```compile_fail
//! #[derive(Clone, serde::Serialize, serde::Deserialize)]
//! pub struct AppDevice {
//!     pub name: String,
//! }
//!
//! connetto_server::connetto_schema! {
//!     pub struct AppSchema;
//!     id: String => diesel::sql_types::Text,
//!     audit_row_key: uuid::Uuid => diesel::sql_types::Uuid,
//!     device_descriptor: AppDevice { nickname: diesel::sql_types::Text },
//! }
//! ```
//!
//! Every member must be named, so a schema missing one is refused:
//!
//! ```compile_fail
//! use connetto_server::defaults::{
//!     ConnettoAudit, ConnettoAuthSchema, ConnettoEnrolments, ConnettoWatermark,
//! };
//!
//! struct NoBans;
//!
//! impl connetto_server::schema::ConnettoSchema for NoBans {
//!     type Id = String;
//!     type Auth = ConnettoAuthSchema;
//!     type Watermark = ConnettoWatermark;
//!     type Audit = ConnettoAudit;
//!     type Enrolments = ConnettoEnrolments;
//! #   #[cfg(feature = "content")]
//! #   type Files = connetto_file_server::DefaultFileSchema;
//! }
//! ```
//!
//! Naming it compiles:
//!
//! ```
//! use connetto_server::defaults::{
//!     ConnettoAudit, ConnettoAuthSchema, ConnettoBans, ConnettoEnrolments, ConnettoWatermark,
//! };
//!
//! struct Complete;
//!
//! impl connetto_server::schema::ConnettoSchema for Complete {
//!     type Id = String;
//!     type Auth = ConnettoAuthSchema;
//!     type Watermark = ConnettoWatermark;
//!     type Audit = ConnettoAudit;
//!     type Bans = ConnettoBans;
//!     type Enrolments = ConnettoEnrolments;
//! #   #[cfg(feature = "content")]
//! #   type Files = connetto_file_server::DefaultFileSchema;
//! }
//! ```

use crate::audit::ConnettoAuditSchema;
use crate::authn::ConnettoStoreSchema;
use crate::ban::ConnettoBanSchema;
use crate::device_cert::ConnettoEnrolmentSchema;
use crate::watermark_schema::ConnettoWatermarkSchema;

/// Every deployment-owned table set connetto reads through a trait, under one
/// identity type.
pub trait ConnettoSchema: Send + Sync + 'static {
    /// The deployment's typed user id, the one every member carries.
    type Id: serde::Serialize
        + serde::de::DeserializeOwned
        + Clone
        + core::fmt::Display
        + Send
        + Sync
        + 'static;
    /// The login sessions and provider tokens.
    type Auth: ConnettoStoreSchema<Id = Self::Id>;
    /// The exactly-once watermark.
    type Watermark: ConnettoWatermarkSchema<Id = Self::Id>;
    /// The audit log of access changes.
    type Audit: ConnettoAuditSchema<Id = Self::Id>;
    /// The ban list.
    type Bans: ConnettoBanSchema<Id = Self::Id>;
    /// The device enrolments, their certificates and the revocation-list
    /// numbers (R74).
    type Enrolments: ConnettoEnrolmentSchema<Id = Self::Id>;
    /// The file server's manifests and chunk registry.
    #[cfg(feature = "content")]
    type Files: connetto_file_server::ConnettoFileSchema;
}

/// The default tables of every member and a unit struct `$name` naming them
/// as a [`ConnettoSchema`], over the identity `id` and the audit log's row key
/// `audit_row_key`, each with its SQL type, and optionally the application's
/// device descriptor with each field's SQL type.
///
/// Invoked at module scope with `diesel` and `diesel_async` in scope. The
/// member structs it emits are `ConnettoAuthSchema`, `ConnettoWatermark`,
/// `ConnettoAudit`, `ConnettoBans` and `ConnettoEnrolments`, and the file
/// member is the file server's `_cfs_` tables. The descriptor is the
/// application's own type, destructured field by field, so a field list that
/// disagrees with it does not compile, and without one it is `()`.
#[macro_export]
macro_rules! connetto_schema {
    (
        $vis:vis struct $name:ident;
        id: $id:ty => $id_sql:ty,
        audit_row_key: $pk:ty => $pk_sql:ty
        $(, device_descriptor: $($desc:ident)::+ { $($field:ident : $field_sql:ty),* $(,)? })? $(,)?
    ) => {
        $crate::connetto_auth_tables!($id, $id_sql);
        $crate::connetto_watermark_table!($id);
        $crate::connetto_audit_table!($id, $id_sql, $pk, $pk_sql);
        $crate::connetto_ban_table!($id, $id_sql);
        $crate::connetto_enrolment_tables!($id, $id_sql; $($($desc)::+ { $($field : $field_sql),* })?);

        /// The deployment's tables, every member named.
        #[derive(Debug, Clone, Copy, Default)]
        $vis struct $name;

        impl $crate::schema::ConnettoSchema for $name {
            type Id = $id;
            type Auth = ConnettoAuthSchema;
            type Watermark = ConnettoWatermark;
            type Audit = ConnettoAudit;
            type Bans = ConnettoBans;
            type Enrolments = ConnettoEnrolments;
            $crate::__connetto_schema_files!();
        }
    };
}

/// The file member of [`connetto_schema!`], present when this crate serves files.
#[cfg(feature = "content")]
#[doc(hidden)]
#[macro_export]
macro_rules! __connetto_schema_files {
    () => {
        type Files = $crate::__files::DefaultFileSchema;
    };
}

/// The file member of [`connetto_schema!`], absent when this crate serves no files.
#[cfg(not(feature = "content"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __connetto_schema_files {
    () => {};
}
