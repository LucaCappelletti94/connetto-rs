//! The structural contract for `auth_events`, the durable record of changes to
//! who can reach what.
//!
//! connetto owns no schema. A deployment declares the table (see
//! `docs/architecture/08-authorization.md`) and implements [`ConnettoAuditSchema`]
//! for it, by hand or through the
//! [`connetto_audit_table!`](crate::connetto_audit_table) convenience macro. The
//! same arrangement as [`ConnettoStoreSchema`](crate::authn::schema::ConnettoStoreSchema)
//! and [`ConnettoWatermarkSchema`](crate::watermark_schema::ConnettoWatermarkSchema).
//!
//! **This table holds state changes, never denials.** A caller probing keys
//! generates one refusal per attempt, so refusals go to structured logging and
//! would drown this table at exactly the moment it matters. What lands here is
//! the rare and durable: a login ended, a share key was issued, a ban was
//! imposed. The split is normative in `08-authorization.md` and
//! `denials_never_reach_the_audit_table` pins it.
//!
//! Only the insert is laundered as an associated type. The watermark's contract
//! carries five because it also reads and upserts; an audit row is written once
//! and never read back by connetto, so one suffices.

use connetto_core::SessionId;
use diesel::deserialize::{self, FromSql, FromSqlRow};
use diesel::expression::AsExpression;
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, IsNull, Output, ToSql};
use diesel_async::AsyncPgConnection;
use diesel_async::methods::ExecuteDsl;
use diesel_async::pooled_connection::bb8::Pool;
use std::io::Write as _;
use subql::backend::{Postgres, Value};

/// The Postgres enum type backing the `op` column.
///
/// A deployment creates it beside the table. Naming it here is what lets the
/// column bind as its own type rather than as text.
pub const AUTH_OP_TYPE: &str = "connetto_auth_op";

/// The Postgres enum type marker for [`AuthOp`].
#[derive(diesel::SqlType, diesel::query_builder::QueryId)]
#[diesel(postgres_type(name = "connetto_auth_op"))]
pub struct AuthOpSql;

/// What changed about who can reach what.
///
/// A closed set, so it is an enum on both sides: a value outside it is
/// unrepresentable in Rust and rejected by Postgres.
///
/// **A login ending is three values rather than one.** Collapsed, the table
/// cannot tell an ordinary logout from a stolen credential, which is the most
/// valuable thing it reports, and the cause is known at the moment the row is
/// written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsExpression, FromSqlRow)]
#[diesel(sql_type = AuthOpSql)]
pub enum AuthOp {
    /// The caller ended their own login through the logout endpoint.
    LoggedOut,
    /// The embedding application revoked the login itself.
    SessionRevoked,
    /// The theft defence saw a rotated-out refresh token presented and killed
    /// the login.
    TokenReplayed,
    /// A share key was issued over one row.
    CapabilityMinted,
    /// A permission changed. Produced by the grant-change watcher (R7).
    PermissionChange,
    /// The authorization model changed. Produced by R5b.
    ModelChange,
    /// An identity was banned, on crossing an abuse threshold.
    Banned,
    /// A ban was lifted through [`BanStore::lift`](crate::ban::BanStore::lift),
    /// which is the only thing that produces this. An expiry that merely lapses
    /// leaves its row behind and no record.
    BanLifted,
}

impl AuthOp {
    /// The label this value carries in Postgres, and the one the enum type
    /// declares.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::LoggedOut => "logged_out",
            Self::SessionRevoked => "session_revoked",
            Self::TokenReplayed => "token_replayed",
            Self::CapabilityMinted => "capability_minted",
            Self::PermissionChange => "permission_change",
            Self::ModelChange => "model_change",
            Self::Banned => "banned",
            Self::BanLifted => "ban_lifted",
        }
    }
}

impl ToSql<AuthOpSql, Pg> for AuthOp {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        out.write_all(self.label().as_bytes())?;
        Ok(IsNull::No)
    }
}

impl FromSql<AuthOpSql, Pg> for AuthOp {
    fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
        match bytes.as_bytes() {
            b"logged_out" => Ok(Self::LoggedOut),
            b"session_revoked" => Ok(Self::SessionRevoked),
            b"token_replayed" => Ok(Self::TokenReplayed),
            b"capability_minted" => Ok(Self::CapabilityMinted),
            b"permission_change" => Ok(Self::PermissionChange),
            b"model_change" => Ok(Self::ModelChange),
            b"banned" => Ok(Self::Banned),
            b"ban_lifted" => Ok(Self::BanLifted),
            other => Err(format!(
                "unrecognised connetto_auth_op label {:?}",
                String::from_utf8_lossy(other)
            )
            .into()),
        }
    }
}

/// One thing that changed about who can reach what.
///
/// `at` is not carried: the column defaults to `now()`, so the database clock
/// decides rather than whichever process happened to emit.
#[derive(Debug, Clone)]
pub struct AuthEvent<Id> {
    /// The session the change concerns. Always present, because every run has a
    /// handle whether or not anyone is logged in.
    pub session: SessionId,
    /// Who it concerns, absent when the caller has no identity.
    pub user_id: Option<Id>,
    /// What changed.
    pub op: AuthOp,
    /// The table a share key names, absent for everything else.
    pub table_name: Option<String>,
    /// The row a share key names, as the typed key values connetto observed on
    /// it, absent for everything else.
    ///
    /// **Not encoded here, deliberately.** connetto does not know what type the
    /// application stores a row key as, and it is not connetto's to decide: it
    /// is almost always a distributed id such as a UUID. So the values travel
    /// as they were read and
    /// [`ConnettoAuditSchema::row_key`] maps them to the column.
    pub pk: Option<Vec<Value<Postgres>>>,
}

impl<Id> AuthEvent<Id> {
    /// An event naming no row, which is every kind except a share mint.
    #[must_use]
    pub const fn new(session: SessionId, user_id: Option<Id>, op: AuthOp) -> Self {
        Self {
            session,
            user_id,
            op,
            table_name: None,
            pk: None,
        }
    }

    /// Name the row this event concerns.
    #[must_use]
    pub fn about_row(mut self, table_name: impl Into<String>, pk: Vec<Value<Postgres>>) -> Self {
        self.table_name = Some(table_name.into());
        self.pk = Some(pk);
        self
    }
}

/// The `auth_events` table and the pre-built insert connetto appends through.
///
/// Insert-only by design: connetto writes the history and never reads it, so
/// the application is free to index and query it however it likes.
pub trait ConnettoAuditSchema: Send + Sync + 'static {
    /// The deployment's typed distributed user id, the same one
    /// [`ConnettoStoreSchema`](crate::authn::schema::ConnettoStoreSchema)
    /// carries.
    type Id: Clone + core::fmt::Display + Send + Sync + 'static;

    /// The type this table stores a shared row's key as.
    ///
    /// The application's choice, like `Id` beside it, because connetto has no
    /// business deciding it: in practice it is a distributed id such as a UUID.
    /// An earlier version of this contract stored the key as `BYTEA` holding a
    /// `MessagePack` encoding of the values, which no policy could join against
    /// and no person could read, in a table whose neighbouring column is text
    /// precisely so a person can read it.
    type RowKey;

    /// The whole `INSERT INTO auth_events ...` statement, laundered as one
    /// executable value, because the diesel trait solver cannot name an insert
    /// statement type generically.
    type Insert: ExecuteDsl<AsyncPgConnection> + Send;

    /// Map the key values connetto read off the row to the stored type.
    ///
    /// `None` when the shape does not fit, which writes no key rather than a
    /// wrong one. connetto reads a row's key as a list of typed values and
    /// cannot know which of them the application keys on, so this is where that
    /// knowledge lives.
    fn row_key(values: &[Value<Postgres>]) -> Option<Self::RowKey>;

    /// Build the insert for one event.
    fn audit_insert(event: AuthEvent<Self::Id>) -> Self::Insert;
}

/// Records one change to who can reach what.
///
/// Fired synchronously by the producer, so an implementation that writes to a
/// database must move the write onto a spawned task rather than blocking the
/// caller. `08-authorization.md` requires audit writing to stay off the
/// synchronous hot path, and [`pg_audit_hook`] is the ready-made implementation
/// that obeys it. Same shape and same wiring point as
/// [`SessionRevocationHook`](crate::authn::service::SessionRevocationHook),
/// which is why it is a callback rather than the schema trait itself: the trait
/// carries an associated statement type and so cannot be a trait object.
pub type AuditHook<Id> = std::sync::Arc<dyn Fn(AuthEvent<Id>) + Send + Sync>;

/// An [`AuditHook`] that appends through `A` on the given pool.
///
/// The write is spawned, so the producer is never delayed by it, and a failure
/// is logged rather than propagated: losing an audit row must not fail the
/// logout, revocation or mint that produced it.
pub fn pg_audit_hook<A>(pool: Pool<AsyncPgConnection>) -> AuditHook<A::Id>
where
    A: ConnettoAuditSchema,
{
    std::sync::Arc::new(move |event: AuthEvent<A::Id>| {
        let pool = pool.clone();
        let op = event.op;
        tokio::spawn(async move {
            let mut conn = match pool.get().await {
                Ok(conn) => conn,
                Err(error) => {
                    tracing::warn!(%error, op = op.label(), "audit row dropped, no connection");
                    return;
                }
            };
            if let Err(error) = ExecuteDsl::execute(A::audit_insert(event), &mut conn).await {
                tracing::warn!(%error, op = op.label(), "audit row dropped, insert failed");
            }
        });
    })
}

/// Generate the default `auth_events` table and its [`ConnettoAuditSchema`]
/// impl, parameterized by the deployment's `Id` type and the type it stores a
/// shared row's key as, each with the diesel SQL type it maps to.
///
/// A convenience default only: the table is the deployment's to define however
/// it likes, and [`ConnettoAuditSchema`] is the real contract, implementable by
/// hand against any table. The reference SQL, including the
/// `connetto_auth_op` enum this depends on, is in
/// `docs/architecture/08-authorization.md`.
///
/// The default `row_key` accepts a single-column UUID key, which is what a
/// distributed id almost always is, and writes no key for anything else rather
/// than a wrong one. A composite or non-UUID key implements the trait by hand.
///
/// Invoked at module scope, it emits the `auth_events` `diesel::table!` module,
/// an insertable row struct, and a unit struct `ConnettoAudit` implementing the
/// trait. The caller needs `diesel` in scope.
///
/// ```ignore
/// connetto_server::connetto_audit_table!(
///     String, diesel::sql_types::Text,
///     uuid::Uuid, diesel::sql_types::Uuid,
/// );
/// // now `ConnettoAudit` implements `ConnettoAuditSchema`.
/// ```
#[macro_export]
macro_rules! connetto_audit_table {
    ($id:ty, $id_sql:ty, $pk:ty, $pk_sql:ty $(,)?) => {
        diesel::table! {
            /// The durable record of changes to who can reach what. Holds state
            /// changes only: denials go to structured logging.
            auth_events (at, session) {
                /// When it happened, defaulted by the column so one clock
                /// decides rather than whichever process emitted.
                at -> diesel::sql_types::Timestamptz,
                /// The session the change concerns, always present because every
                /// run has a handle whether or not anyone is logged in.
                session -> diesel::sql_types::Uuid,
                /// Who it concerns, absent when the caller has no identity.
                user_id -> diesel::sql_types::Nullable<$id_sql>,
                /// What changed, as a closed set both ends agree on.
                op -> $crate::audit::AuthOpSql,
                /// The table a share key names, absent for everything else.
                table_name -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
                /// The row a share key names, absent for everything else.
                pk -> diesel::sql_types::Nullable<$pk_sql>,
            }
        }

        /// Insertable audit row for [`ConnettoAudit`]. `at` is omitted so the
        /// column default decides, keeping one clock.
        #[derive(diesel::Insertable)]
        #[diesel(table_name = auth_events)]
        pub struct ConnettoNewAuthEvent {
            session: $crate::SessionId,
            user_id: Option<$id>,
            op: $crate::audit::AuthOp,
            table_name: Option<String>,
            pk: Option<$pk>,
        }

        /// The default connetto audit schema over the deployment's `Id` type.
        #[derive(Debug, Clone, Copy, Default)]
        pub struct ConnettoAudit;

        impl $crate::audit::ConnettoAuditSchema for ConnettoAudit {
            type Id = $id;
            type RowKey = $pk;
            type Insert = diesel::query_builder::InsertStatement<
                auth_events::table,
                <ConnettoNewAuthEvent as diesel::Insertable<auth_events::table>>::Values,
            >;

            fn row_key(
                values: &[subql::backend::Value<subql::backend::Postgres>],
            ) -> Option<Self::RowKey> {
                match values {
                    [subql::backend::Value::Uuid(id)] => Some(<$pk>::from(*id)),
                    _ => None,
                }
            }

            fn audit_insert(event: $crate::audit::AuthEvent<Self::Id>) -> Self::Insert {
                let pk = event.pk.as_deref().and_then(Self::row_key);
                diesel::insert_into(auth_events::table).values(ConnettoNewAuthEvent {
                    session: event.session,
                    user_id: event.user_id,
                    op: event.op,
                    table_name: event.table_name,
                    pk,
                })
            }
        }
    };
}
