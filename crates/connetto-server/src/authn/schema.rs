//! The structural contract the Postgres auth store writes its queries against.
//!
//! connetto owns no schema. A deployment declares its own `sessions` and
//! `provider_tokens` tables (see `docs/architecture/11-authentication.md`) and
//! implements [`ConnettoStoreSchema`] for them, either by hand or through the
//! [`connetto_auth_tables!`](crate::connetto_auth_tables) convenience macro.
//! [`DbAuthStore`](super::store::DbAuthStore) is generic over this trait and
//! keeps every query and security decision (identity resolution, refresh-token
//! rotation, reuse-is-theft, deadline capping); only the mechanical diesel
//! statements are built here, because the diesel `future` trait solver cannot
//! name them generically without diverging.
//!
//! Three shaping choices are forced by that solver, and all avoid the
//! `E0275 overflow ... ::Output == _` divergence:
//!
//! - All bounds live in one trait-level `where` clause plus a few
//!   associated-type bounds, so `S: ConnettoStoreSchema` is the only bound any
//!   store method or the `AuthStore` impl ever needs.
//! - The plain SELECTs run against a laundered query source
//!   ([`SessionsQuery`](ConnettoStoreSchema::SessionsQuery) /
//!   [`ProviderTokensQuery`](ConnettoStoreSchema::ProviderTokensQuery)): an
//!   associated type that is concretely the table but is not declared
//!   `Table`/`QueryRelation`, so filtering it does not route through the
//!   delegating blanket `impl<T: QueryRelation> FilterDsl for T` (whose `Output`
//!   never terminates for an opaque type). The WHERE predicate is likewise an
//!   opaque associated type ([`SessionPk`](ConnettoStoreSchema::SessionPk) /
//!   [`PtPk`](ConnettoStoreSchema::PtPk)), never a concrete `diesel::dsl::Eq`,
//!   which would make the solver race the blanket against the where-bound.
//! - The statements that need special SQL (the `FOR UPDATE` rotate read and the
//!   two UPDATEs) are laundered whole as opaque loadable/executable associated
//!   types the impl builds concretely, so their bounds collapse to a plain
//!   `LoadQuery` or `QueryFragment + QueryId + Send` and the unnameable
//!   `pub(crate)` lock/changeset internals never surface.

use connetto_core::SessionId;
use diesel::helper_types::{Filter, Limit, Select};
use diesel::insertable::CanInsertInSingleQuery;
use diesel::pg::Pg;
use diesel::prelude::*;
use diesel::query_builder::{
    IntoConflictValueClause, QueryFragment, QueryId, UndecoratedInsertRecord,
};
use diesel::query_dsl::methods::{FilterDsl, LimitDsl, SelectDsl};
use diesel::sql_types::{BigInt, Binary, Bool, Jsonb, Nullable, Text, Uuid};
use diesel::{Insertable, QuerySource};
use diesel_async::AsyncPgConnection;
use diesel_async::methods::LoadQuery as AsyncLoadQuery;

/// A column marker usable in the `WHERE`, `SET`, and `SELECT` clauses of table
/// `Tab`, carrying the fixed SQL type `St`. This is the shape every
/// `diesel::table!` column already has, restated so the store can name one
/// generically and construct it with `T::default()`.
pub trait StoreColumn<Tab, St>:
    Column<Table = Tab> + Expression<SqlType = St> + Default + Send
{
}

impl<C, Tab, St> StoreColumn<Tab, St> for C where
    C: Column<Table = Tab> + Expression<SqlType = St> + Default + Send
{
}

/// The tables, columns, and pre-built statements
/// [`DbAuthStore`](super::store::DbAuthStore) writes its queries against.
///
/// Every column and table member derives `Default` (as `diesel::table!` output
/// does), so the store constructs each marker with `T::default()` rather than an
/// accessor method. The `fn` members build the pieces that carry runtime data or
/// need special SQL.
pub trait ConnettoStoreSchema
where
    // shape 1: insert one session row
    Self::NewSession: Insertable<Self::Sessions>,
    <Self::NewSession as Insertable<Self::Sessions>>::Values: QueryFragment<Pg>
        + CanInsertInSingleQuery<Pg>
        + QueryId
        + Send
        + UndecoratedInsertRecord<Self::Sessions>,
    <Self::Sessions as QuerySource>::FromClause: QueryFragment<Pg> + Send,
    // shape 2: session liveness SELECT
    Self::SessionsQuery: FilterDsl<Self::SessionPk>,
    Filter<Self::SessionsQuery, Self::SessionPk>: SelectDsl<(Self::Revoked, Self::AbsoluteDeadlineMs)>,
    Select<Filter<Self::SessionsQuery, Self::SessionPk>, (Self::Revoked, Self::AbsoluteDeadlineMs)>:
        LimitDsl,
    for<'q> Limit<
        Select<Filter<Self::SessionsQuery, Self::SessionPk>, (Self::Revoked, Self::AbsoluteDeadlineMs)>,
    >: AsyncLoadQuery<'q, AsyncPgConnection, (bool, i64)> + Send,
    // shape 3 (the FOR UPDATE rotate read) is laundered whole as `SessionRow`.
    // shape 6: provider-token upsert
    Self::NewProviderToken: Insertable<Self::ProviderTokens>,
    <Self::NewProviderToken as Insertable<Self::ProviderTokens>>::Values:
        UndecoratedInsertRecord<Self::ProviderTokens> + IntoConflictValueClause,
    <<Self::NewProviderToken as Insertable<Self::ProviderTokens>>::Values as IntoConflictValueClause>::ValueClause:
        QueryFragment<Pg> + CanInsertInSingleQuery<Pg> + QueryId + Send,
    <Self::ProviderTokens as QuerySource>::FromClause: QueryFragment<Pg> + Send,
    // shape 7: provider-token SELECT
    Self::ProviderTokensQuery: FilterDsl<Self::PtPk>,
    Filter<Self::ProviderTokensQuery, Self::PtPk>:
        SelectDsl<(Self::PtIssuer, Self::PtAccessToken, Self::PtRefreshToken, Self::PtExpiresAtMs)>,
    Select<
        Filter<Self::ProviderTokensQuery, Self::PtPk>,
        (Self::PtIssuer, Self::PtAccessToken, Self::PtRefreshToken, Self::PtExpiresAtMs),
    >: LimitDsl,
    for<'q> Limit<
        Select<
            Filter<Self::ProviderTokensQuery, Self::PtPk>,
            (Self::PtIssuer, Self::PtAccessToken, Self::PtRefreshToken, Self::PtExpiresAtMs),
        >,
    >: AsyncLoadQuery<'q, AsyncPgConnection, (String, String, Option<String>, Option<i64>)> + Send,
{
    /// The developer's typed distributed user id, the `sessions.user_id` value.
    type Id: serde::Serialize
        + serde::de::DeserializeOwned
        + Clone
        + core::fmt::Display
        + Send
        + Sync
        + 'static;

    /// The sessions table, the `INSERT` target.
    type Sessions: Table + QueryId + Default + Send + 'static;
    /// The sessions table laundered as an opaque query source for plain SELECTs.
    type SessionsQuery: Default + Send;
    /// The whole opaque `SELECT (rotation columns) WHERE session_id = ? FOR
    /// UPDATE` read used by rotation. Laundered as one loadable value so the row
    /// lock composes without the generic `for_update` diverging.
    type SessionRow: for<'q> AsyncLoadQuery<
            'q,
            AsyncPgConnection,
            (Self::Id, serde_json::Value, Vec<u8>, i64, i64, bool),
        > + Send;

    /// `sessions.user_id`, typed as the developer's `Id` SQL type.
    type UserId: Expression + Default + Send;
    /// `sessions.attrs`, the opaque `AuthContext` blob (`Jsonb`).
    type Attrs: StoreColumn<Self::Sessions, Jsonb>;
    /// `sessions.current_refresh_hash` (`Binary`).
    type CurrentRefreshHash: StoreColumn<Self::Sessions, Binary>;
    /// `sessions.idle_deadline_ms` (`BigInt`).
    type IdleDeadlineMs: StoreColumn<Self::Sessions, BigInt>;
    /// `sessions.absolute_deadline_ms` (`BigInt`).
    type AbsoluteDeadlineMs: StoreColumn<Self::Sessions, BigInt>;
    /// `sessions.revoked` (`Bool`).
    type Revoked: StoreColumn<Self::Sessions, Bool>;
    /// The insertable new-sessions row.
    type NewSession: Send;
    /// The opaque `sessions.session_id = ?` predicate.
    type SessionPk: Send;
    /// The whole opaque `UPDATE sessions SET current_refresh_hash = ?,
    /// idle_deadline_ms = ? WHERE session_id = ?` statement.
    type RotationUpdate: QueryFragment<Pg> + QueryId + Send;
    /// The whole opaque `UPDATE sessions SET revoked = true WHERE session_id = ?`
    /// statement.
    type RevokeUpdate: QueryFragment<Pg> + QueryId + Send;

    /// Build the `sessions.session_id = ?` predicate.
    fn session_pk(session_id: SessionId) -> Self::SessionPk;
    /// Build the `SELECT ... WHERE session_id = ? FOR UPDATE` rotate read.
    fn session_row_for_update(session_id: SessionId) -> Self::SessionRow;
    /// Build the rotation UPDATE statement.
    fn rotation_update(
        session_id: SessionId,
        current_refresh_hash: Vec<u8>,
        idle_deadline_ms: i64,
    ) -> Self::RotationUpdate;
    /// Build the revoke UPDATE statement (`revoked = true`).
    fn revoke_update(session_id: SessionId) -> Self::RevokeUpdate;

    /// Build the insertable new-sessions row. The store cannot name a developer
    /// struct's fields, so it hands the column values here.
    #[allow(clippy::too_many_arguments)] // reason: mirrors the fixed sessions row shape
    fn new_session(
        session_id: SessionId,
        user_id: Self::Id,
        attrs: serde_json::Value,
        current_refresh_hash: Vec<u8>,
        idle_deadline_ms: i64,
        absolute_deadline_ms: i64,
        revoked: bool,
    ) -> Self::NewSession;

    /// The provider-tokens table, the `INSERT ... ON CONFLICT` target.
    type ProviderTokens: Table + QueryId + Default + Send + 'static;
    /// The provider-tokens table laundered as an opaque query source.
    type ProviderTokensQuery: Default + Send;
    /// `provider_tokens.session_id` (a native `uuid` primary key, the conflict
    /// target).
    type PtSessionId: StoreColumn<Self::ProviderTokens, Uuid>;
    /// `provider_tokens.issuer` (`Text`).
    type PtIssuer: StoreColumn<Self::ProviderTokens, Text>;
    /// `provider_tokens.access_token` (`Text`).
    type PtAccessToken: StoreColumn<Self::ProviderTokens, Text>;
    /// `provider_tokens.refresh_token` (`Nullable<Text>`).
    type PtRefreshToken: StoreColumn<Self::ProviderTokens, Nullable<Text>>;
    /// `provider_tokens.expires_at_ms` (`Nullable<BigInt>`).
    type PtExpiresAtMs: StoreColumn<Self::ProviderTokens, Nullable<BigInt>>;
    /// The insertable new-provider-token row.
    type NewProviderToken: Send;
    /// The opaque `provider_tokens.session_id = ?` predicate.
    type PtPk: Send;

    /// Build the `provider_tokens.session_id = ?` predicate, the conflict-target
    /// select filter.
    fn pt_pk(session_id: SessionId) -> Self::PtPk;

    /// Build the insertable new-provider-token row.
    fn new_provider_token(
        session_id: SessionId,
        issuer: String,
        access_token: String,
        refresh_token: Option<String>,
        expires_at_ms: Option<i64>,
    ) -> Self::NewProviderToken;
}

/// Generate the default connetto auth tables and their [`ConnettoStoreSchema`]
/// impl, parameterized by the developer's `Id` type and its diesel SQL type.
///
/// This is a convenience default only: the tables are the developer's to define
/// however they like, and [`ConnettoStoreSchema`] is the real contract,
/// implementable by hand against any tables. The reference SQL for these tables
/// is in `docs/architecture/11-authentication.md`.
///
/// Invoked at module scope, it emits the `connetto_sessions` and
/// `connetto_provider_tokens` `diesel::table!` modules, two insertable row
/// structs, and a unit struct `ConnettoAuthSchema` implementing the trait. The
/// caller needs `diesel` in scope.
///
/// ```ignore
/// connetto_server::connetto_auth_tables!(String, diesel::sql_types::Text);
/// let store = DbAuthStore::<ConnettoAuthSchema>::new(pool, lifetimes, resolver);
/// ```
#[macro_export]
macro_rules! connetto_auth_tables {
    ($id:ty, $id_sql:ty) => {
        diesel::table! {
            /// connetto sessions: connetto-minted session id, the developer's
            /// typed user id, the opaque `AuthContext` blob, the rotating
            /// refresh-secret hash, and the refresh deadlines.
            connetto_sessions (session_id) {
                session_id -> diesel::sql_types::Uuid,
                user_id -> $id_sql,
                attrs -> diesel::sql_types::Jsonb,
                current_refresh_hash -> diesel::sql_types::Binary,
                idle_deadline_ms -> diesel::sql_types::BigInt,
                absolute_deadline_ms -> diesel::sql_types::BigInt,
                revoked -> diesel::sql_types::Bool,
            }
        }

        diesel::table! {
            /// connetto retained provider tokens, keyed by session id.
            connetto_provider_tokens (session_id) {
                session_id -> diesel::sql_types::Uuid,
                issuer -> diesel::sql_types::Text,
                access_token -> diesel::sql_types::Text,
                refresh_token -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
                expires_at_ms -> diesel::sql_types::Nullable<diesel::sql_types::BigInt>,
            }
        }

        /// Insertable new-session row for [`ConnettoAuthSchema`].
        #[derive(diesel::Insertable)]
        #[diesel(table_name = connetto_sessions)]
        pub struct ConnettoNewSession {
            session_id: $crate::SessionId,
            user_id: $id,
            attrs: serde_json::Value,
            current_refresh_hash: Vec<u8>,
            idle_deadline_ms: i64,
            absolute_deadline_ms: i64,
            revoked: bool,
        }

        /// Insertable new-provider-token row for [`ConnettoAuthSchema`].
        #[derive(diesel::Insertable)]
        #[diesel(table_name = connetto_provider_tokens)]
        pub struct ConnettoNewProviderToken {
            session_id: $crate::SessionId,
            issuer: String,
            access_token: String,
            refresh_token: Option<String>,
            expires_at_ms: Option<i64>,
        }

        /// The default connetto auth schema over the developer's `Id` type.
        #[derive(Debug, Clone, Copy, Default)]
        pub struct ConnettoAuthSchema;

        impl $crate::authn::schema::ConnettoStoreSchema for ConnettoAuthSchema {
            type Id = $id;

            type Sessions = connetto_sessions::table;
            type SessionsQuery = connetto_sessions::table;
            type SessionRow = diesel::helper_types::ForUpdate<
                diesel::helper_types::Select<
                    diesel::helper_types::Filter<
                        connetto_sessions::table,
                        diesel::dsl::Eq<connetto_sessions::session_id, $crate::SessionId>,
                    >,
                    (
                        connetto_sessions::user_id,
                        connetto_sessions::attrs,
                        connetto_sessions::current_refresh_hash,
                        connetto_sessions::idle_deadline_ms,
                        connetto_sessions::absolute_deadline_ms,
                        connetto_sessions::revoked,
                    ),
                >,
            >;
            type UserId = connetto_sessions::user_id;
            type Attrs = connetto_sessions::attrs;
            type CurrentRefreshHash = connetto_sessions::current_refresh_hash;
            type IdleDeadlineMs = connetto_sessions::idle_deadline_ms;
            type AbsoluteDeadlineMs = connetto_sessions::absolute_deadline_ms;
            type Revoked = connetto_sessions::revoked;
            type NewSession = ConnettoNewSession;
            type SessionPk = diesel::dsl::Eq<connetto_sessions::session_id, $crate::SessionId>;
            type RotationUpdate = diesel::helper_types::Update<
                diesel::helper_types::Filter<
                    connetto_sessions::table,
                    diesel::dsl::Eq<connetto_sessions::session_id, $crate::SessionId>,
                >,
                (
                    diesel::dsl::Eq<connetto_sessions::current_refresh_hash, Vec<u8>>,
                    diesel::dsl::Eq<connetto_sessions::idle_deadline_ms, i64>,
                ),
            >;
            type RevokeUpdate = diesel::helper_types::Update<
                diesel::helper_types::Filter<
                    connetto_sessions::table,
                    diesel::dsl::Eq<connetto_sessions::session_id, $crate::SessionId>,
                >,
                diesel::dsl::Eq<connetto_sessions::revoked, bool>,
            >;

            fn session_pk(session_id: $crate::SessionId) -> Self::SessionPk {
                use diesel::ExpressionMethods as _;
                connetto_sessions::session_id.eq(session_id)
            }
            fn session_row_for_update(session_id: $crate::SessionId) -> Self::SessionRow {
                use diesel::{ExpressionMethods as _, QueryDsl as _};
                connetto_sessions::table
                    .filter(connetto_sessions::session_id.eq(session_id))
                    .select((
                        connetto_sessions::user_id,
                        connetto_sessions::attrs,
                        connetto_sessions::current_refresh_hash,
                        connetto_sessions::idle_deadline_ms,
                        connetto_sessions::absolute_deadline_ms,
                        connetto_sessions::revoked,
                    ))
                    .for_update()
            }
            fn rotation_update(
                session_id: $crate::SessionId,
                current_refresh_hash: Vec<u8>,
                idle_deadline_ms: i64,
            ) -> Self::RotationUpdate {
                use diesel::{ExpressionMethods as _, QueryDsl as _};
                diesel::update(
                    connetto_sessions::table.filter(connetto_sessions::session_id.eq(session_id)),
                )
                .set((
                    connetto_sessions::current_refresh_hash.eq(current_refresh_hash),
                    connetto_sessions::idle_deadline_ms.eq(idle_deadline_ms),
                ))
            }
            fn revoke_update(session_id: $crate::SessionId) -> Self::RevokeUpdate {
                use diesel::{ExpressionMethods as _, QueryDsl as _};
                diesel::update(
                    connetto_sessions::table.filter(connetto_sessions::session_id.eq(session_id)),
                )
                .set(connetto_sessions::revoked.eq(true))
            }

            fn new_session(
                session_id: $crate::SessionId,
                user_id: Self::Id,
                attrs: serde_json::Value,
                current_refresh_hash: Vec<u8>,
                idle_deadline_ms: i64,
                absolute_deadline_ms: i64,
                revoked: bool,
            ) -> Self::NewSession {
                ConnettoNewSession {
                    session_id,
                    user_id,
                    attrs,
                    current_refresh_hash,
                    idle_deadline_ms,
                    absolute_deadline_ms,
                    revoked,
                }
            }

            type ProviderTokens = connetto_provider_tokens::table;
            type ProviderTokensQuery = connetto_provider_tokens::table;
            type PtSessionId = connetto_provider_tokens::session_id;
            type PtIssuer = connetto_provider_tokens::issuer;
            type PtAccessToken = connetto_provider_tokens::access_token;
            type PtRefreshToken = connetto_provider_tokens::refresh_token;
            type PtExpiresAtMs = connetto_provider_tokens::expires_at_ms;
            type NewProviderToken = ConnettoNewProviderToken;
            type PtPk = diesel::dsl::Eq<connetto_provider_tokens::session_id, $crate::SessionId>;

            fn pt_pk(session_id: $crate::SessionId) -> Self::PtPk {
                use diesel::ExpressionMethods as _;
                connetto_provider_tokens::session_id.eq(session_id)
            }

            fn new_provider_token(
                session_id: $crate::SessionId,
                issuer: String,
                access_token: String,
                refresh_token: Option<String>,
                expires_at_ms: Option<i64>,
            ) -> Self::NewProviderToken {
                ConnettoNewProviderToken {
                    session_id,
                    issuer,
                    access_token,
                    refresh_token,
                    expires_at_ms,
                }
            }
        }
    };
}
