//! The structural contract for `connetto_bans`, the identities a deployment is
//! currently refusing.
//!
//! connetto owns no schema. A deployment declares the table and implements
//! [`ConnettoBanSchema`] for it, by hand or through the
//! [`connetto_ban_table!`](crate::connetto_ban_table) convenience macro, the
//! same arrangement as [`ConnettoStoreSchema`](crate::authn::ConnettoStoreSchema),
//! [`ConnettoWatermarkSchema`](crate::watermark_schema::ConnettoWatermarkSchema)
//! and [`ConnettoAuditSchema`](crate::audit::ConnettoAuditSchema).
//!
//! Current state, not history. One row per banned identity, replaced when a
//! later crossing bans the same person again. The append-only record of every
//! impose and lift is `auth_events`, which is why an expiry that merely lapses
//! leaves no trace here or there.
//!
//! **A ban has no sweeper.** An expiry that passes stops matching
//! [`Ban::applies_at`] immediately, declaratively, with nothing running, and its
//! row stays until [`BanStore::lift`] clears it. A deployment wanting rows
//! cleared promptly schedules its own task calling the lift, which puts the
//! scheduling where scheduling is easy and works identically on one server or
//! ten. A sweeper inside connetto was rejected because a deployment may run
//! several servers over replicated databases, so each would sweep the same rows
//! and race.
//!
//! ```sql
//! CREATE TABLE connetto_bans (
//!     user_id    <IdSqlType> PRIMARY KEY,
//!     session    UUID NOT NULL,
//!     reason     TEXT NOT NULL,
//!     banned_at  TIMESTAMPTZ NOT NULL,
//!     expires_at TIMESTAMPTZ
//! );
//! ```
//!
//! `banned_at` carries no column default, unlike `auth_events.at`, because
//! connetto computes `expires_at` from a duration and the two have to come from
//! one clock or the recorded span is a lie. `session` is the run the crossing
//! happened on, kept because `auth_events.session` is `NOT NULL` and a lift
//! performed months later has no run of its own to name.

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use connetto_core::SessionId;
use diesel::OptionalExtension as _;
use diesel::helper_types::{Filter, Limit, Select};
use diesel::query_dsl::methods::{FilterDsl, LimitDsl, SelectDsl};
use diesel::sql_types::{Nullable, Text, Timestamptz, Uuid};
use diesel_async::methods::{ExecuteDsl, LoadQuery as AsyncLoadQuery};
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl as _};

pub use crate::authn::schema::Instant;

/// A ban as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ban {
    /// The run the crossing happened on.
    pub session: SessionId,
    /// Which threshold the caller crossed, as connetto recorded it.
    pub reason: String,
    /// When the ban started.
    pub banned_at: Instant,
    /// When it lapses. Absent is permanent.
    pub expires_at: Option<Instant>,
}

impl Ban {
    /// Whether this ban still refuses the caller at `now`.
    #[must_use]
    pub fn applies_at(&self, now: Instant) -> bool {
        self.expires_at.is_none_or(|expiry| expiry > now)
    }
}

/// A ban about to be written.
#[derive(Debug, Clone)]
pub struct NewBan<Id> {
    /// Who is banned.
    pub user_id: Id,
    /// The run the crossing happened on.
    pub session: SessionId,
    /// Which threshold they crossed.
    pub reason: String,
    /// When the ban starts.
    pub banned_at: Instant,
    /// When it lapses. Absent is permanent.
    pub expires_at: Option<Instant>,
}

impl<Id> NewBan<Id> {
    /// A ban starting now, lasting `ttl` or forever when absent.
    ///
    /// A `ttl` too large for a timestamp is taken as permanent, since asking for
    /// longer than the calendar means forever.
    #[must_use]
    pub fn starting_now(
        user_id: Id,
        session: SessionId,
        reason: impl Into<String>,
        ttl: Option<Duration>,
    ) -> Self {
        let banned_at = chrono::Utc::now();
        let expires_at = ttl.and_then(|ttl| {
            chrono::TimeDelta::from_std(ttl)
                .ok()
                .and_then(|delta| banned_at.checked_add_signed(delta))
        });
        Self {
            user_id,
            session,
            reason: reason.into(),
            banned_at,
            expires_at,
        }
    }
}

/// The ban list could not be reached.
///
/// Every read of it fails closed: a ban must never lapse because a table was
/// briefly unreadable, and the handshake already cannot complete without the
/// database, so this adds no outage surface that is not there already.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct BanError(String);

impl BanError {
    /// Name a failure.
    #[must_use]
    pub fn new(detail: impl core::fmt::Display) -> Self {
        Self(detail.to_string())
    }

    /// What went wrong.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.0
    }
}

/// The answer to one ban-list operation.
pub type BanFuture<'a, T> =
    core::pin::Pin<Box<dyn core::future::Future<Output = Result<T, BanError>> + Send + 'a>>;

/// Reads and writes the identities a deployment is refusing.
///
/// A trait object rather than a type parameter on the session manager, which
/// already carries seven. The schema trait behind it carries associated
/// statement types and so cannot be one, which is why [`pg_ban_store`] confines
/// that generic to a factory.
pub trait BanStore<Id>: Send + Sync + 'static {
    /// The ban on `user_id`, as stored.
    ///
    /// Return the row untouched. connetto decides whether it still applies, so
    /// an implementation must not filter on the expiry.
    fn check<'a>(&'a self, user_id: &'a Id) -> BanFuture<'a, Option<Ban>>;

    /// Write `ban`, replacing whatever ban that identity already had.
    fn impose(&self, ban: NewBan<Id>) -> BanFuture<'_, ()>;

    /// Remove the ban on `user_id`, returning whether there was one.
    ///
    /// Every lift goes through here and every lift is recorded, which is why an
    /// expiry that simply lapses produces no record.
    fn lift<'a>(&'a self, user_id: &'a Id) -> BanFuture<'a, bool>;
}

/// The tables, columns and pre-built statements a [`BanStore`] runs.
///
/// Every associated table and column member derives `Default` (as
/// `diesel::table!` output does), so the store constructs each marker with
/// `T::default()`. The `fn` members build the pieces carrying runtime data.
pub trait ConnettoBanSchema: Send + Sync + 'static
where
    // The plain `SELECT session, reason, banned_at, expires_at WHERE user_id = ?`.
    // Laundered query source plus opaque predicate, so filtering does not route
    // through the delegating blanket `impl<T: QueryRelation> FilterDsl for T`
    // whose `Output` never terminates for an opaque type.
    Self::BansQuery: FilterDsl<Self::BanPk>,
    Filter<Self::BansQuery, Self::BanPk>:
        SelectDsl<(Self::Session, Self::Reason, Self::BannedAt, Self::ExpiresAt)>,
    Select<
        Filter<Self::BansQuery, Self::BanPk>,
        (Self::Session, Self::Reason, Self::BannedAt, Self::ExpiresAt),
    >: LimitDsl,
    for<'q> Limit<
        Select<
            Filter<Self::BansQuery, Self::BanPk>,
            (Self::Session, Self::Reason, Self::BannedAt, Self::ExpiresAt),
        >,
    >: AsyncLoadQuery<'q, AsyncPgConnection, (SessionId, String, Instant, Option<Instant>)> + Send,
{
    /// The deployment's typed distributed user id, the same one
    /// [`ConnettoAuditSchema`](crate::audit::ConnettoAuditSchema) carries.
    type Id: Clone + core::fmt::Display + Send + Sync + 'static;

    /// The bans table laundered as an opaque query source for the plain SELECT.
    type BansQuery: Default + Send;
    /// The `session` column (`Uuid`).
    type Session: diesel::Expression<SqlType = Uuid> + Default + Send;
    /// The `reason` column (`Text`).
    type Reason: diesel::Expression<SqlType = Text> + Default + Send;
    /// The `banned_at` column (`Timestamptz`).
    type BannedAt: diesel::Expression<SqlType = Timestamptz> + Default + Send;
    /// The `expires_at` column (`Nullable<Timestamptz>`).
    type ExpiresAt: diesel::Expression<SqlType = Nullable<Timestamptz>> + Default + Send;
    /// The opaque `user_id = ?` predicate.
    type BanPk: Send;

    /// The whole `INSERT ... ON CONFLICT (user_id) DO UPDATE` statement,
    /// laundered as one executable value because the diesel trait solver cannot
    /// name an upsert statement type generically.
    type Impose: ExecuteDsl<AsyncPgConnection> + Send;
    /// The whole `DELETE ... WHERE user_id = ?` statement, laundered the same
    /// way.
    type Lift: ExecuteDsl<AsyncPgConnection> + Send;

    /// Build the `user_id = ?` predicate.
    fn ban_pk(user_id: &Self::Id) -> Self::BanPk;
    /// Build the upsert for one ban.
    fn ban_upsert(ban: NewBan<Self::Id>) -> Self::Impose;
    /// Build the delete for one identity.
    fn ban_delete(user_id: &Self::Id) -> Self::Lift;
}

/// A [`BanStore`] over `B` on the given pool.
///
/// **The owner pool, never the reader pool.** The reader pool connects as a role
/// row-level security applies to, and an invisible row there is not an error but
/// zero rows, so the fail-closed read would never fire and the ban would
/// silently not apply. The owner pool bypasses policies by construction and is
/// already where the auth store reads. The accepted cost is that a deployment
/// cannot use row-level security to partition bans between its own tenants and
/// must express that in the query instead.
#[must_use]
pub fn pg_ban_store<B>(pool: Pool<AsyncPgConnection>) -> Arc<dyn BanStore<B::Id>>
where
    B: ConnettoBanSchema,
{
    Arc::new(PgBanStore::<B> {
        pool,
        schema: PhantomData,
    })
}

/// The Postgres [`BanStore`], generic over the deployment's schema.
struct PgBanStore<B> {
    pool: Pool<AsyncPgConnection>,
    schema: PhantomData<fn() -> B>,
}

impl<B: ConnettoBanSchema> BanStore<B::Id> for PgBanStore<B> {
    fn check<'a>(&'a self, user_id: &'a B::Id) -> BanFuture<'a, Option<Ban>> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(BanError::new)?;
            let filtered = FilterDsl::filter(B::BansQuery::default(), B::ban_pk(user_id));
            let query = SelectDsl::select(
                filtered,
                (
                    B::Session::default(),
                    B::Reason::default(),
                    B::BannedAt::default(),
                    B::ExpiresAt::default(),
                ),
            );
            let row: Option<(SessionId, String, Instant, Option<Instant>)> = query
                .first(&mut conn)
                .await
                .optional()
                .map_err(BanError::new)?;
            Ok(row.map(|(session, reason, banned_at, expires_at)| Ban {
                session,
                reason,
                banned_at,
                expires_at,
            }))
        })
    }

    fn impose(&self, ban: NewBan<B::Id>) -> BanFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(BanError::new)?;
            ExecuteDsl::execute(B::ban_upsert(ban), &mut conn)
                .await
                .map_err(BanError::new)?;
            Ok(())
        })
    }

    fn lift<'a>(&'a self, user_id: &'a B::Id) -> BanFuture<'a, bool> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(BanError::new)?;
            let removed = ExecuteDsl::execute(B::ban_delete(user_id), &mut conn)
                .await
                .map_err(BanError::new)?;
            Ok(removed > 0)
        })
    }
}

/// Generate the default `connetto_bans` table and its [`ConnettoBanSchema`]
/// impl, parameterized by the deployment's `Id` type and the diesel SQL type it
/// maps to.
///
/// A convenience default only: the table is the deployment's to define however
/// it likes, and [`ConnettoBanSchema`] is the real contract, implementable by
/// hand against any table. The reference SQL is in the module documentation.
///
/// Invoked at module scope, it emits the `connetto_bans` `diesel::table!`
/// module, an insertable row struct, and a unit struct `ConnettoBans`
/// implementing the trait. The caller needs `diesel` in scope.
///
/// ```ignore
/// connetto_server::connetto_ban_table!(String, diesel::sql_types::Text);
/// // now `ConnettoBans` implements `ConnettoBanSchema`.
/// ```
#[macro_export]
macro_rules! connetto_ban_table {
    ($id:ty, $id_sql:ty $(,)?) => {
        diesel::table! {
            /// The identities currently refused, one row each, a null
            /// `expires_at` meaning permanent.
            connetto_bans (user_id) {
                user_id -> $id_sql,
                session -> diesel::sql_types::Uuid,
                reason -> diesel::sql_types::Text,
                banned_at -> diesel::sql_types::Timestamptz,
                expires_at -> diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>,
            }
        }

        /// Insertable ban row for [`ConnettoBans`].
        #[derive(diesel::Insertable)]
        #[diesel(table_name = connetto_bans)]
        pub struct ConnettoNewBan {
            user_id: $id,
            session: $crate::SessionId,
            reason: String,
            banned_at: $crate::ban::Instant,
            expires_at: Option<$crate::ban::Instant>,
        }

        /// The default connetto ban list over the deployment's `Id` type.
        #[derive(Debug, Clone, Copy, Default)]
        pub struct ConnettoBans;

        impl $crate::ban::ConnettoBanSchema for ConnettoBans {
            type Id = $id;
            type BansQuery = connetto_bans::table;
            type Session = connetto_bans::session;
            type Reason = connetto_bans::reason;
            type BannedAt = connetto_bans::banned_at;
            type ExpiresAt = connetto_bans::expires_at;
            type BanPk = diesel::dsl::Eq<connetto_bans::user_id, $id>;
            type Impose = diesel::helper_types::Set<
                diesel::helper_types::DoUpdate<
                    diesel::helper_types::OnConflict<
                        diesel::query_builder::InsertStatement<
                            connetto_bans::table,
                            <ConnettoNewBan as diesel::Insertable<connetto_bans::table>>::Values,
                        >,
                        connetto_bans::user_id,
                    >,
                >,
                (
                    diesel::dsl::Eq<connetto_bans::session, $crate::SessionId>,
                    diesel::dsl::Eq<connetto_bans::reason, String>,
                    diesel::dsl::Eq<connetto_bans::banned_at, $crate::ban::Instant>,
                    diesel::dsl::Eq<connetto_bans::expires_at, Option<$crate::ban::Instant>>,
                ),
            >;
            type Lift = diesel::dsl::delete<
                diesel::helper_types::Filter<
                    connetto_bans::table,
                    diesel::dsl::Eq<connetto_bans::user_id, $id>,
                >,
            >;

            fn ban_pk(user_id: &Self::Id) -> Self::BanPk {
                use diesel::ExpressionMethods as _;
                connetto_bans::user_id.eq(user_id.clone())
            }

            fn ban_upsert(
                $crate::ban::NewBan {
                    user_id,
                    session,
                    reason,
                    banned_at,
                    expires_at,
                }: $crate::ban::NewBan<Self::Id>,
            ) -> Self::Impose {
                use diesel::ExpressionMethods as _;
                diesel::insert_into(connetto_bans::table)
                    .values(ConnettoNewBan {
                        user_id,
                        session,
                        reason: reason.clone(),
                        banned_at,
                        expires_at,
                    })
                    .on_conflict(connetto_bans::user_id)
                    .do_update()
                    .set((
                        connetto_bans::session.eq(session),
                        connetto_bans::reason.eq(reason),
                        connetto_bans::banned_at.eq(banned_at),
                        connetto_bans::expires_at.eq(expires_at),
                    ))
            }

            fn ban_delete(user_id: &Self::Id) -> Self::Lift {
                use diesel::ExpressionMethods as _;
                use diesel::QueryDsl as _;
                diesel::delete(
                    connetto_bans::table.filter(connetto_bans::user_id.eq(user_id.clone())),
                )
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ban(expires_at: Option<Instant>) -> Ban {
        Ban {
            session: SessionId::from_uuid(uuid::Uuid::nil()),
            reason: "refused_grant".to_owned(),
            banned_at: chrono::Utc::now(),
            expires_at,
        }
    }

    #[test]
    fn a_ban_with_no_expiry_always_applies() {
        assert!(ban(None).applies_at(chrono::Utc::now()));
    }

    #[test]
    fn an_expiry_that_has_passed_stops_applying_with_nothing_having_run() {
        let now = chrono::Utc::now();
        let lapsed = ban(Some(now - chrono::TimeDelta::seconds(1)));
        assert!(!lapsed.applies_at(now));
        let live = ban(Some(now + chrono::TimeDelta::seconds(1)));
        assert!(live.applies_at(now));
    }
}
