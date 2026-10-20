//! The structural contract for `connetto_bans`, the identities a deployment is
//! currently refusing.
//!
//! connetto owns no schema. A deployment declares the table and implements
//! [`ConnettoBanSchema`] for it, by hand or through
//! [`connetto_schema!`](crate::connetto_schema), and names it as the `Bans`
//! member of its [`ConnettoSchema`](crate::schema::ConnettoSchema), the same
//! arrangement as [`ConnettoStoreSchema`](crate::authn::ConnettoStoreSchema),
//! [`ConnettoWriterSchema`](crate::writer_schema::ConnettoWriterSchema)
//! and [`ConnettoAuditSchema`](crate::audit::ConnettoAuditSchema).
//!
//! Current state, not history. One row per banned identity, replaced when a
//! later crossing bans the same person again. The append-only record of every
//! impose and lift is `auth_events`, which is why an expiry that merely lapses
//! leaves no trace here or there.
//!
//! **A ban has no sweeper.** An expiry that passes stops applying immediately,
//! declaratively, with nothing running, and its row stays until
//! [`BanStore::lift`] clears it. The `applies` verdict a read returns is the
//! statement's, judged against the database's clock (chapter 21). A deployment
//! wanting rows cleared promptly schedules its own task calling the lift, which
//! puts the scheduling where scheduling is easy and works identically on one
//! server or ten. A sweeper inside connetto was rejected because a deployment
//! may run several servers over replicated databases, so each would sweep the
//! same rows and race.
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
//! `banned_at` carries no column default, unlike `auth_events.at`, because the
//! insert stamps both columns from one `now()` in one statement, and a ban
//! whose start and expiry disagree would be a lie. `session` is the run the
//! crossing happened on, kept because `auth_events.session` is `NOT NULL` and
//! a lift performed months later has no run of its own to name.

use core::pin::Pin;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use connetto_core::SessionId;
use diesel::QueryResult;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::bb8::Pool;

pub use crate::authn::schema::Instant;

/// A ban as stored, with the read's verdict on whether it still applies.
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
    /// Whether the database's clock is still within the ban's span.
    pub applies: bool,
}

/// A ban about to be written. The store stamps `banned_at` and `expires_at`
/// from the database's clock, so this carries only the span.
#[derive(Debug, Clone)]
pub struct NewBan<Id> {
    /// Who is banned.
    pub user_id: Id,
    /// The run the crossing happened on.
    pub session: SessionId,
    /// Which threshold they crossed.
    pub reason: String,
    /// The ban's span. Absent is permanent.
    pub ttl: Option<Duration>,
}

impl<Id> NewBan<Id> {
    /// A ban stamped at insert, lasting `ttl` or forever when absent.
    ///
    /// A `ttl` too large for a `BIGINT` of seconds is stored as permanent.
    #[must_use]
    pub fn starting_now(
        user_id: Id,
        session: SessionId,
        reason: impl Into<String>,
        ttl: Option<Duration>,
    ) -> Self {
        Self {
            user_id,
            session,
            reason: reason.into(),
            ttl,
        }
    }
}

/// One statement of a [`ConnettoBanSchema`], run on a borrowed connection.
pub type Statement<'c, T> = Pin<Box<dyn Future<Output = QueryResult<T>> + Send + 'c>>;

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
    /// The ban on `user_id`, as stored, with the read's verdict on whether it
    /// still applies.
    fn check<'a>(&'a self, user_id: &'a Id) -> BanFuture<'a, Option<Ban>>;

    /// Write `ban`, replacing whatever ban that identity already had.
    fn impose(&self, ban: NewBan<Id>) -> BanFuture<'_, ()>;

    /// Remove the ban on `user_id`, returning whether there was one.
    ///
    /// Every lift goes through here and every lift is recorded, which is why an
    /// expiry that simply lapses produces no record.
    fn lift<'a>(&'a self, user_id: &'a Id) -> BanFuture<'a, bool>;
}

/// The statements a [`BanStore`] runs over the deployment's ban table.
///
/// A deadline the table holds is stamped `now() + interval` and judged against
/// `now()` in the statement that reads it, never against the process's clock
/// (chapter 21).
pub trait ConnettoBanSchema: Send + Sync + 'static {
    /// The deployment's typed distributed user id, the same one
    /// [`ConnettoAuditSchema`](crate::audit::ConnettoAuditSchema) carries.
    type Id: Clone + core::fmt::Display + Send + Sync + 'static;

    /// The tables this member reads and writes, by name, which startup
    /// requires to exist (R98 decision 5).
    const TABLES: &'static [&'static str];

    /// The ban on `user_id`, with the statement's verdict on whether it still
    /// applies, absent when no such row exists.
    fn ban_row<'c>(
        conn: &'c mut AsyncPgConnection,
        user_id: &'c Self::Id,
    ) -> Statement<'c, Option<Ban>>;

    /// The `INSERT ... ON CONFLICT (user_id) DO UPDATE` that stamps one ban
    /// from the database's clock, replacing whatever ban that identity held.
    fn ban_upsert(conn: &mut AsyncPgConnection, ban: NewBan<Self::Id>) -> Statement<'_, ()>;

    /// The `DELETE` for one identity, returning how many rows it removed.
    fn ban_delete<'c>(
        conn: &'c mut AsyncPgConnection,
        user_id: &'c Self::Id,
    ) -> Statement<'c, usize>;
}

/// A [`BanStore`] over the deployment's ban table, `D`'s [`Bans`] member, on
/// the given pool.
///
/// **The owner pool, never the reader pool.** The reader pool connects as a role
/// row-level security applies to, and an invisible row there is not an error but
/// zero rows, so the fail-closed read would never fire and the ban would
/// silently not apply. The owner pool bypasses policies by construction and is
/// already where the auth store reads. The accepted cost is that a deployment
/// cannot use row-level security to partition bans between its own tenants and
/// must express that in the query instead.
///
/// [`Bans`]: crate::schema::ConnettoSchema::Bans
#[must_use]
pub fn pg_ban_store<D>(pool: Pool<AsyncPgConnection>) -> Arc<dyn BanStore<D::Id>>
where
    D: crate::schema::ConnettoSchema,
{
    Arc::new(PgBanStore::<D::Bans> {
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
            B::ban_row(&mut conn, user_id).await.map_err(BanError::new)
        })
    }

    fn impose(&self, ban: NewBan<B::Id>) -> BanFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(BanError::new)?;
            B::ban_upsert(&mut conn, ban).await.map_err(BanError::new)?;
            Ok(())
        })
    }

    fn lift<'a>(&'a self, user_id: &'a B::Id) -> BanFuture<'a, bool> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(BanError::new)?;
            let removed = B::ban_delete(&mut conn, user_id)
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
/// module and a unit struct `ConnettoBans` implementing the trait. The caller
/// needs `diesel` in scope.
///
/// ```ignore
/// connetto_server::connetto_ban_table!(String, diesel::sql_types::Text);
/// // now `ConnettoBans` implements `ConnettoBanSchema`.
/// ```
#[doc(hidden)]
#[macro_export]
macro_rules! connetto_ban_table {
    ($id:ty, $id_sql:ty $(,)?) => {
        diesel::table! {
            /// The identities currently refused, one row each, a null
            /// `expires_at` meaning permanent.
            connetto_bans (user_id) {
                /// Who is banned, in the deployment's own id type.
                user_id -> $id_sql,
                /// The run the crossing happened on, so a lift months later has
                /// a real session to record against.
                session -> diesel::sql_types::Uuid,
                /// Which threshold they crossed, as connetto recorded it.
                reason -> diesel::sql_types::Text,
                /// When the ban started, stamped by the insert's `now()`.
                banned_at -> diesel::sql_types::Timestamptz,
                /// When it lapses, `now()` plus the ban's span. Null is
                /// permanent.
                expires_at -> diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>,
            }
        }

        /// The default connetto ban list over the deployment's `Id` type.
        #[derive(Debug, Clone, Copy, Default)]
        pub struct ConnettoBans;

        impl $crate::ban::ConnettoBanSchema for ConnettoBans {
            type Id = $id;
            const TABLES: &'static [&'static str] = &["connetto_bans"];

            fn ban_row<'c>(
                conn: &'c mut diesel_async::AsyncPgConnection,
                user_id: &'c Self::Id,
            ) -> $crate::ban::Statement<'c, Option<$crate::ban::Ban>> {
                Box::pin(async move {
                    use diesel::ExpressionMethods as _;
                    use diesel::OptionalExtension as _;
                    use diesel_async::RunQueryDsl;
                    // The applies verdict is the statement's, judged against
                    // the database's clock (chapter 21).
                    let found: Option<(
                        $crate::SessionId,
                        String,
                        $crate::ban::Instant,
                        Option<$crate::ban::Instant>,
                        bool,
                        Option<bool>,
                    )> = diesel::QueryDsl::select(
                        diesel::QueryDsl::filter(
                            connetto_bans::table,
                            connetto_bans::user_id.eq(user_id.clone()),
                        ),
                        (
                            connetto_bans::session,
                            connetto_bans::reason,
                            connetto_bans::banned_at,
                            connetto_bans::expires_at,
                            connetto_bans::expires_at.is_null(),
                            connetto_bans::expires_at.gt(diesel::dsl::sql::<
                                diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>,
                            >("now()")),
                        ),
                    )
                    .first(conn)
                    .await
                    .optional()?;
                    Ok(
                        found.map(|(session, reason, banned_at, expires_at, open, fresh)| {
                            $crate::ban::Ban {
                                session,
                                reason,
                                banned_at,
                                expires_at,
                                applies: open || fresh.unwrap_or(false),
                            }
                        }),
                    )
                })
            }

            fn ban_upsert(
                conn: &mut diesel_async::AsyncPgConnection,
                $crate::ban::NewBan {
                    user_id,
                    session,
                    reason,
                    ttl,
                }: $crate::ban::NewBan<Self::Id>,
            ) -> $crate::ban::Statement<'_, ()> {
                Box::pin(async move {
                    use diesel::ExpressionMethods as _;
                    use diesel_async::RunQueryDsl as _;
                    // The expiry is the database's clock plus the ban's span, NULL
                    // for a permanent ban or a span too long for an i64 of seconds
                    // (chapter 21).
                    let span = ttl
                        .filter(|span| i64::try_from(span.as_secs()).is_ok())
                        .map(|span| span.as_secs_f64());
                    let expiry = || {
                        diesel::dsl::sql::<
                            diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>,
                        >("CASE WHEN ")
                        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Double>, _>(span)
                        .sql(" IS NULL THEN NULL ELSE now() + make_interval(secs => ")
                        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Double>, _>(span)
                        .sql(") END")
                    };
                    diesel::insert_into(connetto_bans::table)
                        .values((
                            connetto_bans::user_id.eq(user_id),
                            connetto_bans::session.eq(session.clone()),
                            connetto_bans::reason.eq(reason.clone()),
                            connetto_bans::banned_at.eq($crate::db_clock::now()),
                            connetto_bans::expires_at.eq(expiry()),
                        ))
                        .on_conflict(connetto_bans::user_id)
                        .do_update()
                        .set((
                            connetto_bans::session.eq(session),
                            connetto_bans::reason.eq(reason),
                            connetto_bans::banned_at.eq($crate::db_clock::now()),
                            connetto_bans::expires_at.eq(expiry()),
                        ))
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            }

            fn ban_delete<'c>(
                conn: &'c mut diesel_async::AsyncPgConnection,
                user_id: &'c Self::Id,
            ) -> $crate::ban::Statement<'c, usize> {
                Box::pin(async move {
                    use diesel::ExpressionMethods as _;
                    use diesel_async::RunQueryDsl as _;
                    diesel::delete(diesel::QueryDsl::filter(
                        connetto_bans::table,
                        connetto_bans::user_id.eq(user_id.clone()),
                    ))
                    .execute(conn)
                    .await
                })
            }
        }
    };
}
