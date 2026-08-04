//! Visibility policies for the change, catchup, write and minting paths.
//!
//! Every authorization question goes through subql's [`VisibilityPolicy`], so
//! what answers it is an implementation detail rather than a structural
//! commitment. Until `OpenFGA` and `rls2fga` land, [`PermissiveAuth`] is the
//! stand-in and [`RlsAuth`] is the real one.
//!
//! [`VisibilityPolicy`]: subql::visibility::VisibilityPolicy

use std::convert::Infallible;
use std::sync::Arc;

use connetto_core::auth::Principal;
use subql::backend::Postgres;
use subql::visibility::{RowView, Verdict, VisibilityPolicy, WriteOp};

/// A permissive policy that grants every read and write.
///
/// The stand-in until `OpenFGA` and `rls2fga` land. It authorizes
/// unconditionally, so it must not front a production deployment.
#[derive(Debug, Clone, Copy, Default)]
pub struct PermissiveAuth;

impl VisibilityPolicy for PermissiveAuth {
    type Watcher = Arc<Principal>;
    type Error = Infallible;
    type Backend = Postgres;

    fn may_see<R>(
        &self,
        _row: &R,
        watchers: &[Self::Watcher],
        verdicts: &mut [Verdict],
    ) -> impl Future<Output = Result<(), Infallible>> + Send
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        for verdict in verdicts.iter_mut().take(watchers.len()) {
            *verdict = Verdict::Allow;
        }
        async { Ok(()) }
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn may_write<R>(
        &self,
        _row: &R,
        _watcher: &Self::Watcher,
        _op: WriteOp,
    ) -> Result<Verdict, Infallible>
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        Ok(Verdict::Allow)
    }
}

pub use rls::{RlsAuth, RlsAuthError};

mod rls {
    use std::marker::PhantomData;
    use std::sync::Arc;

    use connetto_core::auth::Principal;
    use diesel::QueryableByName;
    use diesel::sql_query;
    use diesel::sql_types::Bool;
    use diesel_async::pooled_connection::bb8::Pool;
    use diesel_async::scoped_futures::ScopedFutureExt;
    use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
    use sqlparser::dialect::PostgreSqlDialect;
    use subql::backend::Postgres;
    use subql::visibility::{RowView, Verdict, VisibilityPolicy, WriteOp};
    use subql::{DatabaseLike, ParserDB, TableLike};

    use crate::capability::{CallerBinding, CapabilityKey};
    use crate::key_filter::{KeyError, KeyFilter, quote_ident};

    /// Failure surfaced by [`RlsAuth`].
    #[derive(Debug, thiserror::Error)]
    pub enum RlsAuthError {
        /// The Postgres DDL handed to [`RlsAuth::from_ddl`] did not parse.
        #[error("catalog parse failed: {0}")]
        Catalog(String),
        /// The connection pool could not hand out a connection.
        #[error("auth pool error: {0}")]
        Pool(String),
        /// A visibility query failed.
        #[error(transparent)]
        Query(#[from] diesel::result::Error),
        /// A primary-key cell of the row could not be read.
        #[error(transparent)]
        KeyValue(subql::ValueError),
        /// A primary-key column has a type the read filter cannot bind yet.
        #[error("unsupported primary-key type {kind} on table {table}")]
        UnsupportedKeyType {
            /// Table whose key could not be bound.
            table: String,
            /// The scalar kind that is not yet bindable.
            kind: String,
        },
    }

    impl From<KeyError> for RlsAuthError {
        fn from(err: KeyError) -> Self {
            match err {
                KeyError::Value(err) => Self::KeyValue(err),
                KeyError::Unsupported { table, kind } => Self::UnsupportedKeyType { table, kind },
            }
        }
    }

    /// A visibility policy that enforces reads through Postgres Row-Level
    /// Security.
    ///
    /// A read check runs `SELECT EXISTS(...)` for the row's primary key inside a
    /// transaction that first binds the caller (`app.user_id` for the identity,
    /// and the packed share keys under the binding's own setting), so RLS
    /// policies keyed on `current_setting` decide visibility. The key is read
    /// off the row view a column at a time and bound as indexed `"col" = $n`
    /// equality per key column, so the row's own primary-key index answers the
    /// check. A key of a type the bind path does not cover yet (timestamp,
    /// date, time, decimal, json) fails loudly.
    ///
    /// One question names every watcher, and RLS binds one caller per
    /// transaction, so the round trips stay one per watcher until the executor
    /// changes.
    ///
    /// The pool must connect as a role that is itself subject to RLS, meaning a
    /// non-superuser that does not own the table. Postgres bypasses every policy
    /// for a superuser or the table owner, so such a connection would silently
    /// make every read visible.
    ///
    /// Write authorization is not gated here: the mutation applies under the
    /// same RLS context against Postgres, so the database itself rejects a
    /// policy violation, and [`may_write`](RlsAuth::may_write) passes.
    ///
    /// `Key` is the deployment's share-key type, carried only so the caller
    /// this binds is the same one every other path carries.
    pub struct RlsAuth<Key = String> {
        pool: Pool<AsyncPgConnection>,
        catalog: ParserDB,
        key: PhantomData<Key>,
    }

    #[derive(QueryableByName)]
    struct Present {
        #[diesel(sql_type = Bool)]
        present: bool,
    }

    /// The existence question for one row, built once and asked per watcher.
    ///
    /// [`None`] where the row is unanswerable at all: a table the catalog does
    /// not know, a table with no primary key, or a key cell carrying no value.
    /// Every watcher is denied in those cases, which is what asking the
    /// database would have returned for each of them.
    type Question = Option<(String, KeyFilter)>;

    impl<Key> RlsAuth<Key> {
        /// Build over a connection pool and a Postgres DDL catalog.
        ///
        /// # Errors
        ///
        /// [`RlsAuthError::Catalog`] when the DDL does not parse.
        pub fn from_ddl(pool: Pool<AsyncPgConnection>, pg_ddl: &str) -> Result<Self, RlsAuthError> {
            let catalog = ParserDB::parse::<PostgreSqlDialect>(pg_ddl)
                .map_err(|err| RlsAuthError::Catalog(format!("{err:?}")))?;
            Ok(Self {
                pool,
                catalog,
                key: PhantomData,
            })
        }

        /// Build the `SELECT EXISTS` for `row`, reading its key off the view.
        fn question<R>(&self, row: &R) -> Result<Question, RlsAuthError>
        where
            R: RowView<Backend = Postgres> + ?Sized,
        {
            let table_id = row.table_id();
            let Some(index) = usize::try_from(table_id).ok() else {
                return Ok(None);
            };
            let Some(table) = self.catalog.table_by_id(index) else {
                return Ok(None);
            };
            let table = table.table_name().to_owned();
            let Some(filter) = KeyFilter::build(&self.catalog, table_id, &table, |_, column| {
                row.value_at(column)
            })?
            else {
                return Ok(None);
            };
            Ok(Some((
                format!(
                    "SELECT EXISTS(SELECT 1 FROM {} WHERE {}) AS present",
                    quote_ident(&table),
                    filter.predicate(),
                ),
                filter,
            )))
        }
    }

    impl<Key: CapabilityKey> RlsAuth<Key> {
        /// Ask Postgres whether `caller` can see the row the question names.
        async fn visible(
            &self,
            sql: &str,
            filter: &KeyFilter,
            caller: &Principal<String, Key>,
        ) -> Result<bool, RlsAuthError> {
            let query = filter.bind(sql_query(sql.to_owned()).into_boxed::<diesel::pg::Pg>());
            let binding = CallerBinding::of(caller);
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|err| RlsAuthError::Pool(err.to_string()))?;
            let present = conn
                .transaction::<bool, diesel::result::Error, _>(|c| {
                    async move {
                        binding.apply(c).await?;
                        crate::counters::add(&crate::counters::AUTHORIZATION_CALLS, 1);
                        let row: Present = query.get_result(c).await?;
                        Ok(row.present)
                    }
                    .scope_boxed()
                })
                .await?;
            Ok(present)
        }
    }

    impl<Key: CapabilityKey> VisibilityPolicy for RlsAuth<Key> {
        type Watcher = Arc<Principal<String, Key>>;
        type Error = RlsAuthError;
        type Backend = Postgres;

        fn may_see<R>(
            &self,
            row: &R,
            watchers: &[Self::Watcher],
            verdicts: &mut [Verdict],
        ) -> impl Future<Output = Result<(), RlsAuthError>> + Send
        where
            R: RowView<Backend = Postgres> + Sync + ?Sized,
        {
            // The row is read here rather than inside the future, so nothing
            // holds the view across an await.
            let question = self.question(row);
            async move {
                let Some((sql, filter)) = question? else {
                    return Ok(());
                };
                for (watcher, verdict) in watchers.iter().zip(verdicts.iter_mut()) {
                    // A pool or query failure denies this watcher and no other.
                    // Returning here instead would leave every later watcher on
                    // its pre-filled denial, which is a wider denial than one
                    // failed round trip earns.
                    if let Ok(true) = self.visible(&sql, &filter, watcher).await {
                        *verdict = Verdict::Allow;
                    }
                }
                Ok(())
            }
        }

        /// The write applies under the caller's own RLS context, so Postgres
        /// `WITH CHECK` is the gate. Nothing to add here.
        #[allow(clippy::unused_async_trait_impl)]
        async fn may_write<R>(
            &self,
            _row: &R,
            _watcher: &Self::Watcher,
            _op: WriteOp,
        ) -> Result<Verdict, RlsAuthError>
        where
            R: RowView<Backend = Postgres> + Sync + ?Sized,
        {
            Ok(Verdict::Allow)
        }
    }
}
