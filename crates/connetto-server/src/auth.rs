//! Visibility policies for the change, catchup, write and minting paths.
//!
//! Every authorization question goes through subql's [`VisibilityPolicy`], so
//! what answers it is an implementation detail rather than a structural
//! commitment. The shipped answer is `FgaAuth` (R5b) and [`RlsAuth`] is the
//! row-level-security one, kept as the second opinion `ParityAuth` compares
//! against.
//!
//! [`VisibilityPolicy`]: subql::visibility::VisibilityPolicy

pub use rls::{RlsAuth, RlsAuthError};

mod rls {
    use std::marker::PhantomData;
    use std::sync::Arc;

    use connetto_core::auth::Principal;
    use diesel::OptionalExtension;
    use diesel::QueryableByName;
    use diesel::sql_query;
    use diesel::sql_types::Bool;
    use diesel_async::pooled_connection::bb8::Pool;
    use diesel_async::scoped_futures::ScopedFutureExt;
    use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
    use sqlparser::dialect::PostgreSqlDialect;
    use subql::backend::Postgres;
    use subql::visibility::{RowView, RowWrite, Verdict, VisibilityPolicy};
    use subql::{DatabaseLike, ParserDB, TableLike};

    use crate::capability::{CallerBinding, CapabilityKey};
    use crate::key_filter::{KeyError, KeyFilter};
    use connetto_core::quote_ident;

    /// How long a locking read waits for a conflicting writer.
    ///
    /// A mint is not a hot path, but it holds a pooled connection while it
    /// waits, so an unbounded wait would let one stuck transaction exhaust the
    /// pool. An expired wait is an error, which the mint reports as an undecided
    /// answer rather than a denial.
    const LOCK_WAIT: &str = "3s";

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
        /// The write question has no answer for this table, so the caller must
        /// refuse rather than take a yes or a no from it.
        #[error("cannot decide a write on {table}: {detail}")]
        Undecidable {
            /// The table whose rules cannot be spoken for.
            table: String,
            /// Why the answer is unavailable.
            detail: String,
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
        /// The setting a policy reads the caller's identity from.
        user_setting: std::sync::Arc<str>,
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
        /// Read the caller's identity from `setting` rather than the default.
        ///
        /// The share-key setting has been the application's choice since R4; this
        /// is its counterpart, so an application fitting connetto into rules that
        /// already name things its own way can rename both.
        #[must_use]
        pub fn with_user_setting(mut self, setting: impl Into<std::sync::Arc<str>>) -> Self {
            self.user_setting = setting.into();
            self
        }

        /// Build over a connection pool and a Postgres DDL catalog.
        ///
        /// # Errors
        ///
        /// [`RlsAuthError::Catalog`] when the DDL does not parse.
        pub fn from_ddl(pool: Pool<AsyncPgConnection>, pg_ddl: &str) -> Result<Self, RlsAuthError> {
            let catalog = ParserDB::parse::<PostgreSqlDialect>(pg_ddl)
                .map_err(|err| RlsAuthError::Catalog(format!("{err:?}")))?;
            Ok(Self {
                user_setting: crate::capability::DEFAULT_USER_SETTING.into(),
                pool,
                catalog,
                key: PhantomData,
            })
        }

        /// Name the row: its table and the bound equality over its primary key.
        ///
        /// [`None`] where the row is unanswerable at all: a table the catalog
        /// does not know, a table with no primary key, or a key cell carrying no
        /// value. Every caller denies in those cases, which is what asking the
        /// database would have returned.
        fn locate<R>(&self, row: &R) -> Result<Option<(String, KeyFilter)>, RlsAuthError>
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
            Ok(Some((table, filter)))
        }

        /// Build the `SELECT EXISTS` for `row`, reading its key off the view.
        fn question<R>(&self, row: &R) -> Result<Question, RlsAuthError>
        where
            R: RowView<Backend = Postgres> + ?Sized,
        {
            Ok(self.locate(row)?.map(|(table, filter)| {
                (
                    format!(
                        "SELECT EXISTS(SELECT 1 FROM {} WHERE {}) AS present",
                        quote_ident(&table),
                        filter.predicate(),
                    ),
                    filter,
                )
            }))
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
            let binding = CallerBinding::of(caller, std::sync::Arc::clone(&self.user_setting));
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

        /// Ask Postgres whether `caller` may take the existing row for a write.
        ///
        /// A locking read is the question: Postgres applies the table's update
        /// rule to `SELECT ... FOR UPDATE`, so a row the caller may not change
        /// comes back empty while one it may comes back present. The transaction
        /// commits at once, which releases the lock, and it bounds its wait
        /// first, because a mint holds a pooled connection while it waits and an
        /// unbounded wait would let one stuck writer exhaust the pool. A wait
        /// that expires is an error, so the caller reports an undecided answer
        /// rather than a denial.
        async fn takeable(
            &self,
            table: &str,
            filter: &KeyFilter,
            caller: &Principal<String, Key>,
        ) -> Result<bool, RlsAuthError> {
            let sql = format!(
                "SELECT true AS present FROM {} WHERE {} FOR UPDATE",
                quote_ident(table),
                filter.predicate(),
            );
            let query = filter.bind(sql_query(sql).into_boxed::<diesel::pg::Pg>());
            let binding = CallerBinding::of(caller, std::sync::Arc::clone(&self.user_setting));
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|err| RlsAuthError::Pool(err.to_string()))?;
            let present = conn
                .transaction::<Option<Present>, diesel::result::Error, _>(|c| {
                    async move {
                        sql_query(format!("SET LOCAL lock_timeout = '{LOCK_WAIT}'"))
                            .execute(c)
                            .await?;
                        binding.apply(c).await?;
                        crate::counters::add(&crate::counters::AUTHORIZATION_CALLS, 1);
                        query.get_result(c).await.optional()
                    }
                    .scope_boxed()
                })
                .await?;
            Ok(present.is_some())
        }

        /// Whether every row-level-security rule on `table` covers every
        /// command.
        ///
        /// A locking read is judged by the update rule, so it speaks for a delete
        /// only when one rule governs both. The moment a table writes any rule
        /// for a single command the two can differ, and the dangerous case is
        /// not only a stricter delete rule: a table with an update rule and no
        /// delete rule permits no delete at all while the locking read still
        /// answers yes.
        ///
        /// Asked per question rather than cached, because a cached answer goes
        /// stale exactly when a deployment tightens a rule.
        async fn one_rule_for_every_command(&self, table: &str) -> Result<bool, RlsAuthError> {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|err| RlsAuthError::Pool(err.to_string()))?;
            let narrowed: Present = sql_query(
                "SELECT EXISTS(SELECT 1 FROM pg_policies \
                 WHERE schemaname = current_schema() AND tablename = $1 AND cmd <> 'ALL') \
                 AS present",
            )
            .bind::<diesel::sql_types::Text, _>(table.to_owned())
            .get_result(&mut *conn)
            .await?;
            Ok(!narrowed.present)
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

        /// Answer the two verbs a share can certify, and pass the rest through.
        ///
        /// The two verbs a share names both carry an existing row, so both are
        /// answerable: a locking read is what the update rule judges. An insert
        /// and the resulting-row half of an update carry no existing row, and
        /// their only caller applies the write to Postgres immediately
        /// afterwards, so the database is their gate and answering them here
        /// would be a second evaluator that can disagree with it.
        ///
        /// A verb this does not know refuses rather than guessing, which is what
        /// subql's own documentation asks of an implementation.
        async fn may_write<R>(
            &self,
            write: RowWrite<'_, R>,
            watcher: &Self::Watcher,
        ) -> Result<Verdict, RlsAuthError>
        where
            R: RowView<Backend = Postgres> + Sync + ?Sized,
        {
            let old = match write {
                RowWrite::Insert { .. } | RowWrite::Update { .. } => return Ok(Verdict::Allow),
                RowWrite::UpdateUsing { old } | RowWrite::Delete { old } => old,
                _ => return Ok(Verdict::Deny),
            };
            let Some((table, filter)) = self.locate(old)? else {
                return Ok(Verdict::Deny);
            };
            if matches!(write, RowWrite::Delete { .. })
                && !self.one_rule_for_every_command(&table).await?
            {
                return Err(RlsAuthError::Undecidable {
                    table,
                    detail: "the table writes a rule for a single command, and a locking read \
                             speaks only for the update rule"
                        .to_owned(),
                });
            }
            if self.takeable(&table, &filter, watcher).await? {
                Ok(Verdict::Allow)
            } else {
                Ok(Verdict::Deny)
            }
        }
    }
}
