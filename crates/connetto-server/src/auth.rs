//! Authorization policies for the write and read paths.
//!
//! The server gates every mutation through an [`AuthPolicy`]. Until `OpenFGA` and
//! `rls2fga` land, [`PermissiveAuth`] is the stand-in.

use std::convert::Infallible;

use connetto_core::auth::AuthContext;
use connetto_core::traits::{AuthPolicy, MutationOp};

/// A permissive [`AuthPolicy`] that grants every read and write.
///
/// The stand-in until `OpenFGA` and `rls2fga` land. It authorizes
/// unconditionally, so it must not front a production deployment.
#[derive(Debug, Clone, Copy, Default)]
pub struct PermissiveAuth;

impl AuthPolicy for PermissiveAuth {
    type Error = Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn can_read(
        &self,
        _ctx: &AuthContext,
        _table: &str,
        _pk: &[u8],
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn can_write(
        &self,
        _ctx: &AuthContext,
        _table: &str,
        _pk: &[u8],
        _op: MutationOp,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[cfg(feature = "pg-async")]
pub use rls::{RlsAuth, RlsAuthError};

#[cfg(feature = "pg-async")]
mod rls {
    use connetto_core::auth::AuthContext;
    use connetto_core::traits::{AuthPolicy, MutationOp};
    use diesel::QueryableByName;
    use diesel::sql_query;
    use diesel::sql_types::{BigInt, Binary, Bool, Double, Text};
    use diesel_async::pooled_connection::bb8::Pool;
    use diesel_async::scoped_futures::ScopedFutureExt;
    use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
    use sqlparser::dialect::PostgreSqlDialect;
    use subql::backend::Value;
    use subql::{ParserDB, catalog_helpers};

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
        /// The primary-key bytes did not decode.
        #[error("primary-key decode failed: {0}")]
        PkDecode(String),
        /// A primary-key column has a type the read filter cannot bind yet.
        #[error("unsupported primary-key type {kind} on table {table}")]
        UnsupportedKeyType {
            /// Table whose key could not be bound.
            table: String,
            /// The scalar kind that is not yet bindable.
            kind: String,
        },
    }

    /// An [`AuthPolicy`] that enforces reads through Postgres Row-Level Security.
    ///
    /// A read check runs `SELECT EXISTS(...)` for the row's primary key inside a
    /// transaction that first sets `app.user_id` to the requesting identity, so
    /// RLS policies keyed on `current_setting('app.user_id')` decide visibility.
    /// The key arrives as [`crate::pk`] bytes, decoded back into typed values and
    /// bound as indexed `"col" = $n` equality per key column, so the row's own
    /// primary-key index answers the check. A key of a type the bind path does
    /// not cover yet (timestamp, date, time, decimal, json) fails loudly.
    ///
    /// The pool must connect as a role that is itself subject to RLS, meaning a
    /// non-superuser that does not own the table. Postgres bypasses every policy
    /// for a superuser or the table owner, so such a connection would silently
    /// make every read visible.
    ///
    /// Write authorization is not gated here yet: it lands when the mutation
    /// applies under the same RLS context against Postgres, so the database
    /// itself rejects a policy violation. Until that write path exists,
    /// [`can_write`](RlsAuth::can_write) passes and reads are the enforced
    /// surface.
    pub struct RlsAuth {
        pool: Pool<AsyncPgConnection>,
        catalog: ParserDB,
    }

    #[derive(QueryableByName)]
    struct Present {
        #[diesel(sql_type = Bool)]
        present: bool,
    }

    impl RlsAuth {
        /// Build over a connection pool and a Postgres DDL catalog.
        ///
        /// # Errors
        ///
        /// [`RlsAuthError::Catalog`] when the DDL does not parse.
        pub fn from_ddl(pool: Pool<AsyncPgConnection>, pg_ddl: &str) -> Result<Self, RlsAuthError> {
            let catalog = ParserDB::parse::<PostgreSqlDialect>(pg_ddl)
                .map_err(|err| RlsAuthError::Catalog(format!("{err:?}")))?;
            Ok(Self { pool, catalog })
        }

        /// Primary-key column names for `table`, in key order.
        fn pk_columns(&self, table: &str) -> Option<Vec<String>> {
            let table_id = catalog_helpers::table_id(&self.catalog, table)?;
            catalog_helpers::primary_key_columns(&self.catalog, table_id)?
                .into_iter()
                .map(|col| catalog_helpers::column_name(&self.catalog, table_id, col))
                .collect()
        }
    }

    /// Quote a SQL identifier, doubling embedded quotes.
    fn quote_ident(name: &str) -> String {
        format!("\"{}\"", name.replace('"', "\"\""))
    }

    impl AuthPolicy for RlsAuth {
        type Error = RlsAuthError;

        async fn can_read(
            &self,
            ctx: &AuthContext,
            table: &str,
            pk: &[u8],
        ) -> Result<bool, RlsAuthError> {
            let Some(pk_cols) = self.pk_columns(table) else {
                return Ok(false);
            };
            if pk_cols.is_empty() {
                return Ok(false);
            }
            let key =
                crate::pk::decode(pk).map_err(|err| RlsAuthError::PkDecode(err.to_string()))?;
            if key.len() != pk_cols.len() {
                return Ok(false);
            }
            // Typed, indexed equality per key column: "col" = $n. Identifiers come
            // from the parsed catalog and values bind positionally, so the row's
            // own primary-key index answers the check.
            let predicate = pk_cols
                .iter()
                .enumerate()
                .map(|(i, col)| format!("{} = ${}", quote_ident(col), i + 1))
                .collect::<Vec<_>>()
                .join(" AND ");
            let sql = format!(
                "SELECT EXISTS(SELECT 1 FROM {} WHERE {}) AS present",
                quote_ident(table),
                predicate,
            );
            let mut query = sql_query(sql).into_boxed::<diesel::pg::Pg>();
            for value in &key {
                query = match value {
                    Value::Bool(b) => query.bind::<Bool, _>(*b),
                    Value::Int(int) => query.bind::<BigInt, _>(*int),
                    Value::Float(float) => query.bind::<Double, _>(*float),
                    Value::String(text) => query.bind::<Text, _>(text.clone()),
                    Value::Bytes(bytes) => query.bind::<Binary, _>(bytes.clone()),
                    Value::Uuid(uuid) => query.bind::<diesel::sql_types::Uuid, _>(*uuid),
                    Value::Null | Value::Missing => return Ok(false),
                    other => {
                        return Err(RlsAuthError::UnsupportedKeyType {
                            table: table.to_owned(),
                            kind: format!("{:?}", other.scalar_kind()),
                        });
                    }
                };
            }
            let user_id = ctx.user_id.clone();
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|err| RlsAuthError::Pool(err.to_string()))?;
            let present = conn
                .transaction::<bool, diesel::result::Error, _>(|c| {
                    async move {
                        sql_query("SELECT set_config('app.user_id', $1, true)")
                            .bind::<Text, _>(user_id)
                            .execute(c)
                            .await?;
                        let row: Present = query.get_result(c).await?;
                        Ok(row.present)
                    }
                    .scope_boxed()
                })
                .await?;
            Ok(present)
        }

        #[allow(clippy::unused_async_trait_impl)]
        async fn can_write(
            &self,
            _ctx: &AuthContext,
            _table: &str,
            _pk: &[u8],
            _op: MutationOp,
        ) -> Result<bool, RlsAuthError> {
            Ok(true)
        }
    }
}
