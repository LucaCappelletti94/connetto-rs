//! The structural contract the Postgres write target keys its exactly-once
//! watermark against.
//!
//! connetto owns no schema. A deployment declares its own durable mutation
//! watermark table (see `docs/architecture/11-authentication.md`) and implements
//! [`ConnettoWatermarkSchema`] for it, either by hand or through the
//! [`connetto_watermark_table!`](crate::connetto_watermark_table) convenience
//! macro. [`PgWriteTarget`](crate::write_target::PgWriteTarget)'s `commit` and
//! `last_applied` are generic over this trait and keep the dedup decision (the
//! monotone `GREATEST` advance) themselves; only the mechanical diesel
//! statements are built in the impl, because the diesel `future` trait solver
//! cannot name the `ON CONFLICT ... DO UPDATE` statement type without the public
//! [`diesel::helper_types`] aliases the impl composes it from.
//!
//! The watermark keys on `session_id` alone (R2): the connetto-minted durable
//! session handle from the verified access token. The watermark needs a stable
//! per-client handle, which is what a session is, and it does not need to know
//! who the client is, so the earlier `(user_id, session_id)` key carried an
//! identity column that only widened the schema contract. The whole
//! `INSERT ... ON CONFLICT (session_id) DO UPDATE SET last_seq = GREATEST(...)`
//! statement is laundered as one executable associated type
//! ([`Upsert`](ConnettoWatermarkSchema::Upsert)), named concretely in the
//! impl through [`diesel::helper_types::Set`], [`diesel::helper_types::DoUpdate`],
//! and [`diesel::helper_types::OnConflict`]. `GREATEST(last_seq, <new seq>)`
//! binds the new sequence directly, which equals `EXCLUDED.last_seq` (that value
//! is exactly what would have been inserted), so the statement never has to name
//! the still-private `diesel::upsert::Excluded` type.

use connetto_core::SessionId;
use diesel::helper_types::{Filter, Limit, Select};
use diesel::query_dsl::methods::{FilterDsl, LimitDsl, SelectDsl};
use diesel::sql_types::BigInt;
use diesel::{BoolExpressionMethods as _, ExpressionMethods as _};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::methods::{ExecuteDsl, LoadQuery as AsyncLoadQuery};

diesel::define_sql_function! {
    /// SQL `GREATEST` over two `BigInt` operands, used for the monotone
    /// watermark advance so a replayed lower sequence never lowers the mark.
    fn greatest(a: BigInt, b: BigInt) -> BigInt;
}

/// The watermark table, its `last_seq` column, and the pre-built upsert
/// [`PgWriteTarget`](crate::write_target::PgWriteTarget) keys exactly-once on.
///
/// Every associated table and column member derives `Default` (as
/// `diesel::table!` output does), so the write target constructs each marker
/// with `T::default()`. The `fn` members build the pieces that carry runtime
/// data or need special SQL.
pub trait ConnettoWatermarkSchema
where
    // The plain `SELECT last_seq WHERE session_id = ?` read. Laundered query
    // source plus opaque predicate, so filtering does not route through the
    // delegating blanket `impl<T: QueryRelation> FilterDsl for T` whose
    // `Output` never terminates for an opaque type.
    Self::WatermarkQuery: FilterDsl<Self::WmPk>,
    Filter<Self::WatermarkQuery, Self::WmPk>: SelectDsl<Self::LastSeq>,
    Select<Filter<Self::WatermarkQuery, Self::WmPk>, Self::LastSeq>: LimitDsl,
    for<'q> Limit<Select<Filter<Self::WatermarkQuery, Self::WmPk>, Self::LastSeq>>:
        AsyncLoadQuery<'q, AsyncPgConnection, i64> + Send,
{
    /// The deployment's typed distributed user id. Not a watermark column: it
    /// types the [`AuthContext`](connetto_core::auth::AuthContext) the write
    /// target binds as the RLS `app.user_id` GUC during a commit.
    type Id: Clone + core::fmt::Display + Send + Sync + 'static;

    /// The watermark table laundered as an opaque query source for the plain
    /// SELECT (concretely the table, but not declared `Table`/`QueryRelation`).
    type WatermarkQuery: Default + Send;
    /// The `last_seq` column (`BigInt`), the SELECT target.
    type LastSeq: diesel::Expression<SqlType = BigInt> + Default + Send;
    /// The opaque `session_id = ?` predicate.
    type WmPk: Send;

    /// The whole `INSERT ... ON CONFLICT (session_id) DO UPDATE SET
    /// last_seq = GREATEST(last_seq, <new seq>)` statement, laundered as one
    /// executable value. Named concretely in the impl via the
    /// [`diesel::helper_types`] upsert aliases so the diesel on-conflict
    /// internals never surface generically.
    type Upsert: ExecuteDsl<AsyncPgConnection> + Send;

    /// Build the monotone upsert for `session_id` at `last_seq`.
    fn watermark_upsert(session_id: SessionId, last_seq: i64) -> Self::Upsert;
    /// Build the `session_id = ?` predicate.
    fn wm_pk(session_id: SessionId) -> Self::WmPk;
    /// The table's SQL name, for the startup shape check.
    fn table_name() -> &'static str;
}

diesel::table! {
    /// The Postgres catalog view of table columns, read only by the startup
    /// watermark shape check.
    information_schema.columns (table_name, column_name) {
        table_name -> diesel::sql_types::Text,
        column_name -> diesel::sql_types::Text,
    }
}

diesel::table! {
    /// The Postgres catalog view of table constraints, read only by the
    /// startup watermark shape check.
    information_schema.table_constraints (constraint_name) {
        constraint_name -> diesel::sql_types::Text,
        table_name -> diesel::sql_types::Text,
        constraint_type -> diesel::sql_types::Text,
    }
}

/// The watermark table does not match the shape this build keys exactly-once
/// records on.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct WatermarkShapeError(pub String);

/// Refuse to run against a watermark table whose shape mismatches the trait.
///
/// connetto emits no server DDL, so the trait is the only contract, and an
/// unchecked contract lets a server run while mis-keying its exactly-once
/// records, a failure that stays silent until a replay happens. Same treatment
/// R6 gives `REPLICA IDENTITY`.
///
/// # Errors
///
/// [`WatermarkShapeError`] naming the missing table, a missing required
/// column, a leftover `user_id` column from the older two-column key, or a
/// foreign key from the older shape that pointed the watermark at the table of
/// logins.
pub async fn check_watermark_shape<W: ConnettoWatermarkSchema>(
    conn: &mut AsyncPgConnection,
) -> Result<(), WatermarkShapeError> {
    let table = W::table_name();
    let filtered = FilterDsl::filter(columns::table, columns::table_name.eq(table));
    let query = SelectDsl::select(filtered, columns::column_name);
    let names: Vec<String> = query
        .load(conn)
        .await
        .map_err(|err| WatermarkShapeError(format!("reading the shape of {table}: {err}")))?;
    if names.is_empty() {
        return Err(WatermarkShapeError(format!(
            "the watermark table {table} does not exist: create it as \
             (session_id UUID PRIMARY KEY, last_seq BIGINT NOT NULL)"
        )));
    }
    for required in ["session_id", "last_seq"] {
        if !names.iter().any(|name| name == required) {
            return Err(WatermarkShapeError(format!(
                "the watermark table {table} has no {required} column, expected \
                 (session_id UUID PRIMARY KEY, last_seq BIGINT NOT NULL)"
            )));
        }
    }
    if names.iter().any(|name| name == "user_id") {
        return Err(WatermarkShapeError(format!(
            "the watermark table {table} still carries a user_id column: the \
             watermark keys on session_id alone, so drop it"
        )));
    }
    // Every run has a handle, and only a login has a row in the table of
    // logins, so a foreign key from here into that table breaks the first write
    // by a caller with no identity. It is dropped rather than widened because
    // the watermark does not need to know who the caller is.
    let constrained = FilterDsl::filter(
        table_constraints::table,
        table_constraints::table_name
            .eq(table)
            .and(table_constraints::constraint_type.eq("FOREIGN KEY")),
    );
    let foreign_keys: Vec<String> =
        SelectDsl::select(constrained, table_constraints::constraint_name)
            .load(conn)
            .await
            .map_err(|err| {
                WatermarkShapeError(format!("reading the constraints on {table}: {err}"))
            })?;
    if let Some(name) = foreign_keys.into_iter().next() {
        return Err(WatermarkShapeError(format!(
            "the watermark table {table} has the foreign key {name}: a caller with no \
             identity has a handle but no row in the table of logins, so drop it"
        )));
    }
    Ok(())
}

/// Generate the default connetto watermark table and its
/// [`ConnettoWatermarkSchema`] impl, parameterized by the deployment's `Id`
/// type (the identity the write target binds for RLS, not a watermark column).
///
/// This is a convenience default only: the table is the deployment's to define
/// however it likes (a different name, extra columns), and
/// [`ConnettoWatermarkSchema`] is the real contract, implementable by hand
/// against any table. The reference SQL is in
/// `docs/architecture/11-authentication.md`.
///
/// Invoked at module scope, it emits the `_connetto_mutations` `diesel::table!`
/// module, an insertable row struct, and a unit struct `ConnettoWatermark`
/// implementing the trait. The caller needs `diesel` in scope.
///
/// ```ignore
/// connetto_server::connetto_watermark_table!(String);
/// // now `ConnettoWatermark` implements `ConnettoWatermarkSchema`.
/// ```
#[macro_export]
macro_rules! connetto_watermark_table {
    ($id:ty) => {
        diesel::table! {
            /// The durable per-session mutation watermark: the connetto-minted
            /// session id and the highest client sequence durably applied for
            /// that session.
            _connetto_mutations (session_id) {
                session_id -> diesel::sql_types::Uuid,
                last_seq -> diesel::sql_types::BigInt,
            }
        }

        /// Insertable new-watermark row for [`ConnettoWatermark`].
        #[derive(diesel::Insertable)]
        #[diesel(table_name = _connetto_mutations)]
        pub struct ConnettoNewWatermark {
            session_id: $crate::SessionId,
            last_seq: i64,
        }

        /// The default connetto watermark schema over the deployment's `Id` type.
        #[derive(Debug, Clone, Copy, Default)]
        pub struct ConnettoWatermark;

        impl $crate::watermark_schema::ConnettoWatermarkSchema for ConnettoWatermark {
            type Id = $id;
            type WatermarkQuery = _connetto_mutations::table;
            type LastSeq = _connetto_mutations::last_seq;
            type WmPk = diesel::dsl::Eq<_connetto_mutations::session_id, $crate::SessionId>;
            type Upsert = diesel::helper_types::Set<
                diesel::helper_types::DoUpdate<
                    diesel::helper_types::OnConflict<
                        diesel::query_builder::InsertStatement<
                            _connetto_mutations::table,
                            <ConnettoNewWatermark as diesel::Insertable<_connetto_mutations::table>>::Values,
                        >,
                        _connetto_mutations::session_id,
                    >,
                >,
                diesel::dsl::Eq<
                    _connetto_mutations::last_seq,
                    $crate::watermark_schema::greatest<
                        _connetto_mutations::last_seq,
                        <i64 as diesel::expression::AsExpression<diesel::sql_types::BigInt>>::Expression,
                    >,
                >,
            >;

            fn watermark_upsert(
                session_id: $crate::SessionId,
                last_seq: i64,
            ) -> Self::Upsert {
                use diesel::ExpressionMethods as _;
                diesel::insert_into(_connetto_mutations::table)
                    .values(ConnettoNewWatermark {
                        session_id,
                        last_seq,
                    })
                    .on_conflict(_connetto_mutations::session_id)
                    .do_update()
                    .set(
                        _connetto_mutations::last_seq.eq($crate::watermark_schema::greatest(
                            _connetto_mutations::last_seq,
                            last_seq,
                        )),
                    )
            }
            fn wm_pk(session_id: $crate::SessionId) -> Self::WmPk {
                use diesel::ExpressionMethods as _;
                _connetto_mutations::session_id.eq(session_id)
            }
            fn table_name() -> &'static str {
                "_connetto_mutations"
            }
        }
    };
}
