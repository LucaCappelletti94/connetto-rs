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
use diesel_async::AsyncPgConnection;
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
        }
    };
}
