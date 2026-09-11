//! Deployment-facing schema contract for the file server's own tables.
//!
//! connetto-file-server owns no schema.  A deployment declares the three
//! table names (manifests, per-chunk rows, and the chunk state registry)
//! and implements [`ConnettoFileSchema`] for them, either by hand or through
//! the [`connetto_file_tables!`](crate::connetto_file_tables) convenience
//! macro.  Every database function in this crate is generic over this trait
//! so the deployment may choose any names without forking the library.
//!
//! The default invocation (`connetto_file_tables!()`) uses the `_cfs_`
//! prefix and is the one used by the crate's tests and the shipped DDL.

use diesel::helper_types;
use diesel::pg::Pg;
use diesel::prelude::*;
use diesel::query_builder::{QueryFragment, QueryId};
use diesel::query_dsl::methods::{FilterDsl, LimitDsl, OrderDsl, SelectDsl};
use diesel::sql_types::{BigInt, Bool, Bytea, Integer, Text, Timestamptz};
use diesel_async::AsyncPgConnection;
use diesel_async::methods::LoadQuery as AsyncLoadQuery;

/// A column usable in typed diesel expressions for table `Tab` with SQL type `St`.
pub trait FileSchemaColumn<Tab, St>:
    Column<Table = Tab> + Expression<SqlType = St> + Default + Send
{
}

impl<C, Tab, St> FileSchemaColumn<Tab, St> for C where
    C: Column<Table = Tab> + Expression<SqlType = St> + Default + Send
{
}

/// The three tables the file server writes its queries against.
///
/// A deployment implements this trait (typically via the
/// [`connetto_file_tables!`](crate::connetto_file_tables) macro) and every
/// database function in this crate is generic over it so the deployment may
/// choose any table names.
///
/// The associated types carry the concrete diesel table and column types; the
/// factory methods build typed diesel statements with runtime values.
///
/// # Type-solver shaping
///
/// Three shaping choices are forced by the diesel async trait solver to avoid
/// the E0275 overflow:
/// - All bounds live in one trait-level `where` clause.
/// - Plain SELECTs run against a laundered query source
///   ([`ManifestsQuery`](ConnettoFileSchema::ManifestsQuery), etc.) not
///   declared as `Table`/`QueryRelation`, so the blanket `FilterDsl` impl
///   does not route through an unbounded chain.
/// - Statement-returning factory methods use return-position `impl Trait`
///   rather than opaque associated types, so the diesel UPDATE / DELETE
///   internal type hierarchy never surfaces in the trait definition.
pub trait ConnettoFileSchema: Send + Sync + 'static
where
    // ---------------------------------------------------------------
    // Shape M1: SELECT file_id, committed FROM manifests
    //            WHERE file_id = ? AND uploaded_by = ?
    // ---------------------------------------------------------------
    Self::ManifestsQuery: FilterDsl<Self::ManifestPkEq>,
    helper_types::Filter<Self::ManifestsQuery, Self::ManifestPkEq>:
        SelectDsl<(Self::MColFileId, Self::MColCommitted)>,
    helper_types::Select<
        helper_types::Filter<Self::ManifestsQuery, Self::ManifestPkEq>,
        (Self::MColFileId, Self::MColCommitted),
    >: LimitDsl,
    for<'q> helper_types::Limit<
        helper_types::Select<
            helper_types::Filter<Self::ManifestsQuery, Self::ManifestPkEq>,
            (Self::MColFileId, Self::MColCommitted),
        >,
    >: AsyncLoadQuery<'q, AsyncPgConnection, (Vec<u8>, bool)> + Send,
    // ---------------------------------------------------------------
    // Shape MC1: SELECT chunk_hash, chunk_len FROM manifest_chunks
    //            WHERE file_id = ? AND uploaded_by = ? ORDER BY position
    // ---------------------------------------------------------------
    Self::ManifestChunksQuery: FilterDsl<Self::MCPkEq>,
    helper_types::Filter<Self::ManifestChunksQuery, Self::MCPkEq>: OrderDsl<Self::MCColPosition>,
    helper_types::Order<
        helper_types::Filter<Self::ManifestChunksQuery, Self::MCPkEq>,
        Self::MCColPosition,
    >: SelectDsl<(Self::MCColChunkHash, Self::MCColChunkLen)>,
    for<'q> helper_types::Select<
        helper_types::Order<
            helper_types::Filter<Self::ManifestChunksQuery, Self::MCPkEq>,
            Self::MCColPosition,
        >,
        (Self::MCColChunkHash, Self::MCColChunkLen),
    >: AsyncLoadQuery<'q, AsyncPgConnection, (Vec<u8>, i64)> + Send,
    // ---------------------------------------------------------------
    // Shape MC2: SELECT chunk_len WHERE file_id = ? AND uploaded_by = ?
    //            AND chunk_hash = ?
    // ---------------------------------------------------------------
    helper_types::Filter<Self::ManifestChunksQuery, Self::MCPkEq>: FilterDsl<Self::MCChunkHashEq>,
    helper_types::Filter<
        helper_types::Filter<Self::ManifestChunksQuery, Self::MCPkEq>,
        Self::MCChunkHashEq,
    >: SelectDsl<Self::MCColChunkLen>,
    helper_types::Select<
        helper_types::Filter<
            helper_types::Filter<Self::ManifestChunksQuery, Self::MCPkEq>,
            Self::MCChunkHashEq,
        >,
        Self::MCColChunkLen,
    >: LimitDsl,
    for<'q> helper_types::Limit<
        helper_types::Select<
            helper_types::Filter<
                helper_types::Filter<Self::ManifestChunksQuery, Self::MCPkEq>,
                Self::MCChunkHashEq,
            >,
            Self::MCColChunkLen,
        >,
    >: AsyncLoadQuery<'q, AsyncPgConnection, i64> + Send,
    // ---------------------------------------------------------------
    // Shape CR1: SELECT state FROM chunk_registry WHERE chunk_hash = ?
    // ---------------------------------------------------------------
    Self::ChunkRegistryQuery: FilterDsl<Self::CRChunkHashEq>,
    helper_types::Filter<Self::ChunkRegistryQuery, Self::CRChunkHashEq>:
        SelectDsl<Self::CRColState>,
    helper_types::Select<
        helper_types::Filter<Self::ChunkRegistryQuery, Self::CRChunkHashEq>,
        Self::CRColState,
    >: LimitDsl,
    for<'q> helper_types::Limit<
        helper_types::Select<
            helper_types::Filter<Self::ChunkRegistryQuery, Self::CRChunkHashEq>,
            Self::CRColState,
        >,
    >: AsyncLoadQuery<'q, AsyncPgConnection, String> + Send,
    // ---------------------------------------------------------------
    // Shape CR2: SELECT chunk_hash FROM chunk_registry WHERE state = 'deleting'
    // ---------------------------------------------------------------
    Self::ChunkRegistryQuery: FilterDsl<Self::CRStateEq>,
    helper_types::Filter<Self::ChunkRegistryQuery, Self::CRStateEq>:
        SelectDsl<Self::CRColChunkHash>,
    for<'q> helper_types::Select<
        helper_types::Filter<Self::ChunkRegistryQuery, Self::CRStateEq>,
        Self::CRColChunkHash,
    >: AsyncLoadQuery<'q, AsyncPgConnection, Vec<u8>> + Send,
{
    /// The manifests table.
    type Manifests: Table + QueryId + Default + Send + Sync + 'static;

    /// The `manifest_chunks` table.
    type ManifestChunks: Table + QueryId + Default + Send + Sync + 'static;

    /// The `chunk_registry` table.
    type ChunkRegistry: Table + QueryId + Default + Send + Sync + 'static;

    /// Manifests table as an opaque SELECT source.
    type ManifestsQuery: Default + Send;

    /// `manifest_chunks` table as an opaque SELECT source.
    type ManifestChunksQuery: Default + Send;

    /// `chunk_registry` table as an opaque SELECT source.
    type ChunkRegistryQuery: Default + Send;

    /// `manifests.file_id` (`BYTEA`).
    type MColFileId: FileSchemaColumn<Self::Manifests, Bytea>;
    /// `manifests.committed` (`BOOLEAN`).
    type MColCommitted: FileSchemaColumn<Self::Manifests, Bool>;
    /// `manifests.created_at` (`TIMESTAMPTZ`).
    type MColCreatedAt: FileSchemaColumn<Self::Manifests, Timestamptz>;
    /// `manifests.accepted_bytes` (`BIGINT`).
    type MColAcceptedBytes: FileSchemaColumn<Self::Manifests, BigInt>;

    /// `manifest_chunks.file_id` (`BYTEA`).
    type MCColFileId: FileSchemaColumn<Self::ManifestChunks, Bytea>;
    /// `manifest_chunks.position` (`INTEGER`).
    type MCColPosition: FileSchemaColumn<Self::ManifestChunks, Integer>;
    /// `manifest_chunks.chunk_hash` (`BYTEA`).
    type MCColChunkHash: FileSchemaColumn<Self::ManifestChunks, Bytea>;
    /// `manifest_chunks.chunk_len` (`BIGINT`).
    type MCColChunkLen: FileSchemaColumn<Self::ManifestChunks, BigInt>;
    /// `manifest_chunks.stored` (`BOOLEAN`).
    type MCColStored: FileSchemaColumn<Self::ManifestChunks, Bool>;

    /// `chunk_registry.chunk_hash` (`BYTEA`).
    type CRColChunkHash: FileSchemaColumn<Self::ChunkRegistry, Bytea>;
    /// `chunk_registry.state` (`TEXT`).
    type CRColState: FileSchemaColumn<Self::ChunkRegistry, Text>;

    /// Opaque `manifests.file_id = ? AND manifests.uploaded_by = ?` predicate.
    type ManifestPkEq: Send;
    /// Opaque `manifest_chunks.file_id = ? AND manifest_chunks.uploaded_by = ?` predicate.
    type MCPkEq: Send;
    /// Opaque `manifest_chunks.chunk_hash = ?` predicate.
    type MCChunkHashEq: Send;
    /// Opaque `chunk_registry.chunk_hash = ?` predicate.
    type CRChunkHashEq: Send;
    /// Opaque `chunk_registry.state = 'deleting'` predicate.
    type CRStateEq: Send;

    /// SQL name of the manifests table.
    const MANIFESTS_SQL: &'static str;
    /// SQL name of the `manifest_chunks` table.
    const MANIFEST_CHUNKS_SQL: &'static str;
    /// SQL name of the `chunk_registry` table.
    const CHUNK_REGISTRY_SQL: &'static str;

    /// Build `manifests.file_id = file_id AND manifests.uploaded_by = caller`.
    fn manifest_pk_eq(file_id: Vec<u8>, caller: String) -> Self::ManifestPkEq;
    /// Build `manifest_chunks.file_id = file_id AND manifest_chunks.uploaded_by = caller`.
    fn mc_pk_eq(file_id: Vec<u8>, caller: String) -> Self::MCPkEq;
    /// Build `manifest_chunks.chunk_hash = hash`.
    fn mc_chunk_hash_eq(hash: Vec<u8>) -> Self::MCChunkHashEq;
    /// Build `chunk_registry.chunk_hash = hash`.
    fn cr_chunk_hash_eq(hash: Vec<u8>) -> Self::CRChunkHashEq;
    /// Build `chunk_registry.state = 'deleting'`.
    fn cr_state_eq_deleting() -> Self::CRStateEq;

    /// Build `INSERT INTO manifests … ON CONFLICT DO NOTHING`.
    fn insert_manifest_stmt(
        file_id: Vec<u8>,
        total_len: i64,
        caller: String,
        at: chrono::DateTime<chrono::Utc>,
    ) -> impl QueryFragment<Pg> + QueryId + Send + 'static;

    /// Batch-insert registry rows (pending) for the given hashes in one statement.
    ///
    /// Runs `INSERT INTO chunk_registry (chunk_hash, state) VALUES (...) ON CONFLICT DO NOTHING`.
    /// Calling with an empty `hashes` slice is a no-op.
    fn insert_registry_pending_batch_stmt(
        hashes: Vec<Vec<u8>>,
    ) -> impl QueryFragment<Pg> + QueryId + Send + 'static;

    /// Lock the named registry rows in hash order and return their states.
    fn lock_registry_rows_stmt(
        hashes: Vec<Vec<u8>>,
    ) -> impl for<'q> AsyncLoadQuery<'q, AsyncPgConnection, (Vec<u8>, String)> + Send + 'static;

    /// Lock, in hash order, the registry rows whose only references will not
    /// survive this cutoff, so a sweep never blocks uploads of live content.
    fn lock_sweep_rows_stmt(
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> impl for<'q> AsyncLoadQuery<'q, AsyncPgConnection, Vec<u8>> + Send + 'static;

    /// Lock one manifest row and return its committed state.
    ///
    /// Filters by both `file_id` and `uploaded_by` so the lock is scoped to
    /// exactly the caller's row.  Returns an empty result if no row exists for
    /// this (`file_id`, `caller`) pair.
    fn lock_manifest_row_stmt(
        file_id: Vec<u8>,
        caller: String,
    ) -> impl for<'q> AsyncLoadQuery<'q, AsyncPgConnection, bool> + Send + 'static;

    /// Build `UPDATE manifest_chunks SET stored=TRUE WHERE file_id=? AND uploaded_by=?
    /// AND chunk_hash=? AND chunk_len=? AND stored=FALSE`.
    ///
    /// Binding both the composite FK and the declared length ties the stored
    /// mark to the exact row the PUT length check was derived from.
    fn mark_chunk_stored_stmt(
        file_id: Vec<u8>,
        caller: String,
        hash: Vec<u8>,
        chunk_len: i64,
    ) -> impl QueryFragment<Pg> + QueryId + Send + 'static;

    /// Build `UPDATE manifests SET accepted_bytes = accepted_bytes + chunk_len
    /// WHERE file_id=? AND uploaded_by=? AND accepted_bytes <= allowed`.
    fn tally_bytes_stmt(
        file_id: Vec<u8>,
        caller: String,
        chunk_len: i64,
        allowed: i64,
    ) -> impl QueryFragment<Pg> + QueryId + Send + 'static;

    /// Build `UPDATE chunk_registry SET state='stored' WHERE chunk_hash=? AND state='pending'`.
    fn mark_registry_stored_stmt(
        hash: Vec<u8>,
    ) -> impl QueryFragment<Pg> + QueryId + Send + 'static;

    /// Build `UPDATE manifests SET committed=TRUE WHERE file_id=? AND uploaded_by=?
    /// AND committed=FALSE`.
    fn mark_manifest_committed_stmt(
        file_id: Vec<u8>,
        caller: String,
    ) -> impl QueryFragment<Pg> + QueryId + Send + 'static;

    /// Mark locked, still-unreferenced registry rows `deleting` and return their hashes.
    fn mark_unreferenced_deleting_stmt(
        hashes: Vec<Vec<u8>>,
    ) -> impl for<'q> AsyncLoadQuery<'q, AsyncPgConnection, Vec<u8>> + Send + 'static;

    /// Batch-insert chunk rows in one statement.
    ///
    /// Each element of `rows` is `(position, chunk_hash, chunk_len)`.
    /// Runs `INSERT INTO manifest_chunks (...) VALUES (...) ON CONFLICT DO NOTHING`.
    /// Calling with an empty `rows` slice is a no-op.
    fn insert_chunk_rows_batch_stmt(
        file_id: Vec<u8>,
        caller: String,
        rows: Vec<(i32, Vec<u8>, i64)>,
    ) -> impl QueryFragment<Pg> + QueryId + Send + 'static;

    /// Build `DELETE FROM chunk_registry WHERE chunk_hash=?`.
    fn delete_registry_row_stmt(hash: Vec<u8>)
    -> impl QueryFragment<Pg> + QueryId + Send + 'static;

    /// Build `DELETE FROM manifests WHERE NOT committed AND created_at < cutoff RETURNING file_id`.
    ///
    /// The `RETURNING` clause is the reason this returns a loadable type: the
    /// DELETE and the file-id collection must be atomic, which rules out a
    /// separate SELECT-then-DELETE.
    fn delete_orphaned_stmt(
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> impl for<'q> AsyncLoadQuery<'q, AsyncPgConnection, Vec<u8>> + Send + 'static;

    /// Build `SELECT chunk_hash FROM manifest_chunks
    /// WHERE file_id = ? AND uploaded_by = ? AND stored = FALSE`.
    ///
    /// Returns one row per unsatisfied chunk for this manifest.  Used by the commit
    /// dedup check to find which chunk hashes still need store evidence.
    fn all_unstored_chunk_hashes_stmt(
        file_id: Vec<u8>,
        caller: String,
    ) -> impl for<'q> AsyncLoadQuery<'q, AsyncPgConnection, Vec<u8>> + Send + 'static;

    /// Returns the `uploaded_by` of the alphabetically first committed manifest for
    /// `file_id`, limited to one row.
    ///
    /// All committed manifests for one `file_id` carry identical chunk content because
    /// BLAKE3 identity is verified at commit, so any row is representative. Ordering by
    /// `uploaded_by ASC` makes the selection deterministic when multiple callers hold
    /// committed rows for the same file.
    fn any_committed_manifest_caller_stmt(
        file_id: Vec<u8>,
    ) -> impl for<'q> AsyncLoadQuery<'q, AsyncPgConnection, String> + Send + 'static;
}

/// Generate the file-server tables and their [`ConnettoFileSchema`] impl
/// under deployment-chosen names.
///
/// The zero-argument form uses the `_cfs_` prefix; the three-ident form
/// accepts table name identifiers.
///
/// ```ignore
/// connetto_file_tables!();  // default names
/// connetto_file_tables!(app_manifests, app_chunks, app_registry);
/// ```
#[macro_export]
macro_rules! connetto_file_tables {
    () => {
        $crate::connetto_file_tables!(_cfs_manifests, _cfs_manifest_chunks, _cfs_chunk_registry);
    };
    ($manifests:ident, $manifest_chunks:ident, $chunk_registry:ident) => {
        diesel::table! {
            /// File manifests table generated by `connetto_file_tables!`.
            $manifests (file_id, uploaded_by) {
                /// 32-byte BLAKE3 file identity.
                file_id -> diesel::sql_types::Bytea,
                /// Declared byte total, equal to the sum of the chunk lengths.
                total_len -> diesel::sql_types::BigInt,
                /// Running tally of PUT bytes, enforced against the ticket ceiling.
                accepted_bytes -> diesel::sql_types::BigInt,
                /// Whether the manifest is committed.
                committed -> diesel::sql_types::Bool,
                /// Caller identity from the write ticket.
                uploaded_by -> diesel::sql_types::Text,
                /// When the intent was declared, read by the sweep grace window.
                created_at -> diesel::sql_types::Timestamptz,
            }
        }

        diesel::table! {
            /// Per-chunk manifest rows generated by `connetto_file_tables!`.
            $manifest_chunks (file_id, uploaded_by, position) {
                /// Part of the composite foreign key to manifests.
                file_id -> diesel::sql_types::Bytea,
                /// Part of the composite foreign key to manifests.
                uploaded_by -> diesel::sql_types::Text,
                /// 0-based ordinal position.
                position -> diesel::sql_types::Integer,
                /// BLAKE3 hash of the chunk bytes.
                chunk_hash -> diesel::sql_types::Bytea,
                /// Declared byte length.
                chunk_len -> diesel::sql_types::BigInt,
                /// True once the chunk is durably in the object store.
                stored -> diesel::sql_types::Bool,
            }
        }

        diesel::table! {
            /// Per-hash chunk state registry generated by `connetto_file_tables!`.
            ///
            /// A hash is live while any manifest-chunk row references it, so liveness
            /// is derived and no counter is maintained.
            $chunk_registry (chunk_hash) {
                /// BLAKE3 hash identifying the chunk object.
                chunk_hash -> diesel::sql_types::Bytea,
                /// `pending` | `stored` | `deleting`
                state -> diesel::sql_types::Text,
            }
        }

        diesel::allow_tables_to_appear_in_same_query!(
            $manifests,
            $manifest_chunks,
            $chunk_registry,
        );

        /// The connetto file-server schema over the macro-chosen table names.
        pub struct ConnettoFileSchemaImpl;

        impl $crate::ConnettoFileSchema for ConnettoFileSchemaImpl {
            type Manifests = $manifests::table;
            type ManifestChunks = $manifest_chunks::table;
            type ChunkRegistry = $chunk_registry::table;

            type ManifestsQuery = $manifests::table;
            type ManifestChunksQuery = $manifest_chunks::table;
            type ChunkRegistryQuery = $chunk_registry::table;

            type MColFileId = $manifests::columns::file_id;
            type MColCommitted = $manifests::columns::committed;
            type MColCreatedAt = $manifests::columns::created_at;
            type MColAcceptedBytes = $manifests::columns::accepted_bytes;

            type MCColFileId = $manifest_chunks::columns::file_id;
            type MCColPosition = $manifest_chunks::columns::position;
            type MCColChunkHash = $manifest_chunks::columns::chunk_hash;
            type MCColChunkLen = $manifest_chunks::columns::chunk_len;
            type MCColStored = $manifest_chunks::columns::stored;

            type CRColChunkHash = $chunk_registry::columns::chunk_hash;
            type CRColState = $chunk_registry::columns::state;

            type ManifestPkEq = diesel::helper_types::And<
                diesel::helper_types::Eq<$manifests::columns::file_id, Vec<u8>>,
                diesel::helper_types::Eq<$manifests::columns::uploaded_by, String>,
            >;
            type MCPkEq = diesel::helper_types::And<
                diesel::helper_types::Eq<$manifest_chunks::columns::file_id, Vec<u8>>,
                diesel::helper_types::Eq<$manifest_chunks::columns::uploaded_by, String>,
            >;
            type MCChunkHashEq =
                diesel::helper_types::Eq<$manifest_chunks::columns::chunk_hash, Vec<u8>>;
            type CRChunkHashEq =
                diesel::helper_types::Eq<$chunk_registry::columns::chunk_hash, Vec<u8>>;
            type CRStateEq =
                diesel::helper_types::Eq<$chunk_registry::columns::state, &'static str>;

            const MANIFESTS_SQL: &'static str = stringify!($manifests);
            const MANIFEST_CHUNKS_SQL: &'static str = stringify!($manifest_chunks);
            const CHUNK_REGISTRY_SQL: &'static str = stringify!($chunk_registry);

            fn manifest_pk_eq(file_id: Vec<u8>, caller: String) -> Self::ManifestPkEq {
                diesel::BoolExpressionMethods::and(
                    diesel::ExpressionMethods::eq($manifests::file_id, file_id),
                    diesel::ExpressionMethods::eq($manifests::uploaded_by, caller),
                )
            }
            fn mc_pk_eq(file_id: Vec<u8>, caller: String) -> Self::MCPkEq {
                diesel::BoolExpressionMethods::and(
                    diesel::ExpressionMethods::eq($manifest_chunks::file_id, file_id),
                    diesel::ExpressionMethods::eq($manifest_chunks::uploaded_by, caller),
                )
            }
            fn mc_chunk_hash_eq(hash: Vec<u8>) -> Self::MCChunkHashEq {
                diesel::ExpressionMethods::eq($manifest_chunks::chunk_hash, hash)
            }
            fn cr_chunk_hash_eq(hash: Vec<u8>) -> Self::CRChunkHashEq {
                diesel::ExpressionMethods::eq($chunk_registry::chunk_hash, hash)
            }
            fn cr_state_eq_deleting() -> Self::CRStateEq {
                diesel::ExpressionMethods::eq($chunk_registry::state, "deleting")
            }
            fn insert_manifest_stmt(
                file_id: Vec<u8>,
                total_len: i64,
                caller: String,
                at: chrono::DateTime<chrono::Utc>,
            ) -> impl diesel::query_builder::QueryFragment<diesel::pg::Pg>
            + diesel::query_builder::QueryId
            + Send
            + 'static {
                diesel::insert_into($manifests::table)
                    .values((
                        diesel::ExpressionMethods::eq($manifests::file_id, file_id),
                        diesel::ExpressionMethods::eq($manifests::total_len, total_len),
                        diesel::ExpressionMethods::eq($manifests::accepted_bytes, 0_i64),
                        diesel::ExpressionMethods::eq($manifests::committed, false),
                        diesel::ExpressionMethods::eq($manifests::uploaded_by, caller),
                        diesel::ExpressionMethods::eq($manifests::created_at, at),
                    ))
                    .on_conflict_do_nothing()
            }
            fn insert_registry_pending_batch_stmt(
                hashes: Vec<Vec<u8>>,
            ) -> impl diesel::query_builder::QueryFragment<diesel::pg::Pg>
            + diesel::query_builder::QueryId
            + Send
            + 'static {
                diesel::insert_into($chunk_registry::table)
                    .values(
                        hashes
                            .into_iter()
                            .map(|h| {
                                (
                                    diesel::ExpressionMethods::eq($chunk_registry::chunk_hash, h),
                                    diesel::ExpressionMethods::eq(
                                        $chunk_registry::state,
                                        "pending",
                                    ),
                                )
                            })
                            .collect::<Vec<_>>(),
                    )
                    .on_conflict_do_nothing()
            }
            fn lock_registry_rows_stmt(
                hashes: Vec<Vec<u8>>,
            ) -> impl for<'q> diesel_async::methods::LoadQuery<
                'q,
                diesel_async::AsyncPgConnection,
                (Vec<u8>, String),
            > + Send
            + 'static {
                diesel::QueryDsl::select(
                    diesel::QueryDsl::for_update(diesel::QueryDsl::order(
                        diesel::QueryDsl::filter(
                            $chunk_registry::table,
                            diesel::ExpressionMethods::eq_any($chunk_registry::chunk_hash, hashes),
                        ),
                        diesel::ExpressionMethods::asc($chunk_registry::chunk_hash),
                    )),
                    ($chunk_registry::chunk_hash, $chunk_registry::state),
                )
            }
            fn lock_sweep_rows_stmt(
                cutoff: chrono::DateTime<chrono::Utc>,
            ) -> impl for<'q> diesel_async::methods::LoadQuery<
                'q,
                diesel_async::AsyncPgConnection,
                Vec<u8>,
            > + Send
            + 'static {
                let surviving = diesel::dsl::exists(diesel::query_dsl::methods::SelectDsl::select(
                    diesel::QueryDsl::filter(
                        diesel::QueryDsl::filter(
                            $manifest_chunks::table,
                            diesel::ExpressionMethods::eq(
                                $manifest_chunks::chunk_hash,
                                $chunk_registry::chunk_hash,
                            ),
                        ),
                        diesel::dsl::exists(diesel::query_dsl::methods::SelectDsl::select(
                            diesel::QueryDsl::filter(
                                diesel::QueryDsl::filter(
                                    diesel::QueryDsl::filter(
                                        $manifests::table,
                                        diesel::ExpressionMethods::eq(
                                            $manifests::file_id,
                                            $manifest_chunks::file_id,
                                        ),
                                    ),
                                    diesel::ExpressionMethods::eq(
                                        $manifests::uploaded_by,
                                        $manifest_chunks::uploaded_by,
                                    ),
                                ),
                                diesel::BoolExpressionMethods::or(
                                    diesel::ExpressionMethods::eq($manifests::committed, true),
                                    diesel::ExpressionMethods::ge($manifests::created_at, cutoff),
                                ),
                            ),
                            $manifests::file_id,
                        )),
                    ),
                    $manifest_chunks::chunk_hash,
                ));
                diesel::QueryDsl::select(
                    diesel::QueryDsl::for_update(diesel::QueryDsl::order(
                        diesel::QueryDsl::filter(
                            diesel::QueryDsl::filter(
                                $chunk_registry::table,
                                diesel::ExpressionMethods::ne($chunk_registry::state, "deleting"),
                            ),
                            diesel::dsl::not(surviving),
                        ),
                        diesel::ExpressionMethods::asc($chunk_registry::chunk_hash),
                    )),
                    $chunk_registry::chunk_hash,
                )
            }
            fn lock_manifest_row_stmt(
                file_id: Vec<u8>,
                caller: String,
            ) -> impl for<'q> diesel_async::methods::LoadQuery<
                'q,
                diesel_async::AsyncPgConnection,
                bool,
            > + Send
            + 'static {
                diesel::QueryDsl::select(
                    diesel::QueryDsl::for_update(diesel::QueryDsl::filter(
                        diesel::QueryDsl::filter(
                            $manifests::table,
                            diesel::ExpressionMethods::eq($manifests::file_id, file_id),
                        ),
                        diesel::ExpressionMethods::eq($manifests::uploaded_by, caller),
                    )),
                    $manifests::committed,
                )
            }
            fn mark_chunk_stored_stmt(
                file_id: Vec<u8>,
                caller: String,
                hash: Vec<u8>,
                chunk_len: i64,
            ) -> impl diesel::query_builder::QueryFragment<diesel::pg::Pg>
            + diesel::query_builder::QueryId
            + Send
            + 'static {
                diesel::update(diesel::QueryDsl::filter(
                    diesel::QueryDsl::filter(
                        diesel::QueryDsl::filter(
                            diesel::QueryDsl::filter(
                                diesel::QueryDsl::filter(
                                    $manifest_chunks::table,
                                    diesel::ExpressionMethods::eq(
                                        $manifest_chunks::file_id,
                                        file_id,
                                    ),
                                ),
                                diesel::ExpressionMethods::eq(
                                    $manifest_chunks::uploaded_by,
                                    caller,
                                ),
                            ),
                            diesel::ExpressionMethods::eq($manifest_chunks::chunk_hash, hash),
                        ),
                        diesel::ExpressionMethods::eq($manifest_chunks::chunk_len, chunk_len),
                    ),
                    diesel::ExpressionMethods::eq($manifest_chunks::stored, false),
                ))
                .set(diesel::ExpressionMethods::eq(
                    $manifest_chunks::stored,
                    true,
                ))
            }
            fn tally_bytes_stmt(
                file_id: Vec<u8>,
                caller: String,
                chunk_len: i64,
                allowed: i64,
            ) -> impl diesel::query_builder::QueryFragment<diesel::pg::Pg>
            + diesel::query_builder::QueryId
            + Send
            + 'static {
                diesel::update(diesel::QueryDsl::filter(
                    diesel::QueryDsl::filter(
                        diesel::QueryDsl::filter(
                            $manifests::table,
                            diesel::ExpressionMethods::eq($manifests::file_id, file_id),
                        ),
                        diesel::ExpressionMethods::eq($manifests::uploaded_by, caller),
                    ),
                    diesel::ExpressionMethods::le($manifests::accepted_bytes, allowed),
                ))
                .set(diesel::ExpressionMethods::eq(
                    $manifests::accepted_bytes,
                    $manifests::accepted_bytes + chunk_len,
                ))
            }
            fn mark_registry_stored_stmt(
                hash: Vec<u8>,
            ) -> impl diesel::query_builder::QueryFragment<diesel::pg::Pg>
            + diesel::query_builder::QueryId
            + Send
            + 'static {
                diesel::update(diesel::QueryDsl::filter(
                    diesel::QueryDsl::filter(
                        $chunk_registry::table,
                        diesel::ExpressionMethods::eq($chunk_registry::chunk_hash, hash),
                    ),
                    diesel::ExpressionMethods::eq($chunk_registry::state, "pending"),
                ))
                .set(diesel::ExpressionMethods::eq(
                    $chunk_registry::state,
                    "stored",
                ))
            }
            fn mark_manifest_committed_stmt(
                file_id: Vec<u8>,
                caller: String,
            ) -> impl diesel::query_builder::QueryFragment<diesel::pg::Pg>
            + diesel::query_builder::QueryId
            + Send
            + 'static {
                diesel::update(diesel::QueryDsl::filter(
                    diesel::QueryDsl::filter(
                        diesel::QueryDsl::filter(
                            $manifests::table,
                            diesel::ExpressionMethods::eq($manifests::file_id, file_id),
                        ),
                        diesel::ExpressionMethods::eq($manifests::uploaded_by, caller),
                    ),
                    diesel::ExpressionMethods::eq($manifests::committed, false),
                ))
                .set(diesel::ExpressionMethods::eq($manifests::committed, true))
            }
            fn mark_unreferenced_deleting_stmt(
                hashes: Vec<Vec<u8>>,
            ) -> impl for<'q> diesel_async::methods::LoadQuery<
                'q,
                diesel_async::AsyncPgConnection,
                Vec<u8>,
            > + Send
            + 'static {
                diesel::update(diesel::QueryDsl::filter(
                    diesel::QueryDsl::filter(
                        diesel::QueryDsl::filter(
                            $chunk_registry::table,
                            diesel::ExpressionMethods::eq_any($chunk_registry::chunk_hash, hashes),
                        ),
                        diesel::ExpressionMethods::ne($chunk_registry::state, "deleting"),
                    ),
                    diesel::dsl::not(diesel::dsl::exists(
                        diesel::query_dsl::methods::SelectDsl::select(
                            diesel::QueryDsl::filter(
                                $manifest_chunks::table,
                                diesel::ExpressionMethods::eq(
                                    $manifest_chunks::chunk_hash,
                                    $chunk_registry::chunk_hash,
                                ),
                            ),
                            $manifest_chunks::chunk_hash,
                        ),
                    )),
                ))
                .set(diesel::ExpressionMethods::eq(
                    $chunk_registry::state,
                    "deleting",
                ))
                .returning($chunk_registry::chunk_hash)
            }
            fn insert_chunk_rows_batch_stmt(
                file_id: Vec<u8>,
                caller: String,
                rows: Vec<(i32, Vec<u8>, i64)>,
            ) -> impl diesel::query_builder::QueryFragment<diesel::pg::Pg>
            + diesel::query_builder::QueryId
            + Send
            + 'static {
                diesel::insert_into($manifest_chunks::table)
                    .values(
                        rows.into_iter()
                            .map(|(pos, hash, len)| {
                                (
                                    diesel::ExpressionMethods::eq(
                                        $manifest_chunks::file_id,
                                        file_id.clone(),
                                    ),
                                    diesel::ExpressionMethods::eq(
                                        $manifest_chunks::uploaded_by,
                                        caller.clone(),
                                    ),
                                    diesel::ExpressionMethods::eq($manifest_chunks::position, pos),
                                    diesel::ExpressionMethods::eq(
                                        $manifest_chunks::chunk_hash,
                                        hash,
                                    ),
                                    diesel::ExpressionMethods::eq($manifest_chunks::chunk_len, len),
                                    diesel::ExpressionMethods::eq($manifest_chunks::stored, false),
                                )
                            })
                            .collect::<Vec<_>>(),
                    )
                    .on_conflict_do_nothing()
            }
            fn delete_registry_row_stmt(
                hash: Vec<u8>,
            ) -> impl diesel::query_builder::QueryFragment<diesel::pg::Pg>
            + diesel::query_builder::QueryId
            + Send
            + 'static {
                diesel::delete(diesel::QueryDsl::filter(
                    $chunk_registry::table,
                    diesel::ExpressionMethods::eq($chunk_registry::chunk_hash, hash),
                ))
            }
            fn delete_orphaned_stmt(
                cutoff: chrono::DateTime<chrono::Utc>,
            ) -> impl for<'q> diesel_async::methods::LoadQuery<
                'q,
                diesel_async::AsyncPgConnection,
                Vec<u8>,
            > + Send
            + 'static {
                diesel::delete(diesel::QueryDsl::filter(
                    diesel::QueryDsl::filter(
                        $manifests::table,
                        diesel::ExpressionMethods::eq($manifests::committed, false),
                    ),
                    diesel::ExpressionMethods::lt($manifests::created_at, cutoff),
                ))
                .returning($manifests::file_id)
            }
            fn all_unstored_chunk_hashes_stmt(
                file_id: Vec<u8>,
                caller: String,
            ) -> impl for<'q> diesel_async::methods::LoadQuery<
                'q,
                diesel_async::AsyncPgConnection,
                Vec<u8>,
            > + Send
            + 'static {
                diesel::QueryDsl::select(
                    diesel::QueryDsl::filter(
                        diesel::QueryDsl::filter(
                            diesel::QueryDsl::filter(
                                $manifest_chunks::table,
                                diesel::ExpressionMethods::eq($manifest_chunks::file_id, file_id),
                            ),
                            diesel::ExpressionMethods::eq($manifest_chunks::uploaded_by, caller),
                        ),
                        diesel::ExpressionMethods::eq($manifest_chunks::stored, false),
                    ),
                    $manifest_chunks::chunk_hash,
                )
            }
            fn any_committed_manifest_caller_stmt(
                file_id: Vec<u8>,
            ) -> impl for<'q> diesel_async::methods::LoadQuery<
                'q,
                diesel_async::AsyncPgConnection,
                String,
            > + Send
            + 'static {
                diesel::QueryDsl::select(
                    diesel::QueryDsl::limit(
                        diesel::QueryDsl::order(
                            diesel::QueryDsl::filter(
                                diesel::QueryDsl::filter(
                                    $manifests::table,
                                    diesel::ExpressionMethods::eq($manifests::file_id, file_id),
                                ),
                                diesel::ExpressionMethods::eq($manifests::committed, true),
                            ),
                            diesel::ExpressionMethods::asc($manifests::uploaded_by),
                        ),
                        1,
                    ),
                    $manifests::uploaded_by,
                )
            }
        }
    };
}

connetto_file_tables!();

/// The default file-server schema over the `_cfs_` prefix tables.
///
/// Used by the crate's own tests, by `preflight`, and as the template for the
/// shipped DDL constant.  External deployments that need different table names
/// implement [`ConnettoFileSchema`] directly or invoke [`crate::connetto_file_tables!`]
/// with custom names.
pub type DefaultFileSchema = ConnettoFileSchemaImpl;
