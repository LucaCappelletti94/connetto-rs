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

diesel::table! {
    /// File manifests: one row per (upload, uploader) pair.
    _cfs_manifests (file_id, uploaded_by) {
        /// 32-byte BLAKE3 file identity.
        file_id -> Bytea,
        /// Declared byte total (must equal the sum of chunk lengths).
        total_len -> BigInt,
        /// Running tally of PUT bytes, enforced against the ticket ceiling.
        accepted_bytes -> BigInt,
        /// Whether the manifest has been committed.
        committed -> Bool,
        /// Ticket caller identity.
        uploaded_by -> Text,
        /// When the intent was declared; used by the sweep grace window.
        created_at -> Timestamptz,
    }
}

diesel::table! {
    /// Per-chunk rows for each manifest.
    _cfs_manifest_chunks (file_id, uploaded_by, position) {
        /// Part of the composite foreign key to `_cfs_manifests`.
        file_id -> Bytea,
        /// Part of the composite foreign key to `_cfs_manifests`.
        uploaded_by -> Text,
        /// 0-based position in the chunk sequence.
        position -> Integer,
        /// BLAKE3 hash of the chunk bytes.
        chunk_hash -> Bytea,
        /// Declared byte length.
        chunk_len -> BigInt,
        /// True once the chunk is durably in the object store.
        stored -> Bool,
    }
}

diesel::table! {
    /// Per-hash chunk state registry.
    ///
    /// A hash is live while any `_cfs_manifest_chunks` row references it;
    /// liveness is derived and no counter is maintained.  The `state` column
    /// tracks the chunk's lifecycle: `pending` (declared at intent), `stored`
    /// (written to the object store), or `deleting` (marked for GC).
    _cfs_chunk_registry (chunk_hash) {
        /// BLAKE3 hash identifying the chunk object.
        chunk_hash -> Bytea,
        /// `pending` | `stored` | `deleting`
        state -> Text,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    _cfs_manifests,
    _cfs_manifest_chunks,
    _cfs_chunk_registry,
);

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

/// The default file-server schema over the `_cfs_` prefix tables.
///
/// Used by the crate's own tests, by `preflight`, and as the template for the
/// shipped DDL constant.  External deployments that need different table names
/// implement [`ConnettoFileSchema`] directly or invoke [`crate::connetto_file_tables!`]
/// with custom names.
pub struct DefaultFileSchema;

impl ConnettoFileSchema for DefaultFileSchema {
    type Manifests = _cfs_manifests::table;
    type ManifestChunks = _cfs_manifest_chunks::table;
    type ChunkRegistry = _cfs_chunk_registry::table;

    type ManifestsQuery = _cfs_manifests::table;
    type ManifestChunksQuery = _cfs_manifest_chunks::table;
    type ChunkRegistryQuery = _cfs_chunk_registry::table;

    type MColFileId = _cfs_manifests::columns::file_id;
    type MColCommitted = _cfs_manifests::columns::committed;
    type MColCreatedAt = _cfs_manifests::columns::created_at;
    type MColAcceptedBytes = _cfs_manifests::columns::accepted_bytes;

    type MCColFileId = _cfs_manifest_chunks::columns::file_id;
    type MCColPosition = _cfs_manifest_chunks::columns::position;
    type MCColChunkHash = _cfs_manifest_chunks::columns::chunk_hash;
    type MCColChunkLen = _cfs_manifest_chunks::columns::chunk_len;
    type MCColStored = _cfs_manifest_chunks::columns::stored;

    type CRColChunkHash = _cfs_chunk_registry::columns::chunk_hash;
    type CRColState = _cfs_chunk_registry::columns::state;

    type ManifestPkEq = helper_types::And<
        helper_types::Eq<_cfs_manifests::columns::file_id, Vec<u8>>,
        helper_types::Eq<_cfs_manifests::columns::uploaded_by, String>,
    >;
    type MCPkEq = helper_types::And<
        helper_types::Eq<_cfs_manifest_chunks::columns::file_id, Vec<u8>>,
        helper_types::Eq<_cfs_manifest_chunks::columns::uploaded_by, String>,
    >;
    type MCChunkHashEq = helper_types::Eq<_cfs_manifest_chunks::columns::chunk_hash, Vec<u8>>;
    type CRChunkHashEq = helper_types::Eq<_cfs_chunk_registry::columns::chunk_hash, Vec<u8>>;
    type CRStateEq = helper_types::Eq<_cfs_chunk_registry::columns::state, &'static str>;

    const MANIFESTS_SQL: &'static str = "_cfs_manifests";
    const MANIFEST_CHUNKS_SQL: &'static str = "_cfs_manifest_chunks";
    const CHUNK_REGISTRY_SQL: &'static str = "_cfs_chunk_registry";

    fn manifest_pk_eq(file_id: Vec<u8>, caller: String) -> Self::ManifestPkEq {
        _cfs_manifests::file_id
            .eq(file_id)
            .and(_cfs_manifests::uploaded_by.eq(caller))
    }

    fn mc_pk_eq(file_id: Vec<u8>, caller: String) -> Self::MCPkEq {
        _cfs_manifest_chunks::file_id
            .eq(file_id)
            .and(_cfs_manifest_chunks::uploaded_by.eq(caller))
    }

    fn mc_chunk_hash_eq(hash: Vec<u8>) -> Self::MCChunkHashEq {
        _cfs_manifest_chunks::chunk_hash.eq(hash)
    }

    fn cr_chunk_hash_eq(hash: Vec<u8>) -> Self::CRChunkHashEq {
        _cfs_chunk_registry::chunk_hash.eq(hash)
    }

    fn cr_state_eq_deleting() -> Self::CRStateEq {
        _cfs_chunk_registry::state.eq("deleting")
    }

    fn insert_manifest_stmt(
        file_id: Vec<u8>,
        total_len: i64,
        caller: String,
        at: chrono::DateTime<chrono::Utc>,
    ) -> impl QueryFragment<Pg> + QueryId + Send + 'static {
        diesel::insert_into(_cfs_manifests::table)
            .values((
                _cfs_manifests::file_id.eq(file_id),
                _cfs_manifests::total_len.eq(total_len),
                _cfs_manifests::accepted_bytes.eq(0_i64),
                _cfs_manifests::committed.eq(false),
                _cfs_manifests::uploaded_by.eq(caller),
                _cfs_manifests::created_at.eq(at),
            ))
            .on_conflict_do_nothing()
    }

    fn insert_registry_pending_batch_stmt(
        hashes: Vec<Vec<u8>>,
    ) -> impl QueryFragment<Pg> + QueryId + Send + 'static {
        diesel::insert_into(_cfs_chunk_registry::table)
            .values(
                hashes
                    .into_iter()
                    .map(|h| {
                        (
                            _cfs_chunk_registry::chunk_hash.eq(h),
                            _cfs_chunk_registry::state.eq("pending"),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
            .on_conflict_do_nothing()
    }

    fn lock_registry_rows_stmt(
        hashes: Vec<Vec<u8>>,
    ) -> impl for<'q> AsyncLoadQuery<'q, AsyncPgConnection, (Vec<u8>, String)> + Send + 'static
    {
        diesel::QueryDsl::select(
            diesel::QueryDsl::for_update(diesel::QueryDsl::order(
                diesel::QueryDsl::filter(
                    _cfs_chunk_registry::table,
                    _cfs_chunk_registry::chunk_hash.eq_any(hashes),
                ),
                _cfs_chunk_registry::chunk_hash.asc(),
            )),
            (_cfs_chunk_registry::chunk_hash, _cfs_chunk_registry::state),
        )
    }

    fn lock_sweep_rows_stmt(
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> impl for<'q> AsyncLoadQuery<'q, AsyncPgConnection, Vec<u8>> + Send + 'static {
        // A hash is live while any manifest_chunks row references it through a
        // committed or graced (created_at >= cutoff) manifest.  The join uses
        // both columns of the composite FK so uncommitted chunks from one caller
        // do not keep a hash live when a different caller's manifest is the only
        // graced reference.
        let surviving = diesel::dsl::exists(SelectDsl::select(
            diesel::QueryDsl::filter(
                diesel::QueryDsl::filter(
                    _cfs_manifest_chunks::table,
                    _cfs_manifest_chunks::chunk_hash.eq(_cfs_chunk_registry::chunk_hash),
                ),
                diesel::dsl::exists(SelectDsl::select(
                    diesel::QueryDsl::filter(
                        diesel::QueryDsl::filter(
                            diesel::QueryDsl::filter(
                                _cfs_manifests::table,
                                _cfs_manifests::file_id.eq(_cfs_manifest_chunks::file_id),
                            ),
                            _cfs_manifests::uploaded_by.eq(_cfs_manifest_chunks::uploaded_by),
                        ),
                        _cfs_manifests::committed
                            .eq(true)
                            .or(_cfs_manifests::created_at.ge(cutoff)),
                    ),
                    _cfs_manifests::file_id,
                )),
            ),
            _cfs_manifest_chunks::chunk_hash,
        ));
        diesel::QueryDsl::select(
            diesel::QueryDsl::for_update(diesel::QueryDsl::order(
                diesel::QueryDsl::filter(
                    diesel::QueryDsl::filter(
                        _cfs_chunk_registry::table,
                        _cfs_chunk_registry::state.ne("deleting"),
                    ),
                    diesel::dsl::not(surviving),
                ),
                _cfs_chunk_registry::chunk_hash.asc(),
            )),
            _cfs_chunk_registry::chunk_hash,
        )
    }

    fn lock_manifest_row_stmt(
        file_id: Vec<u8>,
        caller: String,
    ) -> impl for<'q> AsyncLoadQuery<'q, AsyncPgConnection, bool> + Send + 'static {
        diesel::QueryDsl::select(
            diesel::QueryDsl::for_update(diesel::QueryDsl::filter(
                diesel::QueryDsl::filter(
                    _cfs_manifests::table,
                    _cfs_manifests::file_id.eq(file_id),
                ),
                _cfs_manifests::uploaded_by.eq(caller),
            )),
            _cfs_manifests::committed,
        )
    }

    fn mark_chunk_stored_stmt(
        file_id: Vec<u8>,
        caller: String,
        hash: Vec<u8>,
        chunk_len: i64,
    ) -> impl QueryFragment<Pg> + QueryId + Send + 'static {
        diesel::update(diesel::QueryDsl::filter(
            diesel::QueryDsl::filter(
                diesel::QueryDsl::filter(
                    diesel::QueryDsl::filter(
                        diesel::QueryDsl::filter(
                            _cfs_manifest_chunks::table,
                            _cfs_manifest_chunks::file_id.eq(file_id),
                        ),
                        _cfs_manifest_chunks::uploaded_by.eq(caller),
                    ),
                    _cfs_manifest_chunks::chunk_hash.eq(hash),
                ),
                _cfs_manifest_chunks::chunk_len.eq(chunk_len),
            ),
            _cfs_manifest_chunks::stored.eq(false),
        ))
        .set(_cfs_manifest_chunks::stored.eq(true))
    }

    fn tally_bytes_stmt(
        file_id: Vec<u8>,
        caller: String,
        chunk_len: i64,
        allowed: i64,
    ) -> impl QueryFragment<Pg> + QueryId + Send + 'static {
        diesel::update(diesel::QueryDsl::filter(
            diesel::QueryDsl::filter(
                diesel::QueryDsl::filter(
                    _cfs_manifests::table,
                    _cfs_manifests::file_id.eq(file_id),
                ),
                _cfs_manifests::uploaded_by.eq(caller),
            ),
            _cfs_manifests::accepted_bytes.le(allowed),
        ))
        .set(_cfs_manifests::accepted_bytes.eq(_cfs_manifests::accepted_bytes + chunk_len))
    }

    fn mark_registry_stored_stmt(
        hash: Vec<u8>,
    ) -> impl QueryFragment<Pg> + QueryId + Send + 'static {
        diesel::update(diesel::QueryDsl::filter(
            diesel::QueryDsl::filter(
                _cfs_chunk_registry::table,
                _cfs_chunk_registry::chunk_hash.eq(hash),
            ),
            _cfs_chunk_registry::state.eq("pending"),
        ))
        .set(_cfs_chunk_registry::state.eq("stored"))
    }

    fn mark_manifest_committed_stmt(
        file_id: Vec<u8>,
        caller: String,
    ) -> impl QueryFragment<Pg> + QueryId + Send + 'static {
        diesel::update(diesel::QueryDsl::filter(
            diesel::QueryDsl::filter(
                diesel::QueryDsl::filter(
                    _cfs_manifests::table,
                    _cfs_manifests::file_id.eq(file_id),
                ),
                _cfs_manifests::uploaded_by.eq(caller),
            ),
            _cfs_manifests::committed.eq(false),
        ))
        .set(_cfs_manifests::committed.eq(true))
    }

    fn mark_unreferenced_deleting_stmt(
        hashes: Vec<Vec<u8>>,
    ) -> impl for<'q> AsyncLoadQuery<'q, AsyncPgConnection, Vec<u8>> + Send + 'static {
        diesel::update(diesel::QueryDsl::filter(
            diesel::QueryDsl::filter(
                diesel::QueryDsl::filter(
                    _cfs_chunk_registry::table,
                    _cfs_chunk_registry::chunk_hash.eq_any(hashes),
                ),
                _cfs_chunk_registry::state.ne("deleting"),
            ),
            diesel::dsl::not(diesel::dsl::exists(SelectDsl::select(
                diesel::QueryDsl::filter(
                    _cfs_manifest_chunks::table,
                    _cfs_manifest_chunks::chunk_hash.eq(_cfs_chunk_registry::chunk_hash),
                ),
                _cfs_manifest_chunks::chunk_hash,
            ))),
        ))
        .set(_cfs_chunk_registry::state.eq("deleting"))
        .returning(_cfs_chunk_registry::chunk_hash)
    }

    fn insert_chunk_rows_batch_stmt(
        file_id: Vec<u8>,
        caller: String,
        rows: Vec<(i32, Vec<u8>, i64)>,
    ) -> impl QueryFragment<Pg> + QueryId + Send + 'static {
        diesel::insert_into(_cfs_manifest_chunks::table)
            .values(
                rows.into_iter()
                    .map(|(pos, hash, len)| {
                        (
                            _cfs_manifest_chunks::file_id.eq(file_id.clone()),
                            _cfs_manifest_chunks::uploaded_by.eq(caller.clone()),
                            _cfs_manifest_chunks::position.eq(pos),
                            _cfs_manifest_chunks::chunk_hash.eq(hash),
                            _cfs_manifest_chunks::chunk_len.eq(len),
                            _cfs_manifest_chunks::stored.eq(false),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
            .on_conflict_do_nothing()
    }

    fn delete_registry_row_stmt(
        hash: Vec<u8>,
    ) -> impl QueryFragment<Pg> + QueryId + Send + 'static {
        diesel::delete(diesel::QueryDsl::filter(
            _cfs_chunk_registry::table,
            _cfs_chunk_registry::chunk_hash.eq(hash),
        ))
    }

    fn delete_orphaned_stmt(
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> impl for<'q> AsyncLoadQuery<'q, AsyncPgConnection, Vec<u8>> + Send + 'static {
        diesel::delete(diesel::QueryDsl::filter(
            diesel::QueryDsl::filter(_cfs_manifests::table, _cfs_manifests::committed.eq(false)),
            _cfs_manifests::created_at.lt(cutoff),
        ))
        .returning(_cfs_manifests::file_id)
    }

    fn all_unstored_chunk_hashes_stmt(
        file_id: Vec<u8>,
        caller: String,
    ) -> impl for<'q> AsyncLoadQuery<'q, AsyncPgConnection, Vec<u8>> + Send + 'static {
        diesel::QueryDsl::select(
            diesel::QueryDsl::filter(
                diesel::QueryDsl::filter(
                    diesel::QueryDsl::filter(
                        _cfs_manifest_chunks::table,
                        _cfs_manifest_chunks::file_id.eq(file_id),
                    ),
                    _cfs_manifest_chunks::uploaded_by.eq(caller),
                ),
                _cfs_manifest_chunks::stored.eq(false),
            ),
            _cfs_manifest_chunks::chunk_hash,
        )
    }

    fn any_committed_manifest_caller_stmt(
        file_id: Vec<u8>,
    ) -> impl for<'q> AsyncLoadQuery<'q, AsyncPgConnection, String> + Send + 'static {
        diesel::QueryDsl::select(
            diesel::QueryDsl::limit(
                diesel::QueryDsl::order(
                    diesel::QueryDsl::filter(
                        diesel::QueryDsl::filter(
                            _cfs_manifests::table,
                            _cfs_manifests::file_id.eq(file_id),
                        ),
                        _cfs_manifests::committed.eq(true),
                    ),
                    _cfs_manifests::uploaded_by.asc(),
                ),
                1,
            ),
            _cfs_manifests::uploaded_by,
        )
    }
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
                /// Declared byte total.
                total_len -> diesel::sql_types::BigInt,
                /// Running PUT tally.
                accepted_bytes -> diesel::sql_types::BigInt,
                /// Whether the manifest is committed.
                committed -> diesel::sql_types::Bool,
                /// Caller identity from the write ticket.
                uploaded_by -> diesel::sql_types::Text,
                /// Intent declaration timestamp.
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
                $manifests::file_id
                    .eq(file_id)
                    .and($manifests::uploaded_by.eq(caller))
            }
            fn mc_pk_eq(file_id: Vec<u8>, caller: String) -> Self::MCPkEq {
                $manifest_chunks::file_id
                    .eq(file_id)
                    .and($manifest_chunks::uploaded_by.eq(caller))
            }
            fn mc_chunk_hash_eq(hash: Vec<u8>) -> Self::MCChunkHashEq {
                $manifest_chunks::chunk_hash.eq(hash)
            }
            fn cr_chunk_hash_eq(hash: Vec<u8>) -> Self::CRChunkHashEq {
                $chunk_registry::chunk_hash.eq(hash)
            }
            fn cr_state_eq_deleting() -> Self::CRStateEq {
                $chunk_registry::state.eq("deleting")
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
                        $manifests::file_id.eq(file_id),
                        $manifests::total_len.eq(total_len),
                        $manifests::accepted_bytes.eq(0_i64),
                        $manifests::committed.eq(false),
                        $manifests::uploaded_by.eq(caller),
                        $manifests::created_at.eq(at),
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
                                    $chunk_registry::chunk_hash.eq(h),
                                    $chunk_registry::state.eq("pending"),
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
                            $chunk_registry::chunk_hash.eq_any(hashes),
                        ),
                        $chunk_registry::chunk_hash.asc(),
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
                            $manifest_chunks::chunk_hash.eq($chunk_registry::chunk_hash),
                        ),
                        diesel::dsl::exists(diesel::query_dsl::methods::SelectDsl::select(
                            diesel::QueryDsl::filter(
                                diesel::QueryDsl::filter(
                                    diesel::QueryDsl::filter(
                                        $manifests::table,
                                        $manifests::file_id.eq($manifest_chunks::file_id),
                                    ),
                                    $manifests::uploaded_by.eq($manifest_chunks::uploaded_by),
                                ),
                                $manifests::committed
                                    .eq(true)
                                    .or($manifests::created_at.ge(cutoff)),
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
                                $chunk_registry::state.ne("deleting"),
                            ),
                            diesel::dsl::not(surviving),
                        ),
                        $chunk_registry::chunk_hash.asc(),
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
                            $manifests::file_id.eq(file_id),
                        ),
                        $manifests::uploaded_by.eq(caller),
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
                diesel::update(
                    $manifest_chunks::table
                        .filter($manifest_chunks::file_id.eq(file_id))
                        .filter($manifest_chunks::uploaded_by.eq(caller))
                        .filter($manifest_chunks::chunk_hash.eq(hash))
                        .filter($manifest_chunks::chunk_len.eq(chunk_len))
                        .filter($manifest_chunks::stored.eq(false)),
                )
                .set($manifest_chunks::stored.eq(true))
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
                diesel::update(
                    $manifests::table
                        .filter($manifests::file_id.eq(file_id))
                        .filter($manifests::uploaded_by.eq(caller))
                        .filter($manifests::accepted_bytes.le(allowed)),
                )
                .set($manifests::accepted_bytes.eq($manifests::accepted_bytes + chunk_len))
            }
            fn mark_registry_stored_stmt(
                hash: Vec<u8>,
            ) -> impl diesel::query_builder::QueryFragment<diesel::pg::Pg>
            + diesel::query_builder::QueryId
            + Send
            + 'static {
                diesel::update(
                    $chunk_registry::table
                        .filter($chunk_registry::chunk_hash.eq(hash))
                        .filter($chunk_registry::state.eq("pending")),
                )
                .set($chunk_registry::state.eq("stored"))
            }
            fn mark_manifest_committed_stmt(
                file_id: Vec<u8>,
                caller: String,
            ) -> impl diesel::query_builder::QueryFragment<diesel::pg::Pg>
            + diesel::query_builder::QueryId
            + Send
            + 'static {
                diesel::update(
                    $manifests::table
                        .filter($manifests::file_id.eq(file_id))
                        .filter($manifests::uploaded_by.eq(caller))
                        .filter($manifests::committed.eq(false)),
                )
                .set($manifests::committed.eq(true))
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
                            $chunk_registry::chunk_hash.eq_any(hashes),
                        ),
                        $chunk_registry::state.ne("deleting"),
                    ),
                    diesel::dsl::not(diesel::dsl::exists(
                        diesel::query_dsl::methods::SelectDsl::select(
                            diesel::QueryDsl::filter(
                                $manifest_chunks::table,
                                $manifest_chunks::chunk_hash.eq($chunk_registry::chunk_hash),
                            ),
                            $manifest_chunks::chunk_hash,
                        ),
                    )),
                ))
                .set($chunk_registry::state.eq("deleting"))
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
                                    $manifest_chunks::file_id.eq(file_id.clone()),
                                    $manifest_chunks::uploaded_by.eq(caller.clone()),
                                    $manifest_chunks::position.eq(pos),
                                    $manifest_chunks::chunk_hash.eq(hash),
                                    $manifest_chunks::chunk_len.eq(len),
                                    $manifest_chunks::stored.eq(false),
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
                diesel::delete($chunk_registry::table.filter($chunk_registry::chunk_hash.eq(hash)))
            }
            fn delete_orphaned_stmt(
                cutoff: chrono::DateTime<chrono::Utc>,
            ) -> impl for<'q> diesel_async::methods::LoadQuery<
                'q,
                diesel_async::AsyncPgConnection,
                Vec<u8>,
            > + Send
            + 'static {
                diesel::delete(
                    $manifests::table
                        .filter($manifests::committed.eq(false))
                        .filter($manifests::created_at.lt(cutoff)),
                )
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
                                $manifest_chunks::file_id.eq(file_id),
                            ),
                            $manifest_chunks::uploaded_by.eq(caller),
                        ),
                        $manifest_chunks::stored.eq(false),
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
                                    $manifests::file_id.eq(file_id),
                                ),
                                $manifests::committed.eq(true),
                            ),
                            $manifests::uploaded_by.asc(),
                        ),
                        1,
                    ),
                    $manifests::uploaded_by,
                )
            }
        }
    };
}
