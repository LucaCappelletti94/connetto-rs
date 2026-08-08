//! The Subscription Materializer core.
//!
//! Session-agnostic: it wraps one `subql` [`SubscriptionEngine`] on the
//! pgoutput vehicle and exposes the primitives the session layer composes.
//!
//! The catalog is a generic (`DB`), so the engine can be driven by any schema
//! model that implements `subql`'s [`DatabaseLike`], from a runtime DDL parse
//! to a compile-time diesel schema. The write policy is a second generic (`W`):
//! which tables accept mutations and where each finds its version column live
//! behind [`WritableCatalog`], implemented per catalog rather than baked in.
//!
//! * [`Materializer::register`] / [`Materializer::unregister`] manage engine
//!   subscriptions keyed by a caller-chosen consumer id.
//! * [`Materializer::dispatch`] runs one CDC [`ChangeEvent`] through matching,
//!   folds the matched event into a `sqlite-diff-rs` patchset with
//!   [`pgoutput_patchset`], compresses it, and returns one [`MatchedPatch`]
//!   per notified consumer.
//! * [`Materializer::advance_cursor`] moves the per-`(session, subscription)`
//!   resume cursor. The session layer owns session ids, so cursor advancement
//!   lives above this core.
//! * [`Materializer::apply_mutation`] / [`Materializer::apply_diffset`] apply an
//!   inbound diffset through `subql`'s catalog-driven apply path.
//!
//! The write path (frame pairing, authorization, idempotency, replies) lives in
//! the session layer. This core supplies its schema-driven pieces: parse an
//! upload into ops, and probe a row for a stale-version conflict.
//!
//! See `docs/architecture/10-subscription-materializer.md`.

use std::collections::{HashMap, HashSet};

use connetto_core::messages::{BindValue, MutationPatch};
use connetto_core::write::{VersionColumn, WritableCatalog};
use diesel::query_builder::{BoxedSqlQuery, SqlQuery};
use diesel::sql_types::{BigInt, Binary, Double, Nullable, Text};
use diesel::{QueryableByName, SqliteConnection, sql_query};
use pg2sqlite::options::Pg2SqliteOptions;
use pg2sqlite::prelude::ReverseTranslator;
use sqlite_diff_rs::{
    ChangesetOp, DiffOps, Indirect, ParsedDiffSet, PatchDelete, PatchSet, PatchsetOp, SchemaWithPK,
    TableSchema, Value,
};
use sqlparser::dialect::{PostgreSqlDialect, SQLiteDialect};
use sqlparser::parser::Parser;
use subql::EventKind;
use subql::backend::{CdcEvent, Postgres, RowKind, ScalarKind, Value as PgValue};
use subql::emit::{WireTable, pgoutput_patchset, pgoutput_patchset_builder};
use subql::patchset::SqliteAdapter;
use subql::reexec::{ReExecEngine, ReExecQueryId, Registered};
use subql::visibility::WriteOp;
use subql::{
    AggAccumulator, AggSpec, AggValue, AggregateBootstrap, ChangeEvent, DatabaseLike, DefaultIds,
    OpaqueCheckpoint, ParserDB, SubscriptionEngine, SubscriptionId, SubscriptionRequest, TableId,
    TableLike, catalog_helpers,
};

use crate::oplog::ChangeRecord;

use diesel_async::AsyncPgConnection;
use subql::patchset::PgAdapter;

/// The wire `Value` flavor a parsed upload carries: owned text and blobs.
type WireValue = Value<String, Vec<u8>>;

/// Map a full uploaded row image to the canonical value shape the row view
/// hands to the authorization seam.
fn row_image(values: &[WireValue]) -> Vec<PgValue<Postgres>> {
    values.iter().map(crate::pk::from_wire).collect()
}

/// Zstd level for bulk payloads. Level 3 is the library default: a sound size
/// versus speed tradeoff for patchset-sized blobs.
const ZSTD_LEVEL: i32 = 3;

/// Failure surfaced by the materializer core.
#[derive(Debug, thiserror::Error)]
pub enum MaterializerError {
    /// The Postgres DDL handed to [`Materializer::new`] did not parse.
    #[error("catalog parse failed: {0}")]
    Catalog(String),
    /// `subql` rejected a subscription registration.
    #[error(transparent)]
    Register(#[from] subql::RegisterError),
    /// `subql` could not dispatch a CDC event.
    #[error(transparent)]
    Dispatch(#[from] subql::DispatchError),
    /// A resume-cursor advance was non-monotonic.
    #[error(transparent)]
    Cursor(#[from] subql::AdvanceCursorError),
    /// Folding an event into an outbound patchset failed.
    #[error("patchset emission failed: {0}")]
    Emit(String),
    /// An uploaded diffset could not be parsed.
    #[error("mutation upload could not be parsed: {0}")]
    Parse(String),
    /// A mutation targeted a table that is not a writable entity.
    #[error("table `{0}` does not accept mutations")]
    NotWritable(String),
    /// A mutation referenced a table or column absent from the catalog.
    #[error("mutation references unknown schema element: {0}")]
    SchemaMismatch(String),
    /// A version-bearing update or delete arrived without the prior version
    /// value the conflict check needs (an insert-only patchset, or an update
    /// that omitted its old image).
    #[error("mutation on `{0}` lacks the prior version needed to detect conflicts")]
    MissingVersion(String),
    /// Applying an inbound diffset against the target failed.
    #[error(transparent)]
    Apply(#[from] diesel::result::Error),
    /// Zstd compression or decompression of a bulk payload failed.
    #[error(transparent)]
    Compression(#[from] std::io::Error),
    /// The client's SQLite-dialect subscription query could not be reverse
    /// translated to Postgres for `subql`.
    #[error("subscription query translation failed: {0}")]
    Translate(String),
}

/// One matched, folded patch produced by [`Materializer::dispatch`].
///
/// Phase 2 shares one folded payload across every matched consumer (no
/// per-session authorization yet), so the bytes are cloned per consumer.
#[derive(Debug, Clone)]
pub struct MatchedPatch {
    /// Consumer the event notified. Maps back to a `(session, subscription)`
    /// in the session layer.
    pub consumer_id: u64,
    /// Zstd-compressed patchset bytes ready to frame as a bulk payload.
    pub payload_zstd: Vec<u8>,
    /// Resume cursor for this event (the source `PgLsn`, big-endian).
    pub cursor: Vec<u8>,
    /// Whether this payload is a synthesized departure notice: the row still
    /// exists and merely left this consumer's window. The session layer does
    /// not put one through the read filter, per R44.
    pub departure: bool,
}

/// A runtime version column: a column resolved by name at run time.
#[derive(Debug, Clone)]
pub struct RuntimeVersionColumn {
    name: String,
}

impl VersionColumn for RuntimeVersionColumn {
    fn name(&self) -> &str {
        &self.name
    }
}

/// A [`WritableCatalog`] declared at run time, layered over a DDL-parsed schema.
///
/// The schema (from the DDL) supplies column order and primary keys. This
/// declares, on top, which tables accept mutations and which of them carry a
/// version column, since neither is derivable from column shapes alone. Build it
/// with [`RuntimeWritableCatalog::builder`].
#[derive(Debug, Clone, Default)]
pub struct RuntimeWritableCatalog {
    writable: HashSet<String>,
    versions: HashMap<String, String>,
}

impl RuntimeWritableCatalog {
    /// Start declaring a runtime write policy.
    #[must_use]
    pub fn builder() -> RuntimeWritableCatalogBuilder {
        RuntimeWritableCatalogBuilder::default()
    }
}

impl WritableCatalog for RuntimeWritableCatalog {
    type Version = RuntimeVersionColumn;

    fn is_writable(&self, table: &str) -> bool {
        self.writable.contains(table)
    }

    fn version_column(&self, table: &str) -> Option<RuntimeVersionColumn> {
        self.versions
            .get(table)
            .map(|name| RuntimeVersionColumn { name: name.clone() })
    }
}

/// Builder for [`RuntimeWritableCatalog`].
#[derive(Debug, Clone, Default)]
pub struct RuntimeWritableCatalogBuilder {
    inner: RuntimeWritableCatalog,
}

impl RuntimeWritableCatalogBuilder {
    /// Declare `table` writable with no version column of its own. Its version
    /// lives in an ancestor whose op the same changeset carries.
    #[must_use]
    pub fn writable(mut self, table: impl Into<String>) -> Self {
        self.inner.writable.insert(table.into());
        self
    }

    /// Declare `table` writable and carrying its own version column named
    /// `version_column`. Version-bearing updates and deletes on this table are
    /// conflict-checked against that column.
    #[must_use]
    pub fn versioned(
        mut self,
        table: impl Into<String>,
        version_column: impl Into<String>,
    ) -> Self {
        let table = table.into();
        self.inner.writable.insert(table.clone());
        self.inner.versions.insert(table, version_column.into());
        self
    }

    /// Finish building.
    #[must_use]
    pub fn build(self) -> RuntimeWritableCatalog {
        self.inner
    }
}

/// One op parsed from a mutation upload, ready for the session write path.
#[derive(Debug, Clone)]
pub(crate) struct PlannedOp {
    /// Catalog id of the target table, naming the row the write check asks
    /// about.
    pub table_id: TableId,
    /// The verb, for the authorization check.
    pub op: WriteOp,
    /// The row the op writes, in catalog column order. An insert and a delete
    /// carry a full image. A changeset update carries the new value where the
    /// upload changed the column and the old one otherwise, so a column the
    /// upload left out of both slots reads as absent, the same residual an
    /// event carries under `REPLICA IDENTITY DEFAULT`.
    pub row: Vec<PgValue<Postgres>>,
    /// Present when this op must be conflict-checked (a version-bearing update
    /// or delete).
    pub conflict: Option<PlannedConflict>,
}

/// The read needed to detect a stale-version conflict for one op.
#[derive(Debug, Clone)]
pub(crate) struct PlannedConflict {
    /// Table carrying the version column.
    pub table: String,
    /// Version column name.
    pub version_column: String,
    /// The prior version value the client based its edit on.
    pub basis: WireValue,
    /// Primary-key column names, in order.
    pub pk_columns: Vec<String>,
    /// Primary-key values matching `pk_columns`.
    pub pk_values: Vec<WireValue>,
}

/// The parsed, schema-resolved ops of one mutation upload.
#[derive(Debug, Clone)]
pub(crate) struct WritePlan {
    /// Ops in upload order.
    pub ops: Vec<PlannedOp>,
}

/// The current server row for a conflicting op.
#[derive(Debug, Clone)]
pub(crate) struct ServerRow {
    /// The current version value, rendered as text.
    pub version: String,
    /// The current row as a JSON object.
    pub row_json: String,
}

/// Outcome of probing one op for a stale-version conflict.
#[derive(Debug, Clone)]
pub(crate) enum ConflictProbe {
    /// The client's basis matches the current server version. Safe to apply.
    Clear,
    /// The basis is stale, or the row is gone. Carries the current row when it
    /// still exists.
    Stale(Option<ServerRow>),
}

/// The products of registering a client's SQLite-dialect subscription: the
/// classified registration plus the Postgres translation it registered.
///
/// Every later server-side read of the subscription query, the snapshot
/// above all, must use [`pg_sql`](Self::pg_sql): the client dialect never
/// reaches a Postgres parser or connection.
pub struct SqliteRegistration {
    /// The classified registration.
    pub registration: Registration,
    /// The subscription query reverse translated to Postgres.
    pub pg_sql: String,
}

/// Outcome of registering a subscription.
pub enum Registration {
    /// A row subscription the engine maintains directly, keyed for CDC routing.
    Row(SubscriptionId),
    /// A captured single-table scalar aggregate the materializer must bootstrap
    /// and re-execute through a connector.
    Aggregate(AggregateCapture),
    /// A single-table delta aggregate the materializer maintains in-process by
    /// folding per-event deltas into a seeded accumulator (`COUNT`, `SUM`,
    /// `AVG`, and the variance and stddev family).
    DeltaAggregate(DeltaAggregateCapture),
}

/// A captured aggregate query awaiting bootstrap.
pub struct AggregateCapture {
    /// Engine-assigned id for the captured query.
    pub query_id: ReExecQueryId,
    /// Consumer that registered it.
    pub consumer_id: u64,
    /// SQL to run for the initial value and on each re-execution.
    pub sql: String,
    /// Decode hint for the scalar result.
    pub kind: ScalarKind,
}

/// A captured delta aggregate awaiting its bootstrap seed.
///
/// Unlike [`AggregateCapture`], the engine maintains this subscription directly
/// (it has a [`SubscriptionId`] and matches CDC events), and the materializer
/// folds the per-event [`AggDelta`](subql::AggDelta)s the engine produces into a running value.
/// The session seeds the initial value through the connector before folding.
pub struct DeltaAggregateCapture {
    /// Consumer that registered it, the key for the folded accumulator state.
    pub consumer_id: u64,
    /// Engine subscription id, for CDC routing and unregistration.
    pub subscription_id: SubscriptionId,
    /// Aggregate the accumulator computes.
    pub spec: AggSpec,
    /// Runnable seed query and its per-column decode kinds.
    pub bootstrap: AggregateBootstrap,
}

/// The result of dispatching one CDC event.
pub struct Dispatched {
    /// Row patches to fan out to matched consumers.
    pub patches: Vec<MatchedPatch>,
    /// Aggregate values that changed in-process (no re-execution needed).
    pub aggregates: Vec<AggregateChange>,
    /// Captured queries whose value must be re-executed through a connector,
    /// coalesced by `query_id`.
    pub triggers: Vec<PendingReExec>,
    /// Delta aggregate values folded in-process from this event's per-consumer
    /// [`AggDelta`](subql::AggDelta)s, ready to deliver to the owning session.
    pub delta_aggregates: Vec<DeltaAggregateChange>,
}

/// An aggregate value that changed in-process, ready to deliver.
pub struct AggregateChange {
    /// Captured query whose value changed.
    pub query_id: ReExecQueryId,
    /// Consumer that owns it.
    pub consumer_id: u64,
    /// The new value serialized as JSON.
    pub result_json: String,
    /// Resume cursor for the event that produced it.
    pub cursor: Vec<u8>,
}

/// A delta aggregate value the materializer folded for one consumer.
pub struct DeltaAggregateChange {
    /// Consumer that owns the folded accumulator.
    pub consumer_id: u64,
    /// The new folded value serialized as JSON.
    pub result_json: String,
}

/// A captured query needing re-execution against the backend.
pub struct PendingReExec {
    /// Captured query to re-execute.
    pub query_id: ReExecQueryId,
    /// Consumer that owns it.
    pub consumer_id: u64,
    /// SQL to run.
    pub sql: String,
    /// Decode hint for the scalar result.
    pub kind: ScalarKind,
    /// Resume cursor for the event that triggered it.
    pub cursor: Vec<u8>,
}

/// Bootstrap metadata retained per captured query.
struct ReExecMeta {
    sql: String,
    kind: ScalarKind,
}

/// Hosts one `subql` engine over a Postgres-flavored catalog on the pgoutput
/// vehicle ([`ChangeEvent`], the `pg_walstream` event type both matching and
/// emission consume), plus the write policy the mutation path consults.
pub struct Materializer<DB = ParserDB, W = RuntimeWritableCatalog>
where
    DB: DatabaseLike,
    W: WritableCatalog,
{
    engine: ReExecEngine<ChangeEvent, DefaultIds, DB>,
    write: W,
    reexec: HashMap<ReExecQueryId, ReExecMeta>,
    /// Per-consumer delta aggregate state, keyed by consumer id. Seeded by the
    /// session after bootstrap, then folded on each dispatched event.
    deltas: HashMap<u64, (AggSpec, AggAccumulator)>,
}

impl Materializer<ParserDB, RuntimeWritableCatalog> {
    /// Build a materializer over a Postgres DDL catalog with an empty write
    /// policy (no writable tables).
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Catalog`] when the DDL does not parse.
    ///
    /// # Examples
    ///
    /// ```
    /// use connetto_server::Materializer;
    ///
    /// let mut mat =
    ///     Materializer::new("CREATE TABLE orders (id INT PRIMARY KEY, quantity INT);")?;
    /// let registration = mat.register(1, "SELECT * FROM orders WHERE quantity > 0")?;
    /// assert!(matches!(registration, connetto_server::Registration::Row(_)));
    /// # Ok::<(), connetto_server::MaterializerError>(())
    /// ```
    pub fn new(pg_ddl: &str) -> Result<Self, MaterializerError> {
        Self::with_write_catalog(pg_ddl, RuntimeWritableCatalog::default())
    }
}

impl<W: WritableCatalog> Materializer<ParserDB, W> {
    /// Build a materializer over a Postgres DDL catalog and a write policy.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Catalog`] when the DDL does not parse.
    pub fn with_write_catalog(pg_ddl: &str, write: W) -> Result<Self, MaterializerError> {
        let catalog = ParserDB::parse::<PostgreSqlDialect>(pg_ddl)
            .map_err(|err| MaterializerError::Catalog(format!("{err:?}")))?;
        Ok(Self {
            engine: ReExecEngine::new(SubscriptionEngine::new(catalog, PostgreSqlDialect {})),
            write,
            reexec: HashMap::new(),
            deltas: HashMap::new(),
        })
    }

    /// Register a subscription from the client's SQLite-dialect `SELECT` and
    /// its bind values.
    ///
    /// The query is reverse translated to Postgres against this materializer's
    /// catalog with its `?` and `?N` placeholders mapped to `$N`, and the
    /// binds ride the registration natively as typed subql values, so no bind
    /// value is ever rendered into SQL text. The client speaks its native
    /// SQLite dialect, the same one it runs against its local replica, and the
    /// server owns translation because it owns the schema. The returned
    /// [`SqliteRegistration`] carries the translation for every later
    /// consumer of the query, the snapshot read above all.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Translate`] when the SQLite query does not parse
    /// or cannot be translated, and [`MaterializerError::Register`] when
    /// `subql` rejects the SELECT or the binds do not pair with its
    /// placeholders.
    pub fn register_sqlite(
        &mut self,
        consumer_id: u64,
        sqlite_sql: &str,
        binds: &[BindValue],
    ) -> Result<SqliteRegistration, MaterializerError> {
        let pg_sql = self.translate_subscription_sql(sqlite_sql)?;
        let request =
            SubscriptionRequest::new(consumer_id, pg_sql.as_str()).binds(wire_binds(binds));
        let registration = self.register_request(consumer_id, request)?;
        Ok(SqliteRegistration {
            registration,
            pg_sql,
        })
    }

    /// Reverse translate one SQLite-dialect `SELECT` into the Postgres SQL
    /// that `subql` parses, using this materializer's catalog for
    /// schema-aware translation. Placeholders translate as syntax, values
    /// never enter the SQL: SQLite `?` and `?N` become Postgres `$N`, with
    /// bare `?` numbered by SQLite's own assignment rule.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Translate`] when the query does not parse as a
    /// single SQLite statement or cannot be reverse translated (a named
    /// parameter form such as `:name` is one such case).
    pub fn translate_subscription_sql(
        &self,
        sqlite_sql: &str,
    ) -> Result<String, MaterializerError> {
        let mut statements = Parser::parse_sql(&SQLiteDialect {}, sqlite_sql)
            .map_err(|err| MaterializerError::Translate(format!("{err}")))?;
        if statements.len() != 1 {
            return Err(MaterializerError::Translate(
                "expected exactly one SQL statement".to_owned(),
            ));
        }
        let statement = statements.remove(0);
        let pg = statement
            .reverse_translate(self.engine.inner().database(), &Pg2SqliteOptions::default())
            .map_err(|err| MaterializerError::Translate(format!("{err}")))?;
        Ok(pg.to_string())
    }
}

/// Convert wire bind values into the typed subql values a
/// [`SubscriptionRequest`] carries. Total by construction: every wire variant
/// has a subql counterpart, blobs included, so a bind can only be refused by
/// the engine's own placeholder pairing.
fn wire_binds(binds: &[BindValue]) -> Vec<PgValue<Postgres>> {
    binds
        .iter()
        .map(|bind| match bind {
            BindValue::Null => PgValue::Null,
            BindValue::Integer(value) => PgValue::Int(*value),
            BindValue::Real(value) => PgValue::Float(*value),
            BindValue::Text(value) => PgValue::String(value.clone()),
            BindValue::Blob(bytes) => PgValue::Bytes(bytes.clone()),
        })
        .collect()
}

impl<DB, W> Materializer<DB, W>
where
    DB: DatabaseLike + 'static,
    W: WritableCatalog,
{
    /// The parsed catalog this materializer matches against.
    ///
    /// The visibility seam needs it to read column values off a change event,
    /// and it holds the row across an await, so it takes a clone at
    /// construction rather than reaching through the materializer's mutex.
    pub const fn catalog(&self) -> &DB {
        self.engine.inner().database()
    }

    /// Register a subscription for `consumer_id` from a SQL `SELECT`.
    ///
    /// A row subscription returns [`Registration::Row`] with its
    /// [`SubscriptionId`]. A delta aggregate the engine maintains from row
    /// images (`COUNT`, `SUM`, `AVG`, variance, stddev) returns
    /// [`Registration::DeltaAggregate`], which the caller seeds through a
    /// connector and then folds. A single-table scalar MIN or MAX the engine
    /// cannot maintain returns [`Registration::Aggregate`], which the caller
    /// bootstraps and re-executes.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Register`] when `subql` rejects the SELECT.
    pub fn register(
        &mut self,
        consumer_id: u64,
        select_sql: &str,
    ) -> Result<Registration, MaterializerError> {
        self.register_request(
            consumer_id,
            SubscriptionRequest::new(consumer_id, select_sql),
        )
    }

    /// Register one built [`SubscriptionRequest`], classifying the engine's
    /// answer into a [`Registration`].
    fn register_request(
        &mut self,
        consumer_id: u64,
        request: SubscriptionRequest<DefaultIds, Postgres>,
    ) -> Result<Registration, MaterializerError> {
        match self.engine.register(request)? {
            Registered::Engine(result) => match result.aggregate_spec() {
                Some(spec) => {
                    let spec = spec.clone();
                    let bootstrap = result
                        .aggregate_bootstrap
                        .clone()
                        .expect("aggregate registration carries a bootstrap");
                    Ok(Registration::DeltaAggregate(DeltaAggregateCapture {
                        consumer_id,
                        subscription_id: result.subscription_id,
                        spec,
                        bootstrap,
                    }))
                }
                None => Ok(Registration::Row(result.subscription_id)),
            },
            Registered::ReExec {
                query_id,
                sql,
                column_kind,
            } => {
                self.reexec.insert(
                    query_id,
                    ReExecMeta {
                        sql: sql.clone(),
                        kind: column_kind,
                    },
                );
                Ok(Registration::Aggregate(AggregateCapture {
                    query_id,
                    consumer_id,
                    sql,
                    kind: column_kind,
                }))
            }
        }
    }

    /// Drop a row subscription. Returns whether it existed.
    pub fn unregister(&mut self, sub_id: SubscriptionId) -> bool {
        self.engine.inner_mut().unregister_subscription(sub_id)
    }

    /// Drop a captured aggregate query. Returns whether it existed.
    pub fn unregister_aggregate(&mut self, query_id: ReExecQueryId) -> bool {
        self.reexec.remove(&query_id);
        self.engine.unregister_reexec_query(query_id)
    }

    /// Install a bootstrapped or re-executed scalar value for a captured query.
    /// Returns whether the query exists.
    pub fn install_scalar(&mut self, query_id: ReExecQueryId, value: PgValue<Postgres>) -> bool {
        self.engine.install(query_id, value)
    }

    /// Seed a delta aggregate's accumulator for `consumer_id`.
    ///
    /// Called once after the session bootstraps the initial value through the
    /// connector. Later [`dispatch`](Self::dispatch) calls fold each event's
    /// [`AggDelta`](subql::AggDelta) into this accumulator.
    pub fn install_aggregate(&mut self, consumer_id: u64, spec: AggSpec, acc: AggAccumulator) {
        self.deltas.insert(consumer_id, (spec, acc));
    }

    /// Drop a delta aggregate: its folded accumulator and its engine
    /// subscription. Returns whether the subscription existed.
    pub fn unregister_delta_aggregate(&mut self, consumer_id: u64, sub_id: SubscriptionId) -> bool {
        self.deltas.remove(&consumer_id);
        self.engine.inner_mut().unregister_subscription(sub_id)
    }

    /// Dispatch one CDC event into row patches, in-process aggregate changes,
    /// and re-execution triggers.
    ///
    /// Row notifications fold once into a compressed patchset shared across the
    /// matched consumers. Scalar aggregates maintained in-process surface as
    /// [`AggregateChange`]s. Captured queries the engine could not resolve
    /// surface as [`PendingReExec`] triggers, coalesced by `query_id`, for the
    /// caller to service through a connector.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Dispatch`] on a dispatch failure,
    /// [`MaterializerError::Emit`] when the event cannot be folded, and
    /// [`MaterializerError::Compression`] on a compression failure.
    pub fn dispatch(&mut self, event: &ChangeEvent) -> Result<Dispatched, MaterializerError> {
        let notifications = self.engine.consumers(event)?;
        let cursor = event
            .checkpoint()
            .map(|lsn| lsn.0.to_be_bytes().to_vec())
            .unwrap_or_default();

        let aggregates = notifications
            .scalar_updates
            .iter()
            .map(|update| AggregateChange {
                query_id: update.query_id,
                consumer_id: update.consumer_id,
                result_json: value_to_json(&update.value),
                cursor: cursor.clone(),
            })
            .collect();

        let mut seen = HashSet::new();
        let mut triggers = Vec::new();
        for trigger in &notifications.triggers {
            if !seen.insert(trigger.query_id) {
                continue;
            }
            if let Some(meta) = self.reexec.get(&trigger.query_id) {
                triggers.push(PendingReExec {
                    query_id: trigger.query_id,
                    consumer_id: trigger.consumer_id,
                    sql: meta.sql.clone(),
                    kind: meta.kind,
                    cursor: cursor.clone(),
                });
            }
        }

        let engine = &notifications.engine;
        // A consumer the engine reports as deleted on an UPDATE did not lose
        // the row, the row left its window. On a DELETE the same list means the
        // row is genuinely gone, which is what makes the event kind the
        // discriminant rather than the list alone.
        let departing: HashSet<u64> = if matches!(event.kind(), EventKind::Update) {
            engine.deleted().iter().copied().collect()
        } else {
            HashSet::new()
        };
        let mut consumers: Vec<u64> = Vec::new();
        consumers.extend_from_slice(engine.inserted());
        consumers.extend_from_slice(engine.updated());
        consumers.extend_from_slice(engine.deleted());
        consumers.sort_unstable();
        consumers.dedup();
        let patches = if consumers.is_empty() {
            Vec::new()
        } else {
            let built = pgoutput_patchset_builder(
                self.engine.inner().database(),
                std::slice::from_ref(event),
            )
            .map_err(|err| MaterializerError::Emit(format!("{err}")))?;
            // One extra encode on an event that has departures, not one per
            // departing consumer: the notice carries a table and a primary key
            // and nothing consumer-specific, so every consumer that lost this
            // row receives the same bytes.
            let departure = if departing.is_empty() {
                None
            } else {
                Self::departure_patchset(&built)
                    .map(|bytes| compress(&bytes))
                    .transpose()?
            };
            let payload = compress(&built.build())?;
            // Fallible only in theory: usize to u64 cannot lose on any
            // supported pointer width, and a counter saturates rather than
            // panics regardless.
            let payload_len = u64::try_from(payload.len()).unwrap_or(u64::MAX);
            consumers
                .into_iter()
                .map(|consumer_id| {
                    let leaving = departing.contains(&consumer_id);
                    let bytes = match (leaving, departure.as_ref()) {
                        (true, Some(notice)) => notice.clone(),
                        _ => payload.clone(),
                    };
                    crate::counters::add(&crate::counters::FANOUT_PAYLOAD_BYTES, payload_len);
                    MatchedPatch {
                        consumer_id,
                        payload_zstd: bytes,
                        cursor: cursor.clone(),
                        departure: leaving && departure.is_some(),
                    }
                })
                .collect()
        };

        // Fold this event's per-consumer deltas into the seeded accumulators.
        // Skip the engine call entirely when no delta aggregate is installed,
        // which is the common case and avoids a spurious error path for events
        // the aggregate machinery treats specially (e.g. Truncate).
        let delta_aggregates = if self.deltas.is_empty() {
            Vec::new()
        } else {
            let deltas = self.engine.inner_mut().aggregate_deltas(event)?;
            let mut changes = Vec::with_capacity(deltas.len());
            for (consumer_id, delta) in deltas {
                if let Some((_, acc)) = self.deltas.get_mut(&consumer_id) {
                    acc.apply(&delta);
                    changes.push(DeltaAggregateChange {
                        consumer_id,
                        result_json: agg_value_to_json(acc.value()),
                    });
                }
            }
            changes
        };

        Ok(Dispatched {
            patches,
            aggregates,
            triggers,
            delta_aggregates,
        })
    }

    /// Build the oplog record for a dispatched CDC event.
    ///
    /// Resolves the table name and a stable primary-key encoding from the
    /// catalog once, so the oplog and the catchup auth filter carry them without
    /// a second catalog pass. Returns `None` when the event carries no checkpoint
    /// or its table is absent from the catalog. Call only after
    /// [`dispatch`](Self::dispatch) has accepted the event, which guarantees it
    /// is a row event.
    #[must_use]
    pub fn oplog_record(&self, event: &ChangeEvent) -> Option<ChangeRecord> {
        let lsn = event.checkpoint()?.0;
        let (table, pk) = self.event_identity(event)?;
        Some(ChangeRecord::new(lsn, table, pk, event.clone()))
    }

    /// The catchup payload for one consumer, and whether it is a departure.
    ///
    /// `None` when the event never matched this consumer. Replaces asking for
    /// the matched set and the payload separately, which took two engine calls
    /// and could not tell a departure from a removal because the merged list
    /// does not carry the distinction.
    ///
    /// Runs the same predicate matching the live path uses, but only through
    /// the core engine, so it folds no aggregates and fires no re-execution
    /// triggers. A departure is recomputed here rather than stored: matching is
    /// a pure function of the event's row images, so replay reaches the same
    /// three lists the live path did and classifies the same way. Live and replay
    /// therefore cannot disagree, whatever either can determine.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Dispatch`] when the event cannot be matched,
    /// [`MaterializerError::Emit`] when it cannot be folded, and
    /// [`MaterializerError::Compression`] on a compression failure.
    pub fn replay_patch(
        &mut self,
        event: &ChangeEvent,
        consumer_id: u64,
    ) -> Result<Option<(Vec<u8>, bool)>, MaterializerError> {
        let (matched, departing) = {
            let notifs = self.engine.inner_mut().consumers(event)?;
            let departing = matches!(event.kind(), EventKind::Update)
                && notifs.deleted().contains(&consumer_id);
            let matched = notifs.inserted().contains(&consumer_id)
                || notifs.updated().contains(&consumer_id)
                || notifs.deleted().contains(&consumer_id);
            (matched, departing)
        };
        if !matched {
            return Ok(None);
        }
        let built =
            pgoutput_patchset_builder(self.engine.inner().database(), std::slice::from_ref(event))
                .map_err(|err| MaterializerError::Emit(format!("{err}")))?;
        if departing && let Some(notice) = Self::departure_patchset(&built) {
            return Ok(Some((compress(&notice)?, true)));
        }
        Ok(Some((compress(&built.build())?, false)))
    }

    /// Fold one event into a compressed patchset, the catchup delivery payload.
    ///
    /// Identical to the row payload [`dispatch`](Self::dispatch) produces on the
    /// live path, so a replayed patch is indistinguishable from a live one.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Emit`] when the event cannot be folded, and
    /// [`MaterializerError::Compression`] on a compression failure.
    pub fn encode_patch(&self, event: &ChangeEvent) -> Result<Vec<u8>, MaterializerError> {
        let raw = pgoutput_patchset(self.engine.inner().database(), std::slice::from_ref(event))
            .map_err(|err| MaterializerError::Emit(format!("{err}")))?;
        Ok(compress(&raw)?)
    }

    /// A patchset carrying one delete for the row `built` describes, marked
    /// indirect.
    ///
    /// Indirect is the session format's own flag and this is the convention
    /// R44 puts on it: a server-synthesized indirect delete means the row left
    /// this subscription's window rather than being removed. The client applies
    /// it only when no surviving subscription still covers the row. A
    /// client-captured changeset keeps the flag's native trigger-caused
    /// meaning, which nothing here reads.
    ///
    /// Reads the table and key off the builder subql already filled, so the key
    /// is the very one the ordinary payload will carry. Deriving it from the
    /// event's typed values instead would mean a second mapping from Postgres
    /// values to storage classes, and a departure whose key disagreed with the
    /// row it must match would delete nothing.
    ///
    /// The bytes are the same for every consumer that lost the same row, so
    /// this is built once per event and cloned, exactly as the ordinary payload
    /// is.
    fn departure_patchset(built: &PatchSet<WireTable, String, Vec<u8>>) -> Option<Vec<u8>> {
        let op = built.iter().next()?;
        let bytes = PatchSet::<WireTable, String, Vec<u8>>::new()
            .delete(PatchDelete::new(op.table().clone(), op.primary_key()).indirect(true))
            .build();
        Some(bytes)
    }

    /// The `(table, primary-key bytes)` identity of a CDC event, for the auth
    /// read filter. Primary-key columns are read from the event's PK image and
    /// encoded by [`crate::pk`] into a stable, self-describing byte string the
    /// auth policy treats as opaque and decodes back into typed values.
    fn event_identity(&self, event: &ChangeEvent) -> Option<(String, Vec<u8>)> {
        let db = self.engine.inner().database();
        let table_id = event.table_id(db);
        let index = usize::try_from(table_id).ok()?;
        let table = db.table_by_id(index)?.table_name().to_owned();
        let mut values = Vec::new();
        for col in event.pk_columns(db) {
            values.push(event.value_at(db, RowKind::Pk, col).ok()?);
        }
        Some((table, crate::pk::encode(&values)))
    }

    /// Advance the resume cursor for `(session_id, sub_id)`.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Cursor`] when the advance would rewind the cursor.
    pub fn advance_cursor(
        &mut self,
        session_id: u64,
        sub_id: SubscriptionId,
        cursor: &[u8],
    ) -> Result<(), MaterializerError> {
        self.engine.inner_mut().advance_cursor(
            session_id,
            sub_id,
            OpaqueCheckpoint(cursor.to_vec()),
        )?;
        Ok(())
    }

    /// Parse a Zstd-compressed mutation upload into schema-resolved ops.
    ///
    /// Classifies each op, extracts its primary key and, for version-bearing
    /// updates and deletes, the read that detects a stale-version conflict.
    /// Rejects a mutation whose target table is not writable, or an update or
    /// delete uploaded as a patchset (patchsets carry no prior image, so a
    /// conflict cannot be detected).
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Compression`] when the payload does not decompress,
    /// [`MaterializerError::Parse`] when the bytes are not a diffset,
    /// [`MaterializerError::NotWritable`], [`MaterializerError::SchemaMismatch`],
    /// or [`MaterializerError::MissingVersion`].
    pub(crate) fn plan_write(&self, payload_zstd: &[u8]) -> Result<WritePlan, MaterializerError> {
        let bytes = decompress(payload_zstd)?;
        let parsed = ParsedDiffSet::parse(&bytes)
            .map_err(|err| MaterializerError::Parse(format!("{err}")))?;
        let mut ops = Vec::new();
        match parsed {
            ParsedDiffSet::Changeset(diff) => {
                for op in diff.iter() {
                    ops.push(self.plan_changeset_op(&op)?);
                }
            }
            ParsedDiffSet::Patchset(diff) => {
                for op in diff.iter() {
                    ops.push(self.plan_patchset_op(&op)?);
                }
            }
        }
        Ok(WritePlan { ops })
    }

    /// Resolve `table` in the catalog, or report the schema mismatch.
    fn table_id(&self, table: &str) -> Result<TableId, MaterializerError> {
        catalog_helpers::table_id(self.engine.inner().database(), table)
            .ok_or_else(|| MaterializerError::SchemaMismatch(table.to_owned()))
    }

    fn plan_changeset_op(
        &self,
        op: &ChangesetOp<'_, TableSchema<String>, String, Vec<u8>>,
    ) -> Result<PlannedOp, MaterializerError> {
        let schema = op.table();
        let table = schema.name().clone();
        if !self.write.is_writable(&table) {
            return Err(MaterializerError::NotWritable(table));
        }
        let table_id = self.table_id(&table)?;
        let pk_values = op.primary_key();
        let (verb, row, conflict) = match op {
            ChangesetOp::Insert { values, .. } => (WriteOp::Insert, row_image(values), None),
            ChangesetOp::Update { values, .. } => {
                let conflict = self.plan_conflict(schema, &pk_values, |idx| {
                    values.get(idx).and_then(|cell| cell.0.clone())
                })?;
                // New over old, so the row is the one the update leaves behind.
                let row = values
                    .iter()
                    .map(|(old, new)| match new.as_ref().or(old.as_ref()) {
                        Some(value) => crate::pk::from_wire(value),
                        None => PgValue::Missing,
                    })
                    .collect();
                (WriteOp::Update, row, conflict)
            }
            ChangesetOp::Delete { old_values, .. } => {
                let conflict =
                    self.plan_conflict(schema, &pk_values, |idx| old_values.get(idx).cloned())?;
                (WriteOp::Delete, row_image(old_values), conflict)
            }
        };
        Ok(PlannedOp {
            table_id,
            op: verb,
            row,
            conflict,
        })
    }

    fn plan_patchset_op(
        &self,
        op: &PatchsetOp<'_, TableSchema<String>, String, Vec<u8>>,
    ) -> Result<PlannedOp, MaterializerError> {
        let table = op.table().name().clone();
        if !self.write.is_writable(&table) {
            return Err(MaterializerError::NotWritable(table));
        }
        match op {
            PatchsetOp::Insert { values, .. } => Ok(PlannedOp {
                table_id: self.table_id(&table)?,
                op: WriteOp::Insert,
                row: row_image(values),
                conflict: None,
            }),
            // A patchset carries no prior image, so an update or delete cannot
            // be conflict-checked. Fail closed.
            PatchsetOp::Update { .. } | PatchsetOp::Delete { .. } => {
                Err(MaterializerError::MissingVersion(table))
            }
        }
    }

    /// Build the conflict read for a version-bearing op, or `None` when the
    /// target carries no version column of its own. `basis` reads the prior
    /// value at a column index from the op's old image.
    fn plan_conflict(
        &self,
        schema: &TableSchema<String>,
        pk_values: &[WireValue],
        basis: impl Fn(usize) -> Option<WireValue>,
    ) -> Result<Option<PlannedConflict>, MaterializerError> {
        let table = schema.name();
        let Some(version) = self.write.version_column(table) else {
            return Ok(None);
        };
        let db = self.engine.inner().database();
        let table_id = catalog_helpers::table_id(db, table)
            .ok_or_else(|| MaterializerError::SchemaMismatch(table.to_owned()))?;
        let version_column = version.name().to_owned();
        let version_idx = catalog_helpers::column_id(db, table_id, &version_column)
            .ok_or_else(|| MaterializerError::SchemaMismatch(version_column.clone()))?;
        let basis = basis(usize::from(version_idx))
            .ok_or_else(|| MaterializerError::MissingVersion(table.to_owned()))?;

        let pk_columns = schema
            .primary_key_columns()
            .into_iter()
            .map(|idx| column_name_at(db, table_id, idx))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Some(PlannedConflict {
            table: table.to_owned(),
            version_column,
            basis,
            pk_columns,
            pk_values: pk_values.to_vec(),
        }))
    }

    /// Apply a client-uploaded [`MutationPatch`] against `conn`.
    ///
    /// The bare apply primitive: the session layer wraps it with authorization,
    /// conflict detection, and idempotency. Returns the number of rows the
    /// batch affected.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Compression`] when the payload does not decompress,
    /// [`MaterializerError::Apply`] when the diffset fails to parse or apply.
    pub fn apply_mutation(
        &self,
        patch: &MutationPatch,
        conn: &mut SqliteConnection,
    ) -> Result<usize, MaterializerError> {
        self.apply_diffset(&patch.patchset_zstd, conn)
    }

    /// Apply Zstd-compressed diffset bytes against `conn` through `subql`'s
    /// catalog-driven apply path.
    ///
    /// The shared apply primitive behind [`Self::apply_mutation`]. It also
    /// stands in for a client applying an outbound patch to its local replica,
    /// since the apply resolves table shapes from the shared catalog and is
    /// role-agnostic.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Compression`] when the payload does not decompress,
    /// [`MaterializerError::Apply`] when the diffset fails to parse or apply.
    pub fn apply_diffset(
        &self,
        payload_zstd: &[u8],
        conn: &mut SqliteConnection,
    ) -> Result<usize, MaterializerError> {
        let bytes = decompress(payload_zstd)?;
        let adapter = SqliteAdapter::new(self.engine.inner().database());
        Ok(self
            .engine
            .inner()
            .apply_diffset_bytes(&bytes, conn, &adapter)?)
    }

    /// Apply a client-uploaded [`MutationPatch`] against an async Postgres
    /// connection through `subql`'s diesel-async apply path.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Compression`] when the payload does not decompress,
    /// [`MaterializerError::Apply`] when the diffset fails to parse or apply.
    pub async fn apply_mutation_async(
        &self,
        patch: &MutationPatch,
        conn: &mut AsyncPgConnection,
    ) -> Result<usize, MaterializerError> {
        self.apply_diffset_async(&patch.patchset_zstd, conn).await
    }

    /// Apply Zstd-compressed diffset bytes against an async Postgres connection.
    ///
    /// The async peer of [`Self::apply_diffset`], driven by `diesel-async` over
    /// a `subql` [`PgAdapter`]. No `spawn_blocking`: the reconstruct runs
    /// synchronously up front, then the future carries only the owned batch and
    /// the connection.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Compression`] when the payload does not decompress,
    /// [`MaterializerError::Apply`] when the diffset fails to parse or apply.
    pub async fn apply_diffset_async(
        &self,
        payload_zstd: &[u8],
        conn: &mut AsyncPgConnection,
    ) -> Result<usize, MaterializerError> {
        let bytes = decompress(payload_zstd)?;
        let adapter = PgAdapter::new(self.engine.inner().database());
        Ok(self
            .engine
            .inner()
            .apply_diffset_bytes_async(&bytes, conn, &adapter)
            .await?)
    }
}

/// Serialize a re-executed scalar value as a JSON string for delivery.
pub(crate) fn value_to_json(value: &PgValue<Postgres>) -> String {
    let json = match value {
        PgValue::Missing | PgValue::Null => serde_json::Value::Null,
        PgValue::Bool(b) => serde_json::Value::Bool(*b),
        PgValue::Int(i) => serde_json::Value::from(*i),
        PgValue::Float(f) => serde_json::Number::from_f64(*f)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        PgValue::String(s) => serde_json::Value::String(s.clone()),
        PgValue::Bytes(b) => serde_json::Value::String(String::from_utf8_lossy(b).into_owned()),
        PgValue::Uuid(u) => serde_json::Value::String(u.to_string()),
        PgValue::Timestamp(t) => serde_json::Value::String(t.to_string()),
        PgValue::TimestampTz(t) => serde_json::Value::String(t.to_string()),
        PgValue::Date(d) => serde_json::Value::String(d.to_string()),
        PgValue::Time(t) => serde_json::Value::String(t.to_string()),
        PgValue::Decimal(d) => serde_json::Value::String(d.to_string()),
        PgValue::Json(j) | PgValue::Jsonb(j) => j.clone(),
    };
    json.to_string()
}

/// Serialize a folded [`AggValue`] as a JSON string for delivery, matching the
/// numeric and null shape [`value_to_json`] produces for the re-execution path.
pub(crate) fn agg_value_to_json(value: AggValue) -> String {
    let json = match value {
        AggValue::Count(c) => serde_json::Value::from(c),
        AggValue::Sum(s) | AggValue::Real(Some(s)) => serde_json::Number::from_f64(s)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        AggValue::Real(None) => serde_json::Value::Null,
    };
    json.to_string()
}

/// `SELECT EXISTS(...)` row from Postgres, which yields a boolean.
#[derive(QueryableByName)]
struct PresentBool {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    present: bool,
}

/// Probe one op for a stale-version conflict against a Postgres target. The
/// read runs under whatever RLS context the caller has set on `conn`.
///
/// # Errors
///
/// [`MaterializerError::Apply`] on a query failure, [`MaterializerError::Parse`]
/// when the read-back row is not valid JSON.
pub(crate) async fn probe_conflict_pg(
    conflict: &PlannedConflict,
    conn: &mut AsyncPgConnection,
) -> Result<ConflictProbe, MaterializerError> {
    let mut predicate: Vec<String> = conflict
        .pk_columns
        .iter()
        .enumerate()
        .map(|(index, col)| format!("{} = ${}", quote_ident(col), index + 1))
        .collect();
    predicate.push(format!(
        "{} = ${}",
        quote_ident(&conflict.version_column),
        conflict.pk_columns.len() + 1
    ));
    let sql = format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE {}) AS present",
        quote_ident(&conflict.table),
        predicate.join(" AND "),
    );
    let mut query = sql_query(sql).into_boxed::<diesel::pg::Pg>();
    for value in &conflict.pk_values {
        query = bind_value_pg(query, value);
    }
    query = bind_value_pg(query, &conflict.basis);
    let present: PresentBool = diesel_async::RunQueryDsl::get_result(query, conn).await?;
    if present.present {
        return Ok(ConflictProbe::Clear);
    }
    Ok(ConflictProbe::Stale(
        read_current_row_pg(conflict, conn).await?,
    ))
}

/// Read the current row for a conflict reply from Postgres, as a JSON object.
async fn read_current_row_pg(
    conflict: &PlannedConflict,
    conn: &mut AsyncPgConnection,
) -> Result<Option<ServerRow>, MaterializerError> {
    let predicate: Vec<String> = conflict
        .pk_columns
        .iter()
        .enumerate()
        .map(|(index, col)| format!("{} = ${}", quote_ident(col), index + 1))
        .collect();
    let sql = format!(
        "SELECT row_to_json(t)::text AS row_json FROM {} t WHERE {} LIMIT 1",
        quote_ident(&conflict.table),
        predicate.join(" AND "),
    );
    let mut query = sql_query(sql).into_boxed::<diesel::pg::Pg>();
    for value in &conflict.pk_values {
        query = bind_value_pg(query, value);
    }
    let rows: Vec<RowJson> = diesel_async::RunQueryDsl::load(query, conn).await?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    let json: serde_json::Value = serde_json::from_str(&row.row_json)
        .map_err(|err| MaterializerError::Parse(format!("{err}")))?;
    let version = json
        .get(&conflict.version_column)
        .map(json_scalar_to_string)
        .unwrap_or_default();
    Ok(Some(ServerRow {
        version,
        row_json: row.row_json,
    }))
}

/// Bind one wire value with the Postgres SQL type matching its variant.
fn bind_value_pg<'a>(
    query: BoxedSqlQuery<'a, diesel::pg::Pg, SqlQuery>,
    value: &WireValue,
) -> BoxedSqlQuery<'a, diesel::pg::Pg, SqlQuery> {
    match value {
        Value::Integer(int) => query.bind::<BigInt, _>(*int),
        Value::Real(real) => query.bind::<Double, _>(*real),
        Value::Text(text) => query.bind::<Text, _>(text.clone()),
        Value::Blob(blob) => query.bind::<Binary, _>(blob.clone()),
        Value::Null => query.bind::<Nullable<Text>, _>(None::<String>),
    }
}

/// `SELECT json_object(...)` row.
#[derive(QueryableByName)]
struct RowJson {
    #[diesel(sql_type = Text)]
    row_json: String,
}

/// Render a JSON scalar as the text the wire form expects.
fn json_scalar_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Resolve a column name by ordinal index.
fn column_name_at<DB: DatabaseLike>(
    db: &DB,
    table_id: u32,
    index: usize,
) -> Result<String, MaterializerError> {
    let column_id =
        u16::try_from(index).map_err(|_| MaterializerError::SchemaMismatch(index.to_string()))?;
    catalog_helpers::column_name(db, table_id, column_id)
        .ok_or_else(|| MaterializerError::SchemaMismatch(format!("column {index}")))
}

/// Quote a SQL identifier, doubling embedded quotes.
fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Zstd-compress a raw bulk payload at the materializer's standard level.
///
/// # Errors
///
/// Propagates the underlying [`std::io::Error`].
pub(crate) fn compress(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    zstd::encode_all(bytes, ZSTD_LEVEL)
}

/// Zstd-decompress a bulk payload.
///
/// # Errors
///
/// Propagates the underlying [`std::io::Error`].
pub(crate) fn decompress(payload_zstd: &[u8]) -> std::io::Result<Vec<u8>> {
    zstd::decode_all(payload_zstd)
}

#[cfg(test)]
mod wire_contract {
    //! Pin the exact JSON string [`value_to_json`] emits for each
    //! [`PgValue`] variant. The client aggregate decoders in
    //! `connetto-client` are written against these bytes, so a change here
    //! that is not mirrored there is a wire break, and this test is the
    //! canary.

    use super::{PgValue, Postgres, value_to_json};

    #[test]
    fn value_to_json_renders_each_scalar_variant() {
        // Absent and explicit null both collapse to JSON null.
        assert_eq!(value_to_json(&PgValue::<Postgres>::Missing), "null");
        assert_eq!(value_to_json(&PgValue::<Postgres>::Null), "null");

        // Bool is a JSON bool, not the SQLite 0/1 integer.
        assert_eq!(value_to_json(&PgValue::<Postgres>::Bool(true)), "true");
        assert_eq!(value_to_json(&PgValue::<Postgres>::Bool(false)), "false");

        // Integers are JSON integers, floats are JSON numbers.
        assert_eq!(value_to_json(&PgValue::<Postgres>::Int(42)), "42");
        assert_eq!(value_to_json(&PgValue::<Postgres>::Float(1.5)), "1.5");

        // Text is a JSON string.
        assert_eq!(
            value_to_json(&PgValue::<Postgres>::String("hi".to_owned())),
            "\"hi\"",
        );

        // Bytes render through String::from_utf8_lossy, not base64. Valid
        // UTF-8 rides through verbatim, and an invalid byte becomes the
        // replacement character (this is lossy by design, see Trap 3).
        assert_eq!(
            value_to_json(&PgValue::<Postgres>::Bytes(b"hi".to_vec())),
            "\"hi\"",
        );
        assert_eq!(
            value_to_json(&PgValue::<Postgres>::Bytes(vec![0xff, b'a'])),
            "\"\u{fffd}a\"",
        );

        // Uuid, the temporal types, and decimals render as their to_string,
        // wrapped as JSON strings, never as numbers.
        let uuid =
            uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        assert_eq!(
            value_to_json(&PgValue::<Postgres>::Uuid(uuid)),
            "\"550e8400-e29b-41d4-a716-446655440000\"",
        );
        let stamp = chrono::NaiveDate::from_ymd_opt(2020, 1, 2)
            .expect("valid date")
            .and_hms_opt(3, 4, 5)
            .expect("valid time");
        assert_eq!(
            value_to_json(&PgValue::<Postgres>::Timestamp(stamp)),
            "\"2020-01-02 03:04:05\"",
        );
        assert_eq!(
            value_to_json(&PgValue::<Postgres>::TimestampTz(stamp.and_utc())),
            "\"2020-01-02 03:04:05 UTC\"",
        );
        assert_eq!(
            value_to_json(&PgValue::<Postgres>::Date(
                chrono::NaiveDate::from_ymd_opt(2020, 1, 2).expect("valid date"),
            )),
            "\"2020-01-02\"",
        );
        assert_eq!(
            value_to_json(&PgValue::<Postgres>::Time(
                chrono::NaiveTime::from_hms_opt(3, 4, 5).expect("valid time"),
            )),
            "\"03:04:05\"",
        );

        // Json and Jsonb pass the raw JSON value through unquoted.
        let doc = serde_json::json!({ "k": 1 });
        assert_eq!(
            value_to_json(&PgValue::<Postgres>::Json(doc.clone())),
            "{\"k\":1}",
        );
        assert_eq!(value_to_json(&PgValue::<Postgres>::Jsonb(doc)), "{\"k\":1}");
    }
}
