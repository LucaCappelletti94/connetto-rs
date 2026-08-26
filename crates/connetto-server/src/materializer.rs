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
use connetto_core::quote_ident;
use connetto_core::write::{VersionColumn, WritableCatalog};
use diesel::query_builder::{BoxedSqlQuery, SqlQuery};
use diesel::sql_types::{BigInt, Binary, Double, Nullable, Text};
use diesel::{QueryableByName, SqliteConnection, sql_query};
use pg2sqlite::options::Pg2SqliteOptions;
use pg2sqlite::prelude::ReverseTranslator;
use pg2sqlite::prelude::SessionVariableMapping;
use pg2sqlite::traits::TranslationOptions;
use rls2fga::translator::Translator;
use sqlite_diff_rs::{
    ChangesetOp, DiffOps, Indirect, ParsedDiffSet, PatchDelete, PatchSet, PatchsetOp, SchemaWithPK,
    TableSchema, Value,
};
use sqlparser::ast::{BinaryOperator, Expr, SetExpr, Statement};
use sqlparser::dialect::{PostgreSqlDialect, SQLiteDialect};
use sqlparser::parser::Parser;
use subql::EventKind;
use subql::backend::{
    BuiltinKind, CdcEvent, Postgres, RowKind, ScalarKind, Value as PgValue, encode_value_key,
};
use subql::emit::{
    WireTable, pgoutput_changeset_builder, pgoutput_patchset, pgoutput_patchset_builder,
};
use subql::patchset::SqliteAdapter;
use subql::reexec::{AsyncConnector, AsyncMode, AutoResolvingEngine, ReExecError, RowsUpdate};
use subql::{
    AggValue, AggregateBootstrap, AggregateResultValue, AggregateValueChange, AggregateValueUpdate,
    ChangeEvent, DatabaseLike, DefaultIds, MaintenanceTransition, OpaqueCheckpoint, ParserDB,
    SubscriptionEngine, SubscriptionId, SubscriptionRequest, TableId, TableLike, Tier,
    catalog_helpers,
};

use crate::reexec::ReadBudget;

use crate::oplog::ChangeRecord;

use diesel_async::AsyncPgConnection;
use subql::patchset::PgAdapter;

/// The wire `Value` flavor a parsed upload carries: owned text and blobs.
type WireValue = Value<String, Vec<u8>>;

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
    /// A database read the engine drove through its connector failed for one
    /// subscription. `timed_out` distinguishes policy from outage (R81
    /// decision 3): a timeout ends that subscription, an outage is retried.
    #[error("re-execution read failed for subscription {subscription}: {detail}")]
    Read {
        /// The subscription whose triggered read failed.
        subscription: SubscriptionId,
        /// Whether the database cancelled the read at connetto's own limit.
        timed_out: bool,
        /// The connector's failure text.
        detail: String,
    },
    /// A seed or re-read result the engine refused to install.
    #[error("result installation refused: {0}")]
    Install(String),
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

/// The write one op performs, carrying the row versions its verb is judged on.
///
/// The owned mirror of subql's `RowWrite`, which the write question is asked
/// through. Owned because a plan outlives the upload it was parsed from, and
/// shaped the same way for the same reason: a replacement is judged on two
/// versions, and pairing a verb with the wrong number of images is not
/// representable.
#[derive(Debug, Clone)]
pub(crate) enum PlannedWrite {
    /// Creating the row.
    Insert {
        /// The row as it will be.
        new: Vec<PgValue<Postgres>>,
    },
    /// Replacing the row.
    ///
    /// A changeset carries two slots per column, so both images come from the
    /// upload. **A column the upload left out of both slots is absent from
    /// each**, which is the residual R5a recorded: a policy reading a column
    /// the client did not touch cannot be answered from the image, and the
    /// question falls to whatever sits behind the row-answering wrapper.
    Update {
        /// The row as it is, from the old slots.
        old: Vec<PgValue<Postgres>>,
        /// The row as it will be, the changed columns over the old ones.
        new: Vec<PgValue<Postgres>>,
    },
    /// Removing the row.
    Delete {
        /// The row as it is.
        old: Vec<PgValue<Postgres>>,
    },
}

/// One op parsed from a mutation upload, ready for the session write path.
#[derive(Debug, Clone)]
pub(crate) struct PlannedOp {
    /// Catalog id of the target table, naming the row the write check asks
    /// about.
    pub table_id: TableId,
    /// The write, and the row versions its verb is judged on.
    pub write: PlannedWrite,
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
    /// A server-computed subscription: any tier whose answer the client cannot
    /// derive from replica rows. Aggregates grouped and ungrouped, extremes,
    /// and captured row-shaped reads all classify here, differing only in how
    /// their first answer is produced ([`SeedPlan`]).
    Computed(ComputedCapture),
}

/// A server-computed subscription awaiting its first answer.
pub struct ComputedCapture {
    /// Engine-assigned identity, one id space with row subscriptions.
    pub subscription_id: SubscriptionId,
    /// Consumer that registered it.
    pub consumer_id: u64,
    /// How the first answer is produced.
    pub seed: SeedPlan,
}

/// How a computed subscription's first answer is produced.
pub enum SeedPlan {
    /// An in-process fold (grouped or not): the session runs the bootstrap
    /// through its own connector outside the materializer lock, then installs
    /// the decoded rows with [`Materializer::install_fold_seed`]. The engine
    /// buffers changes that land during the read and reconciles them against
    /// the seed's stream position.
    Fold {
        /// Runnable seed query with per-column decode kinds. Zero
        /// `group_columns` means one seed row, an ungrouped total.
        bootstrap: AggregateBootstrap,
    },
    /// A scalar extreme (`MIN`/`MAX`): the session runs the read through its
    /// own connector under the subscribing caller's tier (R81 decision 2, a
    /// slow seed delays the caller who asked and nobody else) and installs
    /// the value with [`Materializer::install_scalar`]. Later triggered
    /// re-reads ride the engine's connector under the shared bound.
    Scalar {
        /// SQL for the initial value, the same statement later triggers run.
        sql: String,
        /// Decode hint for the scalar result.
        kind: BuiltinKind,
    },
    /// A grouped extreme or a row read tier: the engine bootstraps it through
    /// its own connector inside [`Materializer::bootstrap_computed`].
    Snapshot,
}

/// The result of dispatching one CDC event.
pub struct Dispatched {
    /// Row patches to fan out to matched consumers.
    pub patches: Vec<MatchedPatch>,
    /// Server-computed results that moved: fold deltas per group, replaced
    /// scalar extremes, re-read row answers, and keyed row changes, each
    /// already shaped for the wire.
    pub computed: Vec<ComputedChange>,
    /// Membership moves this event caused: a subscription's answer changed
    /// because a relationship row moved, never because a row it reads changed
    /// (R27). Empty for every event until a membership term is registered.
    pub narrowings: Vec<TermMove>,
}

/// One server-computed result movement, ready to frame on the wire.
pub struct ComputedChange {
    /// The subscription whose answer moved.
    pub subscription_id: SubscriptionId,
    /// Consumer that owns it.
    pub consumer_id: u64,
    /// The addressed key: a fold group's opaque encoding, a keyed row's
    /// key encoding, or `None` for a single-valued answer.
    pub group_key: Option<Vec<u8>>,
    /// The new value as JSON, or `None` when the addressed key left the
    /// result.
    pub result_json: Option<String>,
    /// Whether this replaces the subscription's whole result rather than
    /// upserting one key.
    pub is_full_result: bool,
    /// Resume cursor of the event that produced it, empty when the movement
    /// came from a seed or a read with no position.
    pub cursor: Vec<u8>,
}

/// The engine the materializer hosts: subql's auto-resolving wrapper in async
/// mode, which owns trigger servicing, per-subscription debounce, key
/// batching, and paging, driving `C` for every database read. The lock-held
/// read this implies is a recorded measured-risk item whose exit is
/// `docs/upstream-subql-nonblocking-read-tier-drive.md`.
type Engine<DB, C> = AutoResolvingEngine<ChangeEvent, DefaultIds, DB, AsyncMode<C>>;

/// The connector shape the materializer drives: connetto's budget rides the
/// per-registration auth context, so every read the engine issues is bounded
/// by the tier of the caller who registered the subscription (R81).
pub trait ReadConnector:
    AsyncConnector<
        Backend = Postgres,
        Checkpoint = subql::PgLsn,
        AuthContext = crate::reexec::ConnettoReadSetup,
        Error: core::fmt::Display + crate::reexec::TimedOutRead + Send,
    > + Send
    + Sync
{
}

impl<C> ReadConnector for C where
    C: AsyncConnector<
            Backend = Postgres,
            Checkpoint = subql::PgLsn,
            AuthContext = crate::reexec::ConnettoReadSetup,
            Error: core::fmt::Display + crate::reexec::TimedOutRead + Send,
        > + Send
        + Sync
{
}

/// Hosts one `subql` engine over a Postgres-flavored catalog on the pgoutput
/// vehicle ([`ChangeEvent`], the `pg_walstream` event type both matching and
/// emission consume), plus the write policy the mutation path consults.
pub struct Materializer<DB = ParserDB, W = RuntimeWritableCatalog, C = crate::reexec::NoConnector>
where
    DB: DatabaseLike,
    W: WritableCatalog,
    C: ReadConnector,
{
    engine: Engine<DB, C>,
    /// The parsed catalog, cloned before the engine takes ownership of its
    /// copy: emission, apply, and write planning read it directly rather
    /// than through the engine.
    catalog: DB,
    write: W,
    /// The deployment's caller mapping: how the client's local caller function
    /// (the no-arg SQLite function R40 registers) reverse translates into
    /// `current_setting('app.user_id', true)`, so a membership subquery reaches
    /// Postgres as SQL the classifier reads. `None` for a deployment serving no
    /// membership term, where a subscription never names the caller.
    caller: Option<SessionVariableMapping>,
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
    /// Build a materializer over a Postgres DDL catalog and a write policy,
    /// with no re-execution connector: computed subscriptions register but
    /// every read they need refuses.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Catalog`] when the DDL does not parse.
    pub fn with_write_catalog(pg_ddl: &str, write: W) -> Result<Self, MaterializerError> {
        Self::build(pg_ddl, write, None, None, crate::reexec::NoConnector)
    }

    /// Build a materializer whose engine can compile a membership subquery and
    /// whose reverse translation rewrites the caller.
    ///
    /// `translator` is the deployment's `rls2fga` translator, handed to the
    /// `subql` engine so a bounded membership term classifies at registration
    /// rather than being refused for want of one. `caller` is the mapping
    /// [`Materializer::translate_subscription_sql`] rewrites the client's local
    /// caller function with, `None` when no policy names the caller.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Catalog`] when the DDL does not parse.
    pub fn with_translation(
        pg_ddl: &str,
        write: W,
        translator: Translator,
        caller: Option<SessionVariableMapping>,
    ) -> Result<Self, MaterializerError> {
        Self::build(
            pg_ddl,
            write,
            Some(translator),
            caller,
            crate::reexec::NoConnector,
        )
    }
}

impl<W: WritableCatalog, C: ReadConnector> Materializer<ParserDB, W, C> {
    /// Build a materializer that drives `connector` for every database read
    /// the engine's computed tiers need: fold seeds installed by the session
    /// aside, extremes, grouped re-reads, and captured row answers all go
    /// through it, each read bounded by the budget its registration carried.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Catalog`] when the DDL does not parse.
    pub fn with_read_connector(
        pg_ddl: &str,
        write: W,
        translator: Option<Translator>,
        caller: Option<SessionVariableMapping>,
        connector: C,
    ) -> Result<Self, MaterializerError> {
        Self::build(pg_ddl, write, translator, caller, connector)
    }

    fn build(
        pg_ddl: &str,
        write: W,
        translator: Option<Translator>,
        caller: Option<SessionVariableMapping>,
        connector: C,
    ) -> Result<Self, MaterializerError> {
        let catalog = ParserDB::parse::<PostgreSqlDialect>(pg_ddl)
            .map_err(|err| MaterializerError::Catalog(format!("{err:?}")))?;
        let mut engine = SubscriptionEngine::new(catalog.clone(), PostgreSqlDialect {});
        if let Some(translator) = translator {
            engine = engine.with_translator(translator);
        }
        Ok(Self {
            engine: AutoResolvingEngine::new(engine, AsyncMode::new(connector)),
            catalog,
            write,
            caller,
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
        budget: ReadBudget,
    ) -> Result<SqliteRegistration, MaterializerError> {
        let pg_sql = self.translate_subscription_sql(sqlite_sql)?;
        let registration = self.register_translated(consumer_id, &pg_sql, binds, None, budget)?;
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
        let mut options = Pg2SqliteOptions::default();
        if let Some(caller) = &self.caller {
            options = options.with_session_variable(caller.clone());
        }
        let pg = statement
            .reverse_translate(&self.catalog, &options)
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

/// One term's seed: the compared columns and the value rows the caller
/// currently matches, one cell per column in the stated order.
pub type TermValueRows = (Vec<String>, Vec<Vec<PgValue<Postgres>>>);

/// What a term registration is seeded with: the subscriber it filters for and
/// the values each compared column currently admits, read from the membership
/// table as the caller.
pub struct TermSeed {
    /// The caller, typed at `member_subject`'s kind (see [`typed_subscriber`]).
    pub subscriber: PgValue<Postgres>,
    /// Per term, its columns and value rows.
    pub term_values: Vec<TermValueRows>,
}

/// Build the subscriber value at `member_subject`'s own scalar kind.
///
/// `TermKey::String` and `TermKey::Uuid` are different variants inside subql's
/// lookup, so a string identity against a column of another kind admits nobody
/// in silence. `None` refuses the term instead: an identity that cannot be
/// read at the column's kind cannot be a member.
#[must_use]
pub fn typed_subscriber(identity: &str, kind: BuiltinKind) -> Option<PgValue<Postgres>> {
    match kind {
        ScalarKind::String => Some(PgValue::String(identity.to_owned())),
        ScalarKind::Uuid => uuid::Uuid::parse_str(identity).ok().map(PgValue::Uuid),
        ScalarKind::Int => identity.parse().ok().map(PgValue::Int),
        _ => None,
    }
}

/// Resolve subql's narrowing ids to catalog names, so the session builds the
/// affected-rows reads without holding the materializer lock (R27).
fn term_moves<DB: DatabaseLike>(
    db: &DB,
    narrowings: &[subql::TermNarrowing<Postgres>],
) -> Vec<TermMove> {
    narrowings
        .iter()
        .map(|narrowing| TermMove {
            sub_id: narrowing.subscription,
            table: catalog_helpers::table_name(db, narrowing.table).unwrap_or_default(),
            pairs: narrowing
                .columns
                .iter()
                .zip(&narrowing.values)
                .map(|(column, value)| {
                    (
                        catalog_helpers::column_name(db, narrowing.table, *column)
                            .unwrap_or_default(),
                        value.clone(),
                    )
                })
                .collect(),
            entered: narrowing.entered,
        })
        .collect()
}

/// One membership move [`Materializer::dispatch`] reported, with subql's ids
/// resolved to catalog names so the session can build the affected-rows reads
/// without holding the materializer lock.
pub struct TermMove {
    /// The engine subscription whose answer moved.
    pub sub_id: SubscriptionId,
    /// The subscribed table, by catalog name.
    pub table: String,
    /// The compared columns and the value each now matches or stopped
    /// matching, pairwise in the filter's order. A composite membership key
    /// moves as a whole tuple, so the affected-rows read must constrain on
    /// every pair or it re-reads on half a key.
    pub pairs: Vec<(String, PgValue<Postgres>)>,
    /// Whether the tuple entered.
    pub entered: bool,
}

/// The subscription's own SELECT with `AND <column> = <value>` conjoined per
/// moved pair, so the rest of the filter still applies to a moved row (R27
/// decision 2) and a composite membership key constrains on every column.
///
/// Each value rides as a SQL literal built from the AST, never by string
/// interpolation, and the query's `$N` placeholders are untouched, so the
/// subscription's own binds still pair. `None` for an empty pair list and
/// when a value's kind has no literal, which subql's term keys exclude at
/// registration.
#[must_use]
pub fn narrowed_sql(pg_sql: &str, pairs: &[(String, PgValue<Postgres>)]) -> Option<String> {
    if pairs.is_empty() {
        return None;
    }
    let mut statements = Parser::parse_sql(&PostgreSqlDialect {}, pg_sql).ok()?;
    let [Statement::Query(query)] = statements.as_mut_slice() else {
        return None;
    };
    let SetExpr::Select(select) = query.body.as_mut() else {
        return None;
    };
    for (column, value) in pairs {
        let narrowing = Expr::BinaryOp {
            left: Box::new(Expr::Identifier(sqlparser::ast::Ident::with_quote(
                '"', column,
            ))),
            op: BinaryOperator::Eq,
            right: Box::new(value_literal(value)?),
        };
        select.selection = Some(match select.selection.take() {
            Some(existing) => Expr::BinaryOp {
                left: Box::new(Expr::Nested(Box::new(existing))),
                op: BinaryOperator::And,
                right: Box::new(narrowing),
            },
            None => narrowing,
        });
    }
    Some(statements[0].to_string())
}

/// One term value as a SQL literal expression. Every kind subql admits as a
/// term key renders: temporal and uuid kinds ride as quoted strings, which
/// PostgreSQL casts against the compared column, and bytes as `\x` bytea
/// input. `Missing`, `Null`, floats and json are not term keys.
fn value_literal(value: &PgValue<Postgres>) -> Option<Expr> {
    use sqlparser::ast::Value as AstValue;
    let literal = match value {
        PgValue::Bool(b) => AstValue::Boolean(*b),
        PgValue::Int(i) => AstValue::Number(i.to_string(), false),
        PgValue::Decimal(d) => AstValue::Number(d.to_string(), false),
        PgValue::String(s) => AstValue::SingleQuotedString(s.clone()),
        PgValue::Uuid(u) => AstValue::SingleQuotedString(u.to_string()),
        PgValue::Timestamp(t) => AstValue::SingleQuotedString(t.to_string()),
        PgValue::TimestampTz(t) => AstValue::SingleQuotedString(t.to_rfc3339()),
        PgValue::Date(d) => AstValue::SingleQuotedString(d.to_string()),
        PgValue::Time(t) => AstValue::SingleQuotedString(t.to_string()),
        PgValue::Bytes(bytes) => {
            use core::fmt::Write;
            let mut hex = String::with_capacity(bytes.len() * 2 + 2);
            hex.push_str("\\x");
            for byte in bytes {
                let _ = write!(hex, "{byte:02x}");
            }
            AstValue::SingleQuotedString(hex)
        }
        PgValue::Missing
        | PgValue::Null
        | PgValue::Float(_)
        | PgValue::Json(_)
        | PgValue::Jsonb(_) => return None,
        // Postgres teaches subql no custom scalars, so the variant's payload
        // is uninhabited and this arm exists only to be total.
        PgValue::Custom(never) => match *never {},
    };
    Some(Expr::Value(literal.into()))
}

impl<DB, W, C> Materializer<DB, W, C>
where
    DB: DatabaseLike + 'static,
    W: WritableCatalog,
    C: ReadConnector,
{
    /// The parsed catalog this materializer matches against.
    ///
    /// The visibility seam needs it to read column values off a change event,
    /// and it holds the row across an await, so it takes a clone at
    /// construction rather than reaching through the materializer's mutex.
    pub const fn catalog(&self) -> &DB {
        &self.catalog
    }

    /// Register a subscription for `consumer_id` from a SQL `SELECT`, with a
    /// generous default read budget. Tests and doc examples only: a session
    /// registers through [`Self::register_translated`] with its caller's tier
    /// budget.
    ///
    /// A row subscription returns [`Registration::Row`] with its
    /// [`SubscriptionId`]. Every other accepted shape returns
    /// [`Registration::Computed`], whose [`SeedPlan`] says how the first
    /// answer is produced.
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
            ReadBudget::new(core::time::Duration::from_secs(5)),
        )
    }

    /// Register one built [`SubscriptionRequest`], classifying the engine's
    /// tier into a [`Registration`]. `budget` bounds every database read the
    /// engine will ever run for this subscription.
    fn register_request(
        &mut self,
        consumer_id: u64,
        request: SubscriptionRequest<DefaultIds, Postgres>,
        budget: ReadBudget,
    ) -> Result<Registration, MaterializerError> {
        let registered = self
            .engine
            .register(request, crate::reexec::ConnettoReadSetup::of(budget))?;
        let subscription_id = registered.subscription_id;
        Ok(match registered.tier {
            Tier::InProcess(served) => match served.aggregate_bootstrap {
                Some(bootstrap) => Registration::Computed(ComputedCapture {
                    subscription_id,
                    consumer_id,
                    seed: SeedPlan::Fold { bootstrap },
                }),
                None => Registration::Row(subscription_id),
            },
            Tier::Scalar { sql, column_kind } => Registration::Computed(ComputedCapture {
                subscription_id,
                consumer_id,
                seed: SeedPlan::Scalar {
                    sql,
                    kind: column_kind,
                },
            }),
            Tier::GroupedScalar { .. } | Tier::KeyedRows { .. } | Tier::WholeRows { .. } => {
                Registration::Computed(ComputedCapture {
                    subscription_id,
                    consumer_id,
                    seed: SeedPlan::Snapshot,
                })
            }
        })
    }

    /// Install a scalar extreme's seed value, read by the session through its
    /// own connector under the subscribing caller's tier.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Install`] when the subscription is unknown or is
    /// not a scalar read.
    pub fn install_scalar(
        &mut self,
        subscription_id: SubscriptionId,
        value: PgValue<Postgres>,
        checkpoint: Option<subql::PgLsn>,
    ) -> Result<ComputedChange, MaterializerError> {
        let update = subql::Install::install(
            &mut self.engine,
            subscription_id,
            subql::ScalarInstall { value, checkpoint },
        )
        .map_err(|err| MaterializerError::Install(err.to_string()))?;
        Ok(ComputedChange {
            subscription_id: update.subscription_id,
            consumer_id: update.consumer_id,
            group_key: None,
            result_json: Some(value_to_json(&update.value)),
            is_full_result: true,
            cursor: cursor_bytes(update.checkpoint.as_ref()),
        })
    }

    /// Drop a subscription of any tier by its engine id. Returns whether it
    /// existed. One call for rows, folds, and read tiers alike: the wrapper
    /// resolves whichever registry holds the id (U7).
    pub fn unregister(&mut self, sub_id: SubscriptionId) -> bool {
        self.engine.unregister_subscription(sub_id)
    }

    /// Install a fold's seed rows, read by the session through its own
    /// connector outside the materializer lock.
    ///
    /// The engine buffers changes dispatched while the read was in flight and
    /// reconciles them against `read_at`, so nothing committed inside the
    /// window is folded into nothing (the guarantee `expect_aggregate` used to
    /// approximate connetto-side, now the engine's own).
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Install`] when the engine refuses the rows: an
    /// unknown or already-seeded subscription, a malformed row, an unordered
    /// read, or too many changes buffered during it.
    pub fn install_fold_seed(
        &mut self,
        subscription_id: SubscriptionId,
        rows: Vec<Vec<PgValue<Postgres>>>,
        read_at: Option<subql::PgLsn>,
    ) -> Result<FoldSeeded, MaterializerError> {
        let output = subql::Install::install(
            &mut self.engine,
            subscription_id,
            subql::AggregateSeedInstall { rows, read_at },
        )
        .map_err(|err| MaterializerError::Install(err.to_string()))?;
        Self::log_transitions(&output.transitions);
        Ok(FoldSeeded {
            changes: output
                .updates
                .into_iter()
                .map(|update| Self::aggregate_change(update, Vec::new()))
                .collect(),
            needs_snapshot: !output.triggers.is_empty(),
        })
    }

    /// Produce a computed subscription's first answer through the engine's own
    /// connector: the scalar read, the grouped seed, or the whole row answer,
    /// depending on the registered tier. Also the recovery read after a
    /// demotion ([`FoldSeeded::needs_snapshot`]).
    ///
    /// Returns no changes when the subscription raced an unregister.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Read`] when the connector refuses or the database
    /// fails, [`MaterializerError::Install`] when the engine refuses the
    /// result.
    pub async fn bootstrap_computed(
        &mut self,
        subscription_id: SubscriptionId,
        consumer_id: u64,
    ) -> Result<Vec<ComputedChange>, MaterializerError> {
        let Some(result) = self
            .engine
            .snapshot(subscription_id)
            .await
            .map_err(reexec_error)?
        else {
            return Ok(Vec::new());
        };
        Ok(match result {
            subql::reexec::SnapshotResult::Scalar(value, checkpoint) => {
                vec![ComputedChange {
                    subscription_id,
                    consumer_id,
                    group_key: None,
                    result_json: Some(value_to_json(&value)),
                    is_full_result: true,
                    cursor: cursor_bytes(checkpoint.as_ref()),
                }]
            }
            subql::reexec::SnapshotResult::GroupedAggregate {
                updates,
                checkpoint,
            } => {
                let cursor = cursor_bytes(checkpoint.as_ref());
                updates
                    .into_iter()
                    .map(|update| Self::aggregate_change(update, cursor.clone()))
                    .collect()
            }
            subql::reexec::SnapshotResult::Rows {
                columns,
                rows,
                checkpoint,
            } => vec![ComputedChange {
                subscription_id,
                consumer_id,
                group_key: None,
                result_json: Some(rows_json(&columns, &rows)),
                is_full_result: true,
                cursor: cursor_bytes(checkpoint.as_ref()),
            }],
            // The enum is non_exhaustive upstream: a tier this build does not
            // know cannot be delivered, so it refuses rather than sending a
            // shape the wire has no meaning for.
            other => {
                return Err(MaterializerError::Install(format!(
                    "unknown snapshot result shape: {other:?}"
                )));
            }
        })
    }

    /// One wire-shaped change from an engine aggregate movement.
    fn aggregate_change(
        update: AggregateValueUpdate<DefaultIds, Postgres>,
        cursor: Vec<u8>,
    ) -> ComputedChange {
        let is_full_result = update.group.is_none();
        ComputedChange {
            subscription_id: update.subscription,
            consumer_id: update.consumer,
            group_key: update.group,
            result_json: match update.change {
                AggregateValueChange::Set(AggregateResultValue::Folded(value)) => {
                    Some(agg_value_to_json(value))
                }
                AggregateValueChange::Set(AggregateResultValue::Scalar(value)) => {
                    Some(value_to_json(&value))
                }
                AggregateValueChange::Remove => None,
            },
            is_full_result,
            cursor,
        }
    }

    /// Log tier transitions: the demotion decision (R30) is server-visible
    /// only, so a subscription that outgrew its fold budget keeps answering
    /// while the operator sees why it now costs reads.
    fn log_transitions(transitions: &[MaintenanceTransition]) {
        for transition in transitions {
            crate::counters::add(&crate::counters::TIER_TRANSITIONS, 1);
            tracing::info!(
                subscription = transition.subscription_id,
                from = ?transition.from,
                to = ?transition.to.kind(),
                reason = ?transition.reason,
                "subscription changed maintenance tier"
            );
        }
    }

    /// Dispatch one CDC event into row patches and computed-result changes.
    ///
    /// Row notifications fold once into a compressed patchset shared across the
    /// matched consumers. Everything the engine's tiers produced (fold deltas,
    /// replaced extremes, re-read row answers, keyed row changes) arrives
    /// already resolved: the engine drove its connector for every read this
    /// event required, each bounded by its registration's budget.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Dispatch`] on a dispatch failure,
    /// [`MaterializerError::Read`] when a triggered read failed,
    /// [`MaterializerError::Emit`] when the event cannot be folded, and
    /// [`MaterializerError::Compression`] on a compression failure.
    pub async fn dispatch(&mut self, event: &ChangeEvent) -> Result<Dispatched, MaterializerError> {
        let notifications = self.engine.consumers(event).await.map_err(reexec_error)?;
        let cursor = event
            .checkpoint()
            .map(|lsn| lsn.0.to_be_bytes().to_vec())
            .unwrap_or_default();
        Self::log_transitions(&notifications.transitions);

        let mut computed = Vec::new();
        for update in notifications.aggregate_updates {
            computed.push(Self::aggregate_change(update, cursor.clone()));
        }
        for update in notifications.scalar_updates {
            computed.push(ComputedChange {
                subscription_id: update.subscription_id,
                consumer_id: update.consumer_id,
                group_key: None,
                result_json: Some(value_to_json(&update.value)),
                is_full_result: true,
                cursor: cursor.clone(),
            });
        }
        computed.extend(Self::rows_changes(notifications.rows_updates, &cursor));
        for delta in notifications.row_deltas {
            computed.push(ComputedChange {
                subscription_id: delta.subscription_id,
                consumer_id: delta.consumer_id,
                // The key's canonical byte encoding, the same one the engine
                // uses for group keys, so the client's keyed storage treats
                // both uniformly.
                group_key: Some(encode_value_key::<Postgres>(&delta.key).unwrap_or_default()),
                result_json: delta.row.map(|row| row_json(&delta.columns, &row)),
                is_full_result: false,
                cursor: cursor.clone(),
            });
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
            let built = pgoutput_patchset_builder(&self.catalog, std::slice::from_ref(event))
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

        let narrowings = term_moves(&self.catalog, notifications.engine.narrowings());

        Ok(Dispatched {
            patches,
            computed,
            narrowings,
        })
    }

    /// Collapse re-read pages into one full-result change per subscription.
    ///
    /// Pages of one re-read share a generation and arrive in delivery order
    /// within one engine call, and a higher generation replaces a lower, so
    /// only the newest generation per subscription survives and its pages
    /// concatenate into one wire frame: the wire's full-result replacement is
    /// atomic where a paged delivery would show a half-replaced answer.
    fn rows_changes(
        updates: Vec<RowsUpdate<DefaultIds, Postgres, subql::PgLsn>>,
        cursor: &[u8],
    ) -> Vec<ComputedChange> {
        /// One subscription's newest re-read, its pages concatenated.
        struct PendingRows {
            consumer_id: u64,
            generation: u64,
            columns: Vec<String>,
            rows: Vec<Vec<PgValue<Postgres>>>,
        }
        let mut latest: HashMap<u64, PendingRows> = HashMap::new();
        for update in updates {
            let entry = latest
                .entry(update.subscription_id)
                .or_insert_with(|| PendingRows {
                    consumer_id: update.consumer_id,
                    generation: update.generation,
                    columns: Vec::new(),
                    rows: Vec::new(),
                });
            if update.generation > entry.generation {
                *entry = PendingRows {
                    consumer_id: update.consumer_id,
                    generation: update.generation,
                    columns: Vec::new(),
                    rows: Vec::new(),
                };
            }
            if entry.columns.is_empty() {
                entry.columns = update.columns;
            }
            entry.rows.extend(update.rows);
        }
        latest
            .into_iter()
            .map(|(subscription_id, pending)| ComputedChange {
                subscription_id,
                consumer_id: pending.consumer_id,
                group_key: None,
                result_json: Some(rows_json(&pending.columns, &pending.rows)),
                is_full_result: true,
                cursor: cursor.to_vec(),
            })
            .collect()
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
            let notifs = self.engine.match_rows(event)?;
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
        let built = pgoutput_patchset_builder(&self.catalog, std::slice::from_ref(event))
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
        let raw = pgoutput_patchset(&self.catalog, std::slice::from_ref(event))
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

    /// A compressed patchset carrying one plain delete for the row `event`
    /// changed, keyed by the image the caller holds.
    ///
    /// This is what a caller who may no longer see the row receives (R6). It is
    /// deliberately not the event's own patch, which for an update carries the
    /// new row values the caller has just lost the right to read, and
    /// deliberately not the departure notice, which the client discards
    /// whenever a sibling subscription still covers the row.
    ///
    /// **The key comes from the changeset rather than the patchset, and that is
    /// the point of building a second fold here.** A patchset update stores the
    /// key it will apply against, which the pgoutput digest fills from the new
    /// image, while a changeset update stores the row identity old-first. A
    /// caller holds the row under the old key, so an update that moved the
    /// primary key would otherwise be withdrawn by a key nothing on the device
    /// matches, and the row would stay.
    ///
    /// [`None`] when the event folds to no operation, which today means a
    /// truncate.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Emit`] when the event cannot be folded, and
    /// [`MaterializerError::Compression`] on a compression failure.
    pub(crate) fn withdrawal_patch(
        &self,
        event: &ChangeEvent,
    ) -> Result<Option<Vec<u8>>, MaterializerError> {
        let built = pgoutput_changeset_builder(&self.catalog, std::slice::from_ref(event))
            .map_err(|err| MaterializerError::Emit(format!("{err}")))?;
        let Some(op) = built.iter().next() else {
            return Ok(None);
        };
        let bytes = PatchSet::<WireTable, String, Vec<u8>>::new()
            .delete(PatchDelete::new(op.table().clone(), op.primary_key()))
            .build();
        Ok(Some(compress(&bytes)?))
    }

    /// The `(table, primary-key bytes)` identity of a CDC event, for the auth
    /// read filter. Primary-key columns are read from the event's PK image and
    /// encoded by [`crate::pk`] into a stable, self-describing byte string the
    /// auth policy treats as opaque and decodes back into typed values.
    fn event_identity(&self, event: &ChangeEvent) -> Option<(String, Vec<u8>)> {
        let db = &self.catalog;
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
        self.engine
            .advance_cursor(session_id, sub_id, OpaqueCheckpoint(cursor.to_vec()))?;
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
        catalog_helpers::table_id(&self.catalog, table)
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
        let db = self.catalog();
        let pk_values = op.primary_key();
        let (write, conflict) = match op {
            ChangesetOp::Insert { values, .. } => (
                PlannedWrite::Insert {
                    new: crate::pk::row_from_wire(db, table_id, values),
                },
                None,
            ),
            ChangesetOp::Update { values, .. } => {
                let conflict = self.plan_conflict(schema, &pk_values, |idx| {
                    values.get(idx).and_then(|cell| cell.0.clone())
                })?;
                // The old slots alone are the row as it is, and the new slots
                // over them are the row the update leaves behind. A column the
                // upload touched in neither slot reads absent from both, which
                // is the same residual an event carries under `REPLICA
                // IDENTITY DEFAULT`.
                let old = values
                    .iter()
                    .enumerate()
                    .map(|(ordinal, (old, _))| match old {
                        Some(value) => crate::pk::from_wire(
                            value,
                            crate::pk::scalar_kind(db, table_id, ordinal),
                        ),
                        None => PgValue::Missing,
                    })
                    .collect();
                let new = values
                    .iter()
                    .enumerate()
                    .map(
                        |(ordinal, (old, new))| match new.as_ref().or(old.as_ref()) {
                            Some(value) => crate::pk::from_wire(
                                value,
                                crate::pk::scalar_kind(db, table_id, ordinal),
                            ),
                            None => PgValue::Missing,
                        },
                    )
                    .collect();
                (PlannedWrite::Update { old, new }, conflict)
            }
            ChangesetOp::Delete { old_values, .. } => {
                let conflict =
                    self.plan_conflict(schema, &pk_values, |idx| old_values.get(idx).cloned())?;
                (
                    PlannedWrite::Delete {
                        old: crate::pk::row_from_wire(db, table_id, old_values),
                    },
                    conflict,
                )
            }
        };
        Ok(PlannedOp {
            table_id,
            write,
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
            PatchsetOp::Insert { values, .. } => {
                let table_id = self.table_id(&table)?;
                Ok(PlannedOp {
                    table_id,
                    write: PlannedWrite::Insert {
                        new: crate::pk::row_from_wire(self.catalog(), table_id, values),
                    },
                    conflict: None,
                })
            }
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
        let db = &self.catalog;
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
        let adapter = SqliteAdapter::new(&self.catalog);
        Ok(subql::patchset::apply_diffset_bytes_with_catalog(
            &self.catalog,
            &bytes,
            conn,
            &adapter,
        )?)
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
        let adapter = PgAdapter::new(&self.catalog);
        Ok(subql::patchset::apply_diffset_bytes_async_with_catalog(
            &self.catalog,
            &bytes,
            conn,
            &adapter,
        )
        .await?)
    }

    /// What each membership term this subscription names needs seeded, as
    /// subql itself describes it.
    ///
    /// Empty for a filter naming none, which is every filter until one is
    /// written. subql compiles the filter here through the same path
    /// `register` uses, so a term described is a term `register` accepts, and
    /// the seed query answered is the subquery's own text rather than SQL
    /// rebuilt from resolved names (R63).
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Register`] for whatever `register` would answer
    /// short of the seed itself: a filter outside subql's shape, an aggregate
    /// over row-level security, or a relationship it cannot serve.
    pub fn describe_terms(
        &self,
        consumer_id: u64,
        pg_sql: &str,
        binds: &[BindValue],
    ) -> Result<Vec<subql::term::TermDescription>, MaterializerError> {
        let request = SubscriptionRequest::new(consumer_id, pg_sql).binds(wire_binds(binds));
        self.engine
            .describe_terms(&request)
            .map_err(MaterializerError::Register)
    }

    /// Register a pre-translated Postgres `SELECT`, optionally seeded with the
    /// subscriber and the values its membership terms currently admit.
    ///
    /// The seed rides the registration itself because subql maintains the
    /// membership sets from the change stream only after it: a term registered
    /// without a subscriber is refused, and one registered without values
    /// admits nobody until a membership row changes.
    ///
    /// # Errors
    ///
    /// [`MaterializerError::Register`] when `subql` rejects the SELECT, the
    /// binds, or the term.
    pub fn register_translated(
        &mut self,
        consumer_id: u64,
        pg_sql: &str,
        binds: &[BindValue],
        seed: Option<TermSeed>,
        budget: ReadBudget,
    ) -> Result<Registration, MaterializerError> {
        let mut request = SubscriptionRequest::new(consumer_id, pg_sql).binds(wire_binds(binds));
        if let Some(seed) = seed {
            request = request.subscriber(seed.subscriber);
            for (columns, rows) in seed.term_values {
                request = request.term_values(columns, rows);
            }
        }
        self.register_request(consumer_id, request, budget)
    }
}

/// A fold's seed accepted: the initial values to deliver, and whether the
/// seed itself demoted the subscription (its groups already exceed the
/// budget), in which case [`Materializer::bootstrap_computed`] produces the
/// first whole answer instead.
pub struct FoldSeeded {
    /// Initial per-group values, wire-shaped.
    pub changes: Vec<ComputedChange>,
    /// Whether a demotion left the first answer to a follow-up read.
    pub needs_snapshot: bool,
}

/// Map an engine drive failure onto the materializer's error, keeping the
/// dispatch-versus-read distinction and the failed subscription's identity,
/// which the session's refusal paths act on (R81 decision 3).
fn reexec_error<E>(err: ReExecError<E>) -> MaterializerError
where
    E: core::fmt::Display + crate::reexec::TimedOutRead,
{
    match err {
        ReExecError::Dispatch(err) => MaterializerError::Dispatch(err),
        ReExecError::Connector {
            subscription,
            error,
        } => MaterializerError::Read {
            subscription,
            timed_out: error.timed_out(),
            detail: error.to_string(),
        },
        ReExecError::Cursor {
            subscription,
            error,
        } => MaterializerError::Read {
            subscription,
            // A cursor failure wraps the connector error one level deeper,
            // and "this connector holds no cursors" is a configuration
            // refusal that no retry clears, so it ends the subscription the
            // same way a timeout does.
            timed_out: matches!(
                &error,
                subql::reexec::CursorError::Connector(inner) if inner.timed_out()
            ) || matches!(error, subql::reexec::CursorError::Unsupported),
            detail: error.to_string(),
        },
        other => MaterializerError::Install(other.to_string()),
    }
}

/// A resume cursor from a read's stream position, empty when unknown.
fn cursor_bytes(checkpoint: Option<&subql::PgLsn>) -> Vec<u8> {
    checkpoint
        .map(|lsn| lsn.0.to_be_bytes().to_vec())
        .unwrap_or_default()
}

/// One row as a JSON object keyed by column name, so the client deserializes
/// it field-name-based per Q5.7, column order irrelevant.
fn row_object(columns: &[String], row: &[PgValue<Postgres>]) -> serde_json::Value {
    serde_json::Value::Object(
        columns
            .iter()
            .zip(row)
            .map(|(column, value)| (column.clone(), value_json(value)))
            .collect(),
    )
}

/// One keyed row as a JSON object string.
pub(crate) fn row_json(columns: &[String], row: &[PgValue<Postgres>]) -> String {
    row_object(columns, row).to_string()
}

/// A whole row answer as a JSON array of objects.
pub(crate) fn rows_json(columns: &[String], rows: &[Vec<PgValue<Postgres>>]) -> String {
    serde_json::Value::Array(rows.iter().map(|row| row_object(columns, row)).collect()).to_string()
}

/// One scalar as a JSON value, the shared shape behind every delivery.
fn value_json(value: &PgValue<Postgres>) -> serde_json::Value {
    match value {
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
        // Uninhabited for this backend, as above.
        PgValue::Custom(never) => match *never {},
    }
}

/// Serialize a re-executed scalar value as a JSON string for delivery.
pub(crate) fn value_to_json(value: &PgValue<Postgres>) -> String {
    value_json(value).to_string()
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

#[cfg(test)]
mod membership_term_tests {
    //! The term path at the materializer seam. subql owns classification, so
    //! what these pin is connetto's own share: the caller mapping reaches the
    //! reverse translation, the canonical shape extracts against the catalog,
    //! the subscriber is typed at the catalog's kind, and a term the seed
    //! cannot serve is refused rather than served half-way.

    use super::*;
    use crate::capability::DEFAULT_USER_SETTING;
    use crate::openfga::Translated;
    use subql::term::TermDescription;

    /// The motivating pair: a guarded table filtered through a membership.
    const SCHEMA: &str = "CREATE TABLE docs (id BIGINT PRIMARY KEY, project_id BIGINT NOT NULL);\nCREATE TABLE project_members (project_id BIGINT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (project_id, user_id));";

    /// The membership-shaped policy the deployment would carry on `docs`.
    const POLICIES: &str = "ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\nCREATE POLICY docs_members ON docs FOR ALL USING (project_id IN (SELECT project_id FROM project_members WHERE user_id = current_setting('app.user_id', true)));";

    /// The client's own SQLite spelling of the motivating filter.
    const CLIENT_SQL: &str = "SELECT * FROM docs WHERE project_id IN (SELECT project_id FROM project_members WHERE user_id = current_app_user())";

    fn materializer(caller: Option<SessionVariableMapping>) -> Materializer {
        let translator = Translated::of::<String>(SCHEMA, POLICIES, DEFAULT_USER_SETTING)
            .expect("the motivating policy translates")
            .into_parts()
            .1;
        Materializer::with_translation(
            SCHEMA,
            RuntimeWritableCatalog::default(),
            translator,
            caller,
        )
        .expect("the schema parses")
    }

    fn mapping() -> SessionVariableMapping {
        SessionVariableMapping::current_setting(DEFAULT_USER_SETTING, "current_app_user")
    }

    // The whole happy path at this seam: the caller rewrites, the canonical
    // shape extracts with the catalog's own kinds, and the seeded request
    // registers as a row subscription.
    #[test]
    fn a_seeded_membership_term_registers() {
        let mut mat = materializer(Some(mapping()));
        let pg_sql = mat
            .translate_subscription_sql(CLIENT_SQL)
            .expect("the caller function reverse translates");
        assert!(
            pg_sql.contains("current_setting"),
            "the mapping must rewrite the caller, got {pg_sql}"
        );
        let terms = mat
            .describe_terms(1, &pg_sql, &[])
            .expect("the canonical shape describes");
        let [term] = terms.as_slice() else {
            panic!("one canonical term describes, got {terms:?}");
        };
        let TermDescription::Membership(membership) = term else {
            panic!("expected a membership term");
        };
        assert_eq!(membership.pairs[0].column, "project_id");
        assert_eq!(membership.member_table, "project_members");
        assert_eq!(membership.pairs[0].member_key, "project_id");
        assert_eq!(membership.subject_kind, ScalarKind::String);
        assert_eq!(membership.member_subject, "user_id");
        assert!(
            membership.seed_sql.contains("project_members"),
            "the seed reads the membership table, got {}",
            membership.seed_sql
        );
        let subscriber = typed_subscriber("alice", membership.subject_kind)
            .expect("a text subject takes any string");
        let seed = TermSeed {
            subscriber,
            term_values: vec![(
                vec![membership.pairs[0].column.clone()],
                vec![vec![PgValue::Int(7)]],
            )],
        };
        let registration = match mat.register_translated(
            1,
            &pg_sql,
            &[],
            Some(seed),
            ReadBudget::new(core::time::Duration::from_secs(5)),
        ) {
            Ok(registration) => registration,
            Err(err) => panic!("the seeded term must register, got {err}"),
        };
        assert!(matches!(registration, Registration::Row(_)));
    }

    // subql requires the subscriber for any filter naming a term, which is
    // what makes an unrecognised shape safe: it registers unseeded and is
    // refused rather than served by one executor only.
    #[test]
    fn an_unseeded_term_is_refused_at_registration() {
        let mut mat = materializer(Some(mapping()));
        let pg_sql = mat
            .translate_subscription_sql(CLIENT_SQL)
            .expect("translates");
        let refused = mat.register_translated(
            1,
            &pg_sql,
            &[],
            None,
            ReadBudget::new(core::time::Duration::from_secs(5)),
        );
        assert!(
            matches!(refused, Err(MaterializerError::Register(_))),
            "a term without a subscriber must be refused"
        );
    }

    // Hazard 1: the subscriber is built at the column's kind or not at all.
    #[test]
    fn the_subscriber_is_typed_at_the_columns_kind() {
        assert_eq!(
            typed_subscriber("alice", ScalarKind::String),
            Some(PgValue::String("alice".to_owned()))
        );
        assert!(typed_subscriber("alice", ScalarKind::Uuid).is_none());
        assert!(typed_subscriber("alice", ScalarKind::Int).is_none());
        assert_eq!(
            typed_subscriber("42", ScalarKind::Int),
            Some(PgValue::Int(42))
        );
        assert!(matches!(
            typed_subscriber("0193c8e5-1111-7abc-8def-000000000000", ScalarKind::Uuid),
            Some(PgValue::Uuid(_))
        ));
        assert!(typed_subscriber("alice", ScalarKind::Bytes).is_none());
    }

    // Without the deployment's mapping the client's caller function cannot
    // reach Postgres as anything it answers, so registration refuses loudly
    // instead of serving a filter one executor cannot run.
    #[test]
    fn without_the_mapping_the_caller_query_is_refused() {
        let mut mat = materializer(None);
        assert!(
            mat.register_sqlite(
                1,
                CLIENT_SQL,
                &[],
                ReadBudget::new(core::time::Duration::from_secs(5))
            )
            .is_err(),
            "an unmapped caller function must refuse loudly"
        );
    }

    // Shapes outside the single-link form seed nothing. subql answers them
    // itself now, so this pins what it answers rather than what connetto's
    // own walk used to recognise (R63).
    #[test]
    fn a_non_canonical_shape_describes_no_term() {
        let mat = materializer(Some(mapping()));
        assert!(
            mat.describe_terms(1, "SELECT * FROM docs WHERE project_id > 5", &[])
                .expect("a literal comparison is an ordinary predicate")
                .is_empty(),
            "a comparison against a literal is not a membership subquery"
        );
        let joined = "SELECT * FROM docs WHERE project_id IN (SELECT pm.project_id FROM project_members pm JOIN docs d ON d.project_id = pm.project_id WHERE pm.user_id = current_setting('app.user_id', true))";
        let described = mat.describe_terms(1, joined, &[]);
        assert!(
            matches!(described, Err(MaterializerError::Register(_))),
            "a subquery joining a second table is outside the shape subql compiles, \
             so it is refused rather than described, got {described:?}"
        );
    }
}
