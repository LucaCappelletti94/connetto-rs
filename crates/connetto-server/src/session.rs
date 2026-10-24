//! Session manager, per-session state machine, the snapshot seam, and the
//! write path.
//!
//! One [`SessionManager`] fronts a shared [`Materializer`], a routing table, a
//! visibility policy, and the server's write target. Each connection is driven
//! by [`SessionManager::serve`], which runs the handshake, then a select loop
//! over inbound control frames and outbound live patches. CDC events reach
//! subscribed sessions through [`SessionManager::dispatch_event`].
//!
//! Flow control charges a credit only to bulk-plane frames
//! (`LivePatch`/`SnapshotPatch`), never to control frames, so keepalive can
//! never deadlock on an empty credit window. See
//! `docs/architecture/10-subscription-materializer.md` and `02-protocol.md`.
//!
//! The write path pairs a `MutationHeader` with the `MutationPatch` that follows
//! it, authorizes every op, detects stale-version conflicts, applies the whole
//! changeset in one transaction, and replies on every outcome: `MutationApplied`
//! on a durable apply, `MutationReject` or `MutationConflict` otherwise. The
//! write applies to the source Postgres under the caller's RLS context.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use connetto_core::auth::{AuthContext, Principal, Subject, VerifiedSession};
use connetto_core::chain::{self, GENESIS};
use connetto_core::device_cert::{KeyId, spki_point};
use connetto_core::messages::{
    AggregateUpdate, BindDevice, BindValue, BotRegistered, BulkMessage, CONTENT_TICKET_REFUSED,
    CONTENT_TICKET_SIGNER_ERROR, Challenge, ConflictRow, ContentTicketGrant, ContentTicketRequest,
    ContentVerb, ControlMessage, DeviceRevokedAck, DevicesList, DevicesRequest, EnrolChallenge,
    EnrolRefusal, EnrolRefused, FatalError, FatalErrorReason, FullResyncReason, FullResyncRequired,
    Grant, Handshake, HandshakeAck, LivePatch, MembershipOpened, MutationApplied, MutationConflict,
    MutationHeader, MutationPatch, MutationReject, MutationRejectReason, NonFatalError, PauseCause,
    Pong, Provenance, RateLimited, RegisterBot, ReplaceShareKeys, RetireWriter, RevocationUpdate,
    RevokeDeviceRequest, SUBSCRIPTION_REFUSED, ShareKeysReplaced, SignedList, SnapshotBegin,
    SnapshotEnd, SnapshotPatch, Subscribe, SubscriptionSpec, WriterAnswer, WriterGrant,
    WriterOutcome, WriterRef, WriterRequest, bot_registration_message, writer_bind_message,
};
use connetto_core::traits::{
    CheckedGrant, ContentTicketSigner, HandshakeAuthority, IncomingFrame, Transport,
};

use crate::device_cert::RevokeError;
use connetto_core::{Backoff, Cursor, PROTOCOL_VERSION, RetryPolicy, SchemaVersion, SessionId};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::bb8::Pool;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ECDSA_P256_SHA256_ASN1, ED25519, UnparsedPublicKey};
use sha2::{Digest, Sha256};
use sqlite_diff_rs::{
    DiffOps, Indirect, ParsedDiffSet, PatchDelete, PatchSet, PatchsetOp, TableSchema,
};
use subql::backend::{CdcEvent, Postgres, ScalarFamily, Value as PgValue};
use subql::term::{TermCaller, TermDescription};
use subql::visibility::transition::{Transition, TransitionError, Transitions, transitions};
use subql::visibility::{EventRow, RowWrite, Verdict, VisibilityPolicy};
use subql::{
    AdvanceCursorError, CdcSource, Checkpoint, DatabaseLike, EventKind, OpaqueCheckpoint, ParserDB,
    PgChangeEvent, PgCommit, PgCommitPosition, PgLsn, Seen, SourceItem, SubscriptionId, TableLike,
};
use tokio::sync::{Mutex, mpsc};
use tracing::Instrument;
use uuid::Uuid;

use crate::abuse::{Caller, Reaction};
use crate::bots::schema::{ListEntry, PgBotRegistry, RegistryError, Verb};

use crate::audit::{AuthEvent, AuthOp};
use crate::counters;
use crate::courier::{CourierDelivery, CourierEntry, CourierRefusal};
use crate::fence::{ReadFence, split_snapshot_cursor};
use crate::guard::RequestGuard;
use crate::materializer::{
    ComputedCapture, ComputedChange, MatchedPatch, Materializer, MaterializerError, PlannedWrite,
    ReadConnector, Registration, RuntimeWritableCatalog, SeedPlan, TermMove, TermSeed, compress,
    narrowed_sql, typed_subscriber,
};
use crate::openfga::{GrantHolder, GrantMove};
use crate::oplog::{CatchupDecision, ChangeRecord, InMemoryOplog, Oplog, catchup_decision};
use crate::reexec::{FailedRead, NoConnector, ReadBudget, ReadFailure};
use crate::reserve::{ReaderPermit, ReaderReservation};
use crate::row_view::ValuesRow;
use crate::schema::ConnettoSchema;
use crate::slot::SlotError;
use crate::throttle::{ReadLimits, Tier};
use crate::timeline::{Position, TimelineError, TimelineHistory};
use crate::write_target::{PgWriteTarget, SettleSpec, Settlement, WriteError, WriteOutcome};
use crate::writer_schema::{SettlePath, SettledOutcome, SettledRow, WriterRow};
use connetto_core::auth::CapabilityKey;
use connetto_core::auth::CapabilitySubject;

/// One page of a subscription's initial rows, produced by a [`SnapshotSource`].
pub struct SnapshotPage {
    /// Raw (uncompressed) insert-patchset bytes for this page's rows.
    pub patchset: Vec<u8>,
    /// Cursor at which this page was read. Live updates strictly greater
    /// than this apply on top on the client.
    pub cursor: Cursor,
    /// Where the next page resumes, or [`None`] when nothing follows this
    /// page.
    pub next: Option<PageKey>,
    /// Whether the read had more rows than this page's allowance.
    ///
    /// Filled with no resume point is a read that cannot be paged, and the
    /// caller must refuse it. Reporting it separately is what keeps the seam
    /// unable to answer a truncation as though it were complete.
    pub filled: bool,
    /// The largest single row this page carries, in bytes, which the caller
    /// judges against its tier's ceiling.
    pub widest_row: u64,
    /// How many rows this page carries.
    pub rows: u32,
    /// What this page's rows measure, summed over their column values.
    ///
    /// Measured rather than predicted, so the caller can size the next page
    /// from what this one actually cost. The planner's own width counts a
    /// value stored out of line as its pointer, so a prediction alone is not
    /// enough to bound a page.
    pub bytes: u64,
}

/// The primary key of the last row a page delivered, in key order.
///
/// Opaque to the session, which hands it back to the source that produced it.
/// Keyset rather than an offset because offset paging costs O(offset) per
/// page, measured under R58 decision 6.
pub struct PageKey {
    /// The key columns' values, in key order.
    pub values: Vec<PgValue<Postgres>>,
}

/// What one page of a read may carry, and where it starts.
pub struct PageSpec {
    /// Resume past this key, or start at the beginning of the read.
    pub after: Option<PageKey>,
    /// How many rows this page may carry.
    pub max_rows: u32,
    /// The wall-clock ceiling on this page's read.
    pub timeout: Duration,
}

/// What the backend predicts one read will produce.
///
/// Both numbers come from one round trip, which is what makes deriving a row
/// cap from a byte budget free (R58 decision 3).
pub struct SnapshotEstimate {
    /// Rows the planner expects the read to return.
    pub rows: f64,
    /// Average row width in bytes the planner expects.
    pub width: u32,
}

/// The caller's own membership rows for a term at registration, read by a
/// [`SnapshotSource`] that can run the seed under the caller's own binding.
pub struct TermSeedRead {
    /// The value rows the membership rows admit, each the subject granting it
    /// and then one cell per compared pair in the term's stated order,
    /// decoded the same way the snapshot decodes, so the seed and the
    /// snapshot agree by construction.
    ///
    /// The subject rides along because a caller is a set. A value two of its
    /// subjects grant has to survive either one of them losing its
    /// membership, and only the row's own subject says which withdrawal
    /// touches it.
    pub rows: Vec<(PgValue<Postgres>, Vec<PgValue<Postgres>>)>,
    /// Whether the membership table is carried by the publication this source
    /// was configured with, or `None` when it has none to check against.
    pub published: Option<bool>,
}

/// Which of the caller's values a described term reads.
const fn caller_of(term: &TermDescription) -> TermCaller {
    match term {
        TermDescription::Membership(membership) => membership.caller,
        TermDescription::Caller(caller) => caller.caller,
    }
}

/// The one kind every term reading `side` compares at.
///
/// The engine builds one subscriber and one subject set per registration, so
/// two terms reading the same side at different kinds cannot share it. They
/// are refused rather than served at whichever kind came first, which would
/// admit nobody in silence for the other.
fn one_kind(terms: &[TermDescription], side: TermCaller) -> Result<ScalarFamily, SubscribeRefusal> {
    let mut kinds = terms
        .iter()
        .filter(|term| caller_of(term) == side)
        .map(|term| match term {
            TermDescription::Membership(membership) => membership.subject_kind,
            TermDescription::Caller(caller) => caller.kind,
        });
    let first = kinds.next().ok_or(SubscribeRefusal::Mistyped)?;
    if kinds.any(|kind| kind != first) {
        return Err(SubscribeRefusal::Mistyped);
    }
    Ok(first)
}

/// Every subject the caller holds, typed at the compared column's kind, the
/// identity first when it has one and then each capability key.
///
/// A caller is a set, the same set [`CallerBinding`](crate::capability) hands
/// Postgres, so a membership row naming any of them moves what the filter
/// admits here exactly as it does in the database.
///
/// Each key has to render here exactly as `CallerBinding` packs it into
/// `app.subjects` through [`CapabilityKey::pack`], because that packed list
/// is what the membership subquery compares against in SQL. A change to
/// either rendering that the other does not follow leaves the seed matching
/// no membership row while the database still matches one, which admits
/// fewer rows in silence.
///
/// A subject that cannot be built at the column's kind refuses the whole
/// registration rather than being dropped from the set, because a seed short
/// one subject admits fewer rows than the query the caller registered
/// returns, and nothing later repairs that.
///
/// An empty set is refused too: a filter reading the subject set could never
/// deliver to a caller holding none.
fn caller_subjects<Id: core::fmt::Display, Key: CapabilityKey>(
    identity: Option<&AuthContext<Id>>,
    capabilities: &[CapabilitySubject<Key>],
    kind: ScalarFamily,
) -> Result<Vec<PgValue<Postgres>>, SubscribeRefusal> {
    let mut subjects = Vec::with_capacity(1 + capabilities.len());
    if let Some(identity) = identity {
        subjects.push(
            typed_subscriber(&identity.user_id.to_string(), kind)
                .ok_or(SubscribeRefusal::Mistyped)?,
        );
    }
    for capability in capabilities {
        let subject = typed_subscriber(&capability.key().to_string(), kind)
            .ok_or(SubscribeRefusal::Mistyped)?;
        if !subjects.contains(&subject) {
            subjects.push(subject);
        }
    }
    if subjects.is_empty() {
        return Err(SubscribeRefusal::Anonymous);
    }
    Ok(subjects)
}

/// The client-dialect test for "this column names one of the caller's
/// subjects", in the one shape the reverse translation reads as a membership
/// over a delimited setting.
///
/// Spelled the way pg2sqlite emits it rather than the obvious way, because
/// the recognizer matches this guarded form and reads a bare `instr` search
/// as a position query instead. The guards are what make it agree with
/// `= ANY(string_to_array(...))` on the cases a plain substring search gets
/// wrong: an unset setting, an empty one, and a column value that itself
/// contains the delimiter.
pub fn subject_set_reach(function: &str, column: &str, separator: char) -> String {
    format!(
        "CASE WHEN {function}() IS NOT NULL THEN {function}() <> '' \
         AND instr({column}, '{separator}') = 0 \
         AND instr('{separator}' || {function}() || '{separator}', \
         '{separator}' || {column} || '{separator}') > 0 END"
    )
}

/// A mapping the mirror needed and the deployment did not bind.
#[derive(Debug, PartialEq, Eq)]
enum MirrorGap {
    /// No identity function, and a term over the table reads the identity.
    Identity,
    /// No subject-set function, and a term over the table reads the set.
    Subjects,
}

/// What the mirror over `member` reads under: one reach per caller kind a
/// term over that table declares, joined by `OR`.
///
/// Joined rather than one mirror per kind, because the mirror is keyed by
/// table and opened once. A table watched by an identity term and a
/// subject-set term at once is mirrored under both, and dropping either
/// would leave that kind's membership moves undelivered with nothing said.
fn mirror_predicate(
    member: &MemberTable,
    identity_function: Option<&str>,
    subjects_function: Option<&str>,
    separator: char,
) -> Result<String, MirrorGap> {
    let subject = connetto_core::quote_ident(&member.subject);
    let mut reaches: Vec<String> = Vec::new();
    if member.identity {
        let function = identity_function.ok_or(MirrorGap::Identity)?;
        reaches.push(format!("{subject} = {function}()"));
    }
    if member.subjects {
        let function = subjects_function.ok_or(MirrorGap::Subjects)?;
        reaches.push(subject_set_reach(function, &subject, separator));
    }
    Ok(reaches.join(" OR "))
}

/// One membership table a subscription's term watches, and how the mirror
/// over it has to name the caller.
///
/// The caller kind rides along because the mirror is written per term: a term
/// reading the identity mirrors the caller's own rows, and one reading the
/// subject set mirrors every row any subject it holds grants.
#[derive(Clone, Debug)]
struct MemberTable {
    /// The membership table, by catalog name.
    table: String,
    /// The column naming the subject a row admits.
    subject: String,
    /// Whether a term over this table compares that column to the identity.
    identity: bool,
    /// Whether a term over this table compares it to the subject set.
    subjects: bool,
}

/// Why a subscription was not registered, beyond the materializer's own
/// refusals. Every cause is answered on the wire with the one fixed
/// `SUBSCRIPTION_REFUSED` detail (R38), so this exists for the structured log.
#[derive(Debug, thiserror::Error)]
enum SubscribeRefusal {
    /// Translation or registration was refused.
    #[error(transparent)]
    Materializer(#[from] MaterializerError),
    /// The seed read failed.
    #[error("the membership seed read failed: {0}")]
    Seed(String),
    /// A membership term filters for a caller, and this one has no identity.
    #[error("a membership term needs an identified caller")]
    Anonymous,
    /// The identity cannot be read at the membership column's kind. A
    /// mistyped subscriber would admit nobody in silence, so it refuses.
    #[error("the caller's identity cannot be read at the membership column's kind")]
    Mistyped,
    /// The membership table is not replicated, so no membership change would
    /// ever move rows and the term would go stale silently.
    #[error(
        "membership table {0} is not carried by the publication, so a membership change would never move rows"
    )]
    Unpublished(String),
    /// The snapshot source has no publication to verify against.
    #[error(
        "no publication is configured on the snapshot source, so a membership table cannot be verified as replicated"
    )]
    NoPublication,
    /// The snapshot source cannot run a seed read.
    #[error("this snapshot source cannot seed a membership term")]
    Unseedable,
    /// The table's predicted average row is already above the ceiling one
    /// delivered row may reach, so no page of it can be served (R58).
    #[error(
        "the read was refused before it ran: the table's average row is {width} bytes, the ceiling on one row is {ceiling}"
    )]
    TableTooWide {
        /// The planner's predicted average row width.
        width: u32,
        /// The tier's ceiling on one row.
        ceiling: u64,
    },
    /// One row of the read is above the ceiling. The three numbers together
    /// say whether the ceiling is set too low or the schema stores
    /// file-shaped data (R58 decision 7).
    #[error(
        "a row of {bytes} bytes is above the {ceiling} byte ceiling, on a table averaging {average} bytes a row"
    )]
    WideRow {
        /// The offending row's size.
        bytes: u64,
        /// The tier's ceiling on one row.
        ceiling: u64,
        /// The table's predicted average row width, for comparison.
        average: u32,
    },
    /// The read filled its page and cannot be paged, because the
    /// subscription's projection carries no primary key to resume from.
    #[error("the read filled its page of {cap} rows and its projection carries no primary key")]
    Unpageable {
        /// The page's row cap.
        cap: u32,
    },
    /// A page after the first failed, and the replacement read failed too.
    #[error("a paged read failed part way through and could not be restarted: {0}")]
    Interrupted(String),
    /// The estimate the page size is derived from could not be read.
    #[error("the read estimate failed: {0}")]
    Estimate(String),
}

/// The server-chosen label of the membership subscription over `member_table`
/// (R27 decision 7). Deterministic, so a term registering again on the same
/// session finds the one already open instead of opening a second, and the
/// prefix is a reserved wire namespace the client can classify by.
fn membership_label(member_table: &str) -> String {
    format!("connetto-membership:{member_table}")
}

/// Produces a subscription's initial rows for a given identity, one page at a
/// time.
///
/// Implemented over Postgres by
/// [`PgSnapshotSource`](crate::PgSnapshotSource): run the subscription's
/// `SELECT` against the backend at a snapshot LSN and encode the rows into an
/// insert-patchset with `sqlite-diff-rs`. No SQLite lives on the backend. The
/// `caller` lets the implementation run the read under the requesting
/// principal's Row-Level Security so the rows already exclude what it cannot
/// see.
///
/// A read arrives in pages because a legitimately large read is the product,
/// not an abuse: the first sync of a new device and a resync the server itself
/// demands are both the whole working set (R58 decision 6). The session paces
/// the pages with the delivery credits it already has.
#[expect(
    async_fn_in_trait,
    reason = "the futures are bound by MaybeSend, which is Send on native, so the auto trait warning does not apply"
)]
pub trait SnapshotSource<Id = String, Key = String>: Send + Sync {
    /// Snapshot-source error.
    ///
    /// [`FailedRead`] because the session answers each failure class
    /// differently (R89 decision 1).
    type Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static + FailedRead;

    /// What the backend predicts `select_sql` will produce, as `caller`.
    ///
    /// Asked before the read is spent: the predicted width sizes the page, and
    /// a predicted average row already above the ceiling on one row is refused
    /// without reading anything.
    ///
    /// # Errors
    ///
    /// Implementation-defined: a backend read or a plan that does not parse.
    async fn estimate(
        &self,
        select_sql: &str,
        binds: &[BindValue],
        caller: &Principal<Id, Key>,
    ) -> Result<SnapshotEstimate, Self::Error>;

    /// Produce one page of the initial rows for `select_sql`, authorized as
    /// `caller`.
    ///
    /// `select_sql` is the Postgres translation of the subscription query,
    /// never the client dialect, with `$N` placeholders paired to `binds` in
    /// order.
    ///
    /// A page that fills its allowance reports where the next one resumes. A
    /// read that fills its allowance and cannot be resumed must fail rather
    /// than return its first rows: a truncation the caller cannot tell from a
    /// complete answer is the one outcome this seam may never produce.
    ///
    /// # Errors
    ///
    /// Implementation-defined: a backend read or encoding failure, a row above
    /// the ceiling, or a read that filled a page it cannot resume.
    async fn snapshot_page(
        &self,
        select_sql: &str,
        binds: &[BindValue],
        caller: &Principal<Id, Key>,
        page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error>;

    /// Read the caller's own membership rows for a term at registration:
    /// `seed_sql` run as `caller` under the same binding the snapshot uses,
    /// plus whether `member_table` is carried by the configured publication.
    ///
    /// `member_subject` names the column the seed projects first, the subject
    /// granting each row, and `member_keys` names the columns it projects
    /// after it in order, one per compared pair. The source resolves all of
    /// them against its own catalog to pick each row's cells.
    ///
    /// The default cannot seed and returns `Ok(None)`, which refuses the
    /// registration: a term served without its seed admits nobody in silence,
    /// and a membership table outside the publication never narrows.
    ///
    /// # Errors
    ///
    /// Implementation-defined: a backend read or decode failure.
    async fn term_seed(
        &self,
        seed_sql: &str,
        member_table: &str,
        member_subject: &str,
        member_keys: &[String],
        caller: &Principal<Id, Key>,
    ) -> Result<Option<TermSeedRead>, Self::Error> {
        let _ = (seed_sql, member_table, member_subject, member_keys, caller);
        Ok(None)
    }
}

/// The products of registering one row subscription, as its delivery needs
/// them: the engine ids plus the Postgres translation of the query, which
/// the snapshot read uses instead of the client dialect.
#[derive(Clone)]
struct RowRegistration {
    /// The engine consumer bound to this subscription.
    consumer_id: u64,
    /// The engine subscription id.
    sub_id: SubscriptionId,
    /// The subscription query reverse translated to Postgres.
    pg_sql: String,
    /// The membership tables the subscription's terms watch, empty for a
    /// filter naming none (R27).
    member_tables: std::sync::Arc<[MemberTable]>,
    /// Whether a term of the filter reads the caller's subject set, which the
    /// registration's seed then holds, so a key change registers it again.
    reads_subjects: bool,
}

/// What registering one subscription produced, before it is known to be rows.
struct Registered {
    /// The classified registration.
    registration: Registration,
    /// The subscription query reverse translated to Postgres.
    pg_sql: String,
    /// The membership tables the filter's terms watch (R27).
    member_tables: std::sync::Arc<[MemberTable]>,
    /// Whether a term of the filter reads the caller's subject set.
    reads_subjects: bool,
}

impl Registered {
    /// The row registration this is, or the computed capture it is instead.
    fn into_row(self, consumer_id: u64) -> Result<RowRegistration, ComputedCapture> {
        match self.registration {
            Registration::Row(sub_id) => Ok(RowRegistration {
                consumer_id,
                sub_id,
                pg_sql: self.pg_sql,
                member_tables: self.member_tables,
                reads_subjects: self.reads_subjects,
            }),
            Registration::Computed(capture) => Err(capture),
        }
    }
}

/// Per-session server configuration.
///
/// Limits and abuse thresholds live on [`RequestGuard`] rather than here,
/// because one instance of it is shared with the auth service and this type is
/// cloned per manager.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Delivery credits granted to the server at handshake.
    initial_credits: u32,
    /// Schema version advertised in the handshake ack, or `None` to declare no
    /// version (staleness detection off for every client).
    schema_version: Option<SchemaVersion>,
    /// The total time one connection may wait on reconnect-log reads that failed transiently while resuming.
    resume_read_budget: Duration,
    /// How long one mutation may keep retrying an apply the database failed transiently before it is answered `Indeterminate`.
    write_retry_budget: Duration,
    /// The time one connection may stay open at its first frame before the registration gate closes it (R91).
    first_frame_budget: Duration,
    /// The silence after which an idle session is closed, reset by every inbound frame.
    idle_limit: Duration,
    #[cfg(feature = "test-seams")]
    key_expiry_clock: Option<tokio::sync::watch::Receiver<SystemTime>>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            initial_credits: 64,
            schema_version: None,
            resume_read_budget: Duration::from_secs(30),
            write_retry_budget: Duration::from_secs(5),
            first_frame_budget: Duration::from_secs(30),
            idle_limit: Duration::from_secs(60),
            #[cfg(feature = "test-seams")]
            key_expiry_clock: None,
        }
    }
}

impl SessionConfig {
    /// Returns the defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the delivery credits granted at handshake.
    #[must_use]
    pub const fn with_initial_credits(mut self, initial_credits: u32) -> Self {
        self.initial_credits = initial_credits;
        self
    }

    /// Sets the schema version advertised in the handshake ack.
    #[must_use]
    pub fn with_schema_version(mut self, schema_version: Option<SchemaVersion>) -> Self {
        self.schema_version = schema_version;
        self
    }

    /// Sets the total time one connection may wait on reconnect-log reads that failed transiently while resuming.
    #[must_use]
    pub const fn with_resume_read_budget(mut self, budget: Duration) -> Self {
        self.resume_read_budget = budget;
        self
    }

    /// Sets how long one mutation may keep retrying an apply the database failed transiently before it is answered `Indeterminate`.
    #[must_use]
    pub const fn with_write_retry_budget(mut self, budget: Duration) -> Self {
        self.write_retry_budget = budget;
        self
    }

    /// Sets the time one connection may stay open at its first frame before the registration gate closes it (R91).
    #[must_use]
    pub const fn with_first_frame_budget(mut self, budget: Duration) -> Self {
        self.first_frame_budget = budget;
        self
    }

    /// Sets the silence after which an idle session is closed, reset by every inbound frame.
    #[must_use]
    pub const fn with_idle_limit(mut self, limit: Duration) -> Self {
        self.idle_limit = limit;
        self
    }
    /// Uses the supplied time for share-key expiry scheduling and comparison.
    #[cfg(feature = "test-seams")]
    #[must_use]
    pub fn with_key_expiry_clock(
        mut self,
        clock: tokio::sync::watch::Receiver<SystemTime>,
    ) -> Self {
        self.key_expiry_clock = Some(clock);
        self
    }

    fn key_expiry_now(&self) -> SystemTime {
        #[cfg(feature = "test-seams")]
        if let Some(clock) = &self.key_expiry_clock {
            return *clock.borrow();
        }
        SystemTime::now()
    }

    /// Delivery credits granted at handshake.
    #[must_use]
    pub fn initial_credits(&self) -> u32 {
        self.initial_credits
    }

    /// The time one connection may stay open at its first frame before the registration gate closes it (R91).
    #[must_use]
    pub const fn first_frame_budget(&self) -> Duration {
        self.first_frame_budget
    }

    /// The silence after which an idle session is closed, reset by every inbound frame.
    #[must_use]
    pub const fn idle_limit(&self) -> Duration {
        self.idle_limit
    }
}
/// Backoff policy for reconnecting a dropped CDC stream.
///
/// [`SessionManager::ingest_with_reconnect`] reconnects the source after the
/// stream fails, resuming from the replication slot's confirmed position.
#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    /// Shared exponential backoff parameters.
    retry: connetto_core::RetryPolicy,
    /// A connection that stayed up at least this long is treated as healthy, so
    /// the backoff resets after it drops.
    healthy_after: Duration,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            retry: connetto_core::RetryPolicy::new().with_max_backoff(Duration::from_secs(30)),
            healthy_after: Duration::from_secs(10),
        }
    }
}

impl ReconnectPolicy {
    /// Returns the defaults: 200 ms initial backoff, 30 s ceiling, retry forever,
    /// 10 s healthy threshold.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the backoff before the first retry.
    #[must_use]
    pub fn with_initial_backoff(mut self, initial_backoff: Duration) -> Self {
        self.retry = self.retry.with_initial_backoff(initial_backoff);
        self
    }

    /// Sets the ceiling for the exponential backoff.
    #[must_use]
    pub fn with_max_backoff(mut self, max_backoff: Duration) -> Self {
        self.retry = self.retry.with_max_backoff(max_backoff);
        self
    }

    /// Sets the attempt limit. `None` retries forever.
    #[must_use]
    pub fn with_max_attempts(mut self, max_attempts: Option<u32>) -> Self {
        self.retry = self.retry.with_max_attempts(max_attempts);
        self
    }

    /// Sets the minimum uptime for a connection to be treated as healthy.
    #[must_use]
    pub const fn with_healthy_after(mut self, healthy_after: Duration) -> Self {
        self.healthy_after = healthy_after;
        self
    }

    /// Attempt limit. `None` retries forever.
    #[must_use]
    pub fn max_attempts(&self) -> Option<u32> {
        self.retry.max_attempts()
    }

    /// Start a reconnect episode under the shared schedule.
    #[must_use]
    pub fn start(&self) -> Backoff<'_> {
        self.retry.start()
    }
}

/// Whether a reconnect episode must stop: the loop counts every failed
/// connect, including the one that opened the episode, so `Some(n)` gives up
/// on failure number n.
const fn attempt_limit_reached(max_attempts: Option<u32>, failures: u32) -> bool {
    match max_attempts {
        Some(max) => failures >= max,
        None => false,
    }
}

/// Where a reconnected change feed resumes, shared between the ingest that moves it and the `connect` that reads it.
///
/// A handle rather than a value, because the checks a `connect` runs before
/// opening the stream can clear it, and a value read before them would resume
/// past a changed timeline or a skipped stretch and silently drop newer changes.
#[derive(Debug, Clone, Default)]
pub struct ResumePoint(Arc<parking_lot::Mutex<Option<PgCommitPosition>>>);

impl ResumePoint {
    /// The position the next stream starts after, for `PgStreamingConfig::start`, `None` when the slot's own position decides.
    #[must_use]
    pub fn get(&self) -> Option<PgCommitPosition> {
        *self.0.lock()
    }

    fn set(&self, position: Option<PgCommitPosition>) {
        *self.0.lock() = position;
    }
}

/// An event from [`SessionManager::ingest_with_reconnect`], for logging or
/// metrics. The loop is otherwise silent, so a caller wanting visibility into
/// reconnect churn observes it here.
#[derive(Debug)]
pub enum ReconnectEvent<'a> {
    /// The CDC stream failed; the loop retries after `backoff`.
    Retrying {
        /// Consecutive failed-attempt count (1-based).
        attempt: u32,
        /// Delay before the next connect.
        backoff: Duration,
        /// The failure that triggered the retry.
        error: &'a str,
    },
    /// The policy's `max_attempts` was reached; the loop stops.
    GaveUp {
        /// Total attempts made.
        attempts: u32,
        /// The last failure.
        error: &'a str,
    },
    /// The authorization service was unreachable for one event, so the ingest
    /// loop retries after `backoff` without reconnecting the change stream.
    AuthRetrying {
        /// Consecutive failed-attempt count (1-based) for this event.
        attempt: u32,
        /// Delay before the next authorization attempt.
        backoff: Duration,
        /// The error from the authorization service.
        error: &'a str,
    },
    /// A re-execution read could not be served, so the ingest loop retries
    /// the same event after `backoff` without reconnecting the change stream.
    ReadRetrying {
        /// Consecutive failed-attempt count (1-based) for this event.
        attempt: u32,
        /// Delay before the next read.
        backoff: Duration,
        /// The connector's failure text.
        error: &'a str,
    },
}

/// What the write question answered for a whole mutation.
///
/// Three answers rather than a boolean, because a refusal and a failure to
/// reach an answer reach the client as different reasons. Telling a client it
/// lacks permission when the truth is that the server cannot tell makes it stop
/// retrying and possibly discard the write, which turns a transient outage into
/// permanent loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteVerdict {
    /// Every op is allowed.
    Allowed,
    /// The policy refused one.
    Denied,
    /// The policy could not be reached, so no answer exists yet.
    Undetermined,
}

/// Failure surfaced by the session layer.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The underlying transport failed.
    #[error("transport error: {0}")]
    Transport(String),
    /// The snapshot source failed.
    #[error("snapshot error: {0}")]
    Snapshot(String),
    /// The read was refused on policy rather than failing: a row or a table
    /// above the tier's ceiling, or a read that filled a page it cannot
    /// resume (R58).
    ///
    /// Separate from [`Snapshot`](Self::Snapshot) because a failed read is
    /// worth retrying and a refused one is not: retrying a refusal replaces
    /// nothing, for ever, one log line at a time.
    #[error("read refused: {0}")]
    ReadRefused(String),
    /// The oplog backing store failed.
    #[error("oplog error: {0}")]
    Oplog(String),
    /// A materializer operation failed.
    #[error(transparent)]
    Materializer(#[from] MaterializerError),
    /// The peer violated the wire protocol.
    #[error("protocol violation: {0}")]
    Protocol(String),
    /// Compressing a bulk payload failed.
    #[error(transparent)]
    Compression(#[from] std::io::Error),
    /// The write target failed outside a mutation commit (the watermark read
    /// at handshake).
    #[error("write target error: {0}")]
    WriteTarget(String),
    /// The bot registry could not settle a registration because its pool was
    /// unreachable or a statement failed (R91). The connection drops rather
    /// than answering a refusal, because a failure is not a spent code, and
    /// answering it as a refusal would spend the bot's only code for nothing.
    #[error("bot registry error: {0}")]
    Registry(String),
    /// The ban list could not be read, so the handshake failed closed rather
    /// than admitting a caller whose ban might not have been seen.
    #[error("ban list error: {0}")]
    BanList(String),
    /// The resume credential could not be minted.
    #[error("resume credential: {0}")]
    Handle(String),
    /// The authorization service was unreachable while answering a visibility
    /// question. The ingest loop retries the same event rather than advancing
    /// past it.
    #[error("auth service unreachable: {0}")]
    AuthUnavailable(String),
    /// A computed subscription's read could not be served by a database the
    /// connector itself called unreachable. The ingest loop holds the event
    /// and retries it in place, pausing delivery (R89 decision 2), never
    /// reconnecting the change stream.
    #[error("database unreachable for a computed read: {0}")]
    ReadUnavailable(String),
    /// The change stream cannot answer what a row looked like before it
    /// changed, for the table named.
    ///
    /// Either the table does not record the previous image (`REPLICA IDENTITY`
    /// is not `FULL`) or the catalog does not know it. **Neither clears by
    /// itself**, so the ingest loop must not hold the event and retry: the
    /// server refuses to serve instead, and the restart meets the startup
    /// refusal naming the table (R6 decision 4).
    #[error(
        "the change stream cannot report the previous version of a row in {0}, so \
         a row that leaves a caller's reach cannot be taken back from them. Run \
         ALTER TABLE {0} REPLICA IDENTITY FULL"
    )]
    ChangeStreamUnusable(String),
    /// The authorization path refused an event for a reason the deployment fixes, so the server stops serving instead of retrying.
    #[error(
        "the authorization path cannot answer for a change in {table}, and asking again \
         gives the same answer: {reason}"
    )]
    AuthorizationUnanswerable {
        /// The changed row's table.
        table: String,
        /// What the authorization path reported.
        reason: String,
    },
}

/// Whether an authorization failure can clear by itself, which decides between holding an event and ending the change stream.
pub trait FailedAuthorization {
    /// Whether asking the same question again can give another answer.
    fn clears_by_itself(&self) -> bool;
}

impl FailedAuthorization for std::io::Error {
    fn clears_by_itself(&self) -> bool {
        true
    }
}

impl FailedAuthorization for core::convert::Infallible {
    fn clears_by_itself(&self) -> bool {
        match *self {}
    }
}

/// What the registry settled a registration into (R91).
#[derive(Debug)]
enum RegistrationOutcome {
    /// The bot's id, answered with the registered frame.
    Registered(Uuid),
    /// The registration was refused, answered with the refusal frame.
    Refused(RegistrationRefusal),
}

/// Why a registration was refused (R91), kept for the log line and nowhere else.
/// The wire carries the refusal frame without saying why.
#[derive(Debug)]
enum RegistrationRefusal {
    /// The list names a table the deployment does not sync.
    TableNotSynced {
        /// The table the entry named.
        #[expect(dead_code, reason = "the refusal is reported through its Debug")]
        table: String,
    },
    /// The list names a verb outside the four.
    UnknownVerb {
        /// The verb the entry named.
        #[expect(dead_code, reason = "the refusal is reported through its Debug")]
        verb: String,
    },
    /// The signature does not verify against the presented key for this
    /// connection's nonce.
    Signature,
    /// The code is unknown, expired or already used, or no registry is wired.
    Code,
}

/// Why the change feed could not be settled before opening.
#[derive(Debug, thiserror::Error)]
pub enum StreamCheckError {
    /// The database's timeline history could not be read.
    #[error(transparent)]
    Timeline(#[from] TimelineError),
    /// The replication slot's resume position could not be read.
    #[error("reading the replication slot: {0}")]
    Slot(#[from] SlotError),
    /// The reconnect log could not be read or trimmed.
    #[error("reconciling the change feed: {0}")]
    Session(#[from] SessionError),
}

/// What settling the change feed found before it opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamCheck {
    /// The system identifier of the database's cluster.
    pub system: u64,
    /// Where the slot resumes, when that is past the reconnect log.
    pub gap: Option<u64>,
}

fn transport_err<E: core::fmt::Display>(err: E) -> SessionError {
    SessionError::Transport(err.to_string())
}

fn oplog_err<E: core::fmt::Display>(err: E) -> SessionError {
    SessionError::Oplog(err.to_string())
}

/// Read the reconnect log through `read`, reading again after a transient failure while the connection's `budget` of waiting lasts.
///
/// Each read runs its own jittered episode of the default policy, 200 ms doubling to 5 s, so clients resuming together after a promotion do not read again in step, and each wait is cut to what is left of the budget and taken from it.
async fn read_log<O: Oplog, R, Fut>(
    budget: &mut Duration,
    mut read: impl FnMut() -> Fut,
) -> Result<R, SessionError>
where
    Fut: core::future::Future<Output = Result<R, O::Error>>,
{
    let policy = RetryPolicy::new();
    let mut episode = policy.start();
    loop {
        match read().await {
            Ok(value) => return Ok(value),
            Err(err) if O::is_transient(&err) => {
                if budget.is_zero() {
                    return Err(oplog_err(err));
                }
                let Some(wait) = episode.next_wait() else {
                    return Err(oplog_err(err));
                };
                let wait = wait.min(*budget);
                *budget -= wait;
                tracing::warn!(error = %err, wait_ms = retry_ms(wait), "the reconnect log did not answer a resume, reading it again");
                tokio::time::sleep(wait).await;
            }
            Err(err) => return Err(oplog_err(err)),
        }
    }
}

/// Take one row subscription out of the session, and with it every membership
/// subscription no other term still needs (R27 decision 7), returning the
/// route and registration of each to release. Synchronous so the callers'
/// futures stay no deeper than their own awaits.
fn take_row_subscription<Id, Key>(
    state: &mut SessionState<Id, Key>,
    label: &str,
) -> Vec<(u64, SubscriptionId)> {
    state.paging.retain(|read| read.label != label);
    let Some(row) = state.subs.remove(label) else {
        return Vec::new();
    };
    let mut taken = vec![(row.reg.consumer_id, row.reg.sub_id)];
    for member in row.reg.member_tables.iter() {
        let still_needed = state.subs.values().any(|sibling| {
            sibling
                .reg
                .member_tables
                .iter()
                .any(|other| other.table == member.table)
        });
        if still_needed {
            continue;
        }
        let hidden_label = membership_label(&member.table);
        state.paging.retain(|read| read.label != hidden_label);
        if let Some(hidden) = state.subs.remove(&hidden_label) {
            taken.push((hidden.reg.consumer_id, hidden.reg.sub_id));
        }
    }
    taken
}

/// A [`ContentTicketSigner`] for deployments without file handling.
///
/// `mint` always fails rather than panicking, since any client can send a
/// `ContentTicketRequest`.
pub struct NoSigner;

/// Nothing was wired to mint with.
#[derive(Debug)]
pub struct NoSignerConfigured;

impl core::fmt::Display for NoSignerConfigured {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("this deployment wired no content ticket signer")
    }
}

impl core::error::Error for NoSignerConfigured {}

impl ContentTicketSigner for NoSigner {
    type Error = NoSignerConfigured;

    fn mint(
        &self,
        _caller: &connetto_core::auth::ContentCaller,
        _file_id: [u8; 32],
        _verb: ContentVerb,
    ) -> impl core::future::Future<Output = Result<String, Self::Error>> + Send {
        core::future::ready(Err(NoSignerConfigured))
    }
}

/// A refusal's wait as the wire's milliseconds, saturating.
fn retry_ms(wait: Duration) -> u64 {
    u64::try_from(wait.as_millis()).unwrap_or(u64::MAX)
}

/// Where a handshake's cursor lets its subscriptions resume.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Resume {
    /// No position, which a client holding no rows presents.
    Fresh,
    /// A position the database's history still holds, and the fence of the snapshot that issued it.
    At(PgCommitPosition, Option<Arc<ReadFence>>),
    /// A position past where its timeline ended, naming changes the database lost, or one this server cannot read (R73).
    BeyondHistory,
}

impl Resume {
    /// Judge `cursor` against the database's `history`.
    fn of(cursor: Option<&Cursor>, history: &TimelineHistory) -> Self {
        let Some(bytes) = cursor
            .map(Cursor::as_bytes)
            .filter(|bytes| !bytes.is_empty())
        else {
            return Self::Fresh;
        };
        match Position::from_fenced_cursor(bytes) {
            Some((position, _)) if position.at.commit_lsn() == PgLsn(0) => Self::Fresh,
            Some((position, fence)) if history.contains(position) => {
                Self::At(position.at, fence.map(Arc::new))
            }
            Some(_) | None => Self::BeyondHistory,
        }
    }
}

/// The word for a checked subject in the log, so a refusal can be counted and
/// filtered by kind without parsing a sentence.
const fn subject_kind<Id, Key>(subject: &Subject<Id, Key>) -> &'static str {
    match subject {
        Subject::Identity(_) => "user",
        Subject::Capability(_) => "key",
    }
}

/// Where a list of grants came from, which names the refusal's log line.
#[derive(Clone, Copy)]
enum GrantSource<'a> {
    /// A handshake, by the client's correlation label.
    Handshake(&'a str),
    /// A key swap, by its request id (R95).
    Swap(&'a str),
}

impl GrantSource<'_> {
    /// Record one refused grant, the only place a refusal is visible.
    fn log_refusal(self, position: u64, reason: &str, detail: &str) {
        match self {
            Self::Handshake(client_id) => tracing::warn!(
                client_id = %client_id,
                grant = position,
                reason,
                detail,
                "grant refused"
            ),
            Self::Swap(request_id) => tracing::warn!(
                request_id = %request_id,
                grant = position,
                reason,
                detail,
                "grant refused"
            ),
        }
    }
}

/// The renderings of a set of held keys, as a policy compares them.
fn rendered_keys<Key: CapabilityKey>(keys: &[CapabilitySubject<Key>]) -> BTreeSet<String> {
    keys.iter().map(|key| key.key().to_string()).collect()
}
/// What a list of grants resolved to.
struct ResolvedGrants<Id, Key> {
    /// The caller the grants name, on the handle they were checked for.
    principal: Principal<Id, Key>,
    /// When each resolved key dies, in Unix seconds by its rendering.
    key_expiry: BTreeMap<String, u64>,
    /// How many grants were refused.
    refusals: u32,
    /// The wait the refused-grant limit imposed, when it was crossed.
    wait: Option<Duration>,
}

/// Whether a change of the caller's share keys can change what one row
/// subscription delivers.
///
/// `key_tables` is `None` when no authorization store reports which tables
/// read the keys, and then every subscription is taken as reached.
fn key_change_reaches(reg: &RowRegistration, key_tables: Option<&[String]>) -> bool {
    reg.reads_subjects
        || key_tables.is_none_or(|tables| {
            crate::snapshot::table_from_select(&reg.pg_sql)
                .map_or(true, |table| tables.contains(&table))
        })
}

/// Resolve when the earliest held key dies, and never while none is held.
async fn next_key_expiry(expiry: &BTreeMap<String, u64>, config: &SessionConfig) {
    let Some(&earliest) = expiry.values().min() else {
        return core::future::pending().await;
    };
    #[cfg(feature = "test-seams")]
    if let Some(clock) = &config.key_expiry_clock {
        let mut clock = clock.clone();
        loop {
            if clock
                .borrow_and_update()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                >= earliest
            {
                return;
            }
            if clock.changed().await.is_err() {
                return core::future::pending().await;
            }
        }
    }
    let now = config
        .key_expiry_now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    tokio::time::sleep(Duration::from_secs(earliest).saturating_sub(now)).await;
}

/// Map a materializer failure to the reason sent back on the wire.
pub(crate) fn reject_reason(err: &MaterializerError) -> MutationRejectReason {
    match err {
        MaterializerError::Parse(detail) => MutationRejectReason::Malformed {
            detail: detail.clone(),
        },
        MaterializerError::NotWritable(_) | MaterializerError::SchemaMismatch(_) => {
            MutationRejectReason::SchemaMismatch
        }
        MaterializerError::Apply(inner) => MutationRejectReason::Constraint {
            detail: inner.to_string(),
        },
        other => MutationRejectReason::Other {
            detail: other.to_string(),
        },
    }
}

/// Whether a writer row's account is the caller's, the Display rendering
/// standing in for the id's equality at this edge, the same spelling every
/// Postgres binding and registry key uses.
fn same_account<Id: core::fmt::Display>(row_user: Option<&Id>, caller_user: Option<&Id>) -> bool {
    match (row_user, caller_user) {
        (Some(owner), Some(caller)) => owner.to_string() == caller.to_string(),
        _ => false,
    }
}

/// A frame queued for a session's outbound path.
enum Outbound {
    /// A live row patch (bulk plane, credit-gated).
    Live(LivePatch),
    /// An aggregate value update (control plane, never credit-gated).
    Aggregate(AggregateUpdate),
    /// A fatal close: the pump sends it as a control frame and ends the
    /// session (revocation and supersession arrive this way).
    Fatal(FatalError),
    /// End the session without sending anything. A ban tells the caller
    /// nothing, so it draws no frame and no reason.
    Drop,
    /// A non-fatal control frame delivered immediately, bypassing the bulk
    /// queue. Used for session-wide notifications such as delivery paused or
    /// resumed.
    Control(ControlMessage),
    /// Re-read one row subscription and replace what the client holds, because
    /// a grant reaching its table moved (R7) or a table it reads was emptied
    /// (R48). Carried as an instruction rather than as frames because only this
    /// session's own task holds the transport, and the notice and its
    /// replacement must stay one ordered pair.
    Resnapshot {
        /// The client-facing label of the subscription to replace.
        sub_id: String,
        /// What the client is told, which decides how much it clears: only a
        /// truncate entitles it to delete a whole table regardless of what a
        /// sibling subscription still claims.
        reason: FullResyncReason,
    },
    /// Replace the row registration that still owns a requested reader reservation.
    ReservedResnapshot {
        sub_id: String,
        owner: (u64, SubscriptionId),
        permit: ReaderPermit,
    },
    /// Rebuild the computed registration that still owns this label.
    Rebootstrap {
        sub_id: String,
        retired_id: SubscriptionId,
    },
    /// End one row subscription a key change left unservable, in order behind
    /// the frames already queued for it (R95).
    Refuse {
        /// The client-facing label of the subscription.
        sub_id: String,
    },
}

/// Route from a `subql` consumer id back to the owning session's outbound
/// channel.
#[derive(Clone)]
struct Route<Id, Key> {
    /// The durable handle folded to the `u64` subql keys this session's
    /// per-subscription cursors on, stable across reconnects.
    session_key: u64,
    sub_id: SubscriptionId,
    label: String,
    tx: mpsc::UnboundedSender<Outbound>,
    /// The subscribing session's caller, consulted per event for the read
    /// filter before a live patch is delivered. Shared rather than copied,
    /// because the fan-out clones one route per subscriber per event.
    principal: Arc<Principal<Id, Key>>,
    /// The table this subscription reads, absent when the translated SQL names
    /// none the parser recognises. What a moved grant is matched against (R7).
    table: Option<String>,
    /// The subscription's Postgres SQL, for the move-in read a membership
    /// narrowing triggers (R27). Shared, because the fan-out clones one route
    /// per subscriber per event.
    pg_sql: std::sync::Arc<str>,
    /// The subscription's bind values, paired with `pg_sql`'s placeholders.
    binds: std::sync::Arc<[BindValue]>,
    /// The membership tables this subscription's terms watch, empty for a
    /// filter naming none. A grant moved by a change to one of these tables is
    /// served incrementally by the term's own move (R27 decision 2), so the
    /// R7 resend is suppressed for exactly these tables.
    member_tables: std::sync::Arc<[MemberTable]>,
    /// The fence of the snapshot a resumed subscription was issued after, which
    /// decides whether a change below where catchup left its cursor was missed.
    fence: Option<Arc<ReadFence>>,
}

/// Route from an aggregate subscription (re-execution query or delta aggregate)
/// to its session's outbound channel.
#[derive(Clone)]
struct AggRoute {
    label: String,
    tx: mpsc::UnboundedSender<Outbound>,
}

/// A live connection in the session registry: the socket counter that owns
/// the entry, the outbound channel a close is delivered on, and who holds it.
struct LiveSession {
    connection_num: u64,
    tx: mpsc::UnboundedSender<Outbound>,
    /// The identity's rendering, absent for a caller with no identity, so a ban
    /// can find every connection one person holds.
    user: Option<String>,
}

/// What a completed handshake establishes for the run loop.
struct HandshakeOutcome<Id, Key> {
    connection_num: u64,
    principal: Arc<Principal<Id, Key>>,
    resume: Resume,
    /// What is left of the connection's wait on reconnect-log reads after the handshake's.
    resume_read_budget: Duration,
    /// The writer this connection writes as, resolved at the handshake for a
    /// number request and set by the `BindDevice` for a device one, absent
    /// before that bind.
    writer_row: Option<WriterRow<Id>>,
    /// The challenge nonce of the round the handshake settled, the message a
    /// device key signs to bind its writer (R75).
    bind_nonce: [u8; 32],
    /// How many grants were refused, tallied for abuse once the run is
    /// registered so a crossing can close the connection it happened on.
    refused_grants: u32,
    /// The logging context, opened as soon as the run has a handle so that a
    /// refused grant is recorded inside it.
    span: tracing::Span,
    /// The sending half of the outbound channel, held by `SessionState`. Created here rather than in the run loop so the session is registered before the handshake ack leaves, since a revocation crossing that gap would otherwise find no session to close.
    outbound_tx: mpsc::UnboundedSender<Outbound>,
    /// The receiving half of the outbound channel, drained by the run loop.
    outbound_rx: mpsc::UnboundedReceiver<Outbound>,
    /// When each held share key dies, by its rendering.
    key_expiry: BTreeMap<String, u64>,
    /// Known completed subject coverage for the resume cursor.
    cursor_subjects: Option<BTreeSet<String>>,
}

/// One item waiting on the outbound queue.
///
/// Whether a frame is rationed and whether it is ordered against the data are
/// two separate questions, and the queue answers both. [`Rows`](Self::Rows)
/// costs a credit, because flow control exists to bound bulk. `SnapshotEnd`
/// costs nothing but must still travel behind the rows it completes, so it
/// waits in line and leaves free.
///
/// The set is closed on purpose. A control frame that must **not** be held
/// behind data, a `Pong` above all, has no variant here and cannot be queued
/// by accident: it goes straight out through `send_control`.
enum Deliverable {
    /// A bulk frame. Costs one credit.
    Rows(BulkMessage),
    /// The frame closing a snapshot. Ordered, never charged.
    SnapshotComplete(SnapshotEnd),
}

impl Deliverable {
    /// Whether sending this spends one of the client's delivery credits.
    const fn costs_credit(&self) -> bool {
        matches!(self, Self::Rows(_))
    }

    /// The subscription this frame belongs to.
    fn sub_id(&self) -> Option<&str> {
        match self {
            Self::Rows(BulkMessage::LivePatch(patch)) => Some(&patch.sub_id),
            Self::Rows(BulkMessage::SnapshotPatch(patch)) => Some(&patch.sub_id),
            Self::Rows(BulkMessage::MutationPatch(_)) => None,
            Self::SnapshotComplete(end) => Some(&end.sub_id),
        }
    }
}

/// One live row subscription, as the session has to remember it.
///
/// The request is kept because a resync re-reads the same set from the server
/// side: the client is told to discard what it holds and is handed a
/// replacement, so nothing asks it to describe the subscription again.
struct RowSub {
    reg: RowRegistration,
    sub: Subscribe,
    /// Bytes the first delivery carried, once it completed. The reference the
    /// growth warning is measured against (R58 decision 8).
    first_delivery: Option<u64>,
    /// Bytes delivered for this subscription over its whole life.
    delivered: u64,
    /// Whether the growth line has already been logged, so it fires once.
    warned: bool,
}

/// How far past its first delivery a standing request may grow before the
/// developer hears about it (R58 decision 8).
///
/// The live set stays the application's to bound, so this is a line in the log
/// and never a refusal.
const GROWTH_WARN_FACTOR: u64 = 100;

/// Log a refused read by name and produce the error the refusal path answers
/// with.
///
/// Every cause reaches the wire as the one fixed `SUBSCRIPTION_REFUSED`
/// detail (R38), so the cause exists for the structured log alone. A running
/// application cannot adapt to a read limit, by design: it is something a
/// developer meets in the log during development.
fn refuse_read(sub_id: &str, cause: &SubscribeRefusal) -> SessionError {
    tracing::warn!(sub_id = %sub_id, cause = %cause, "read refused");
    SessionError::ReadRefused(cause.to_string())
}

/// How many rows a page of a table averaging `width` bytes a row may carry
/// under a `budget` byte page.
///
/// An average, so a table whose row widths vary wildly still produces a page
/// well off the budget, and the planner approximates the width of a value
/// stored out of line. Never zero rows: a page cannot be smaller than one row,
/// which is why the ceiling on one row exists beside the budget.
fn page_rows(budget: u64, width: u32) -> u32 {
    let rows = budget / u64::from(width).max(1);
    u32::try_from(rows).unwrap_or(u32::MAX).max(1)
}

/// Whether a moved grant concerns this caller.
///
/// A key-shaped grantee is compared against the keys the session holds, in the
/// rendering [`ModelSubject`](crate::openfga::ModelSubject) asks questions
/// with, so a share or an installation withdrawn reaches its bearer and
/// disturbs no other subscriber.
fn concerns<Id, Key>(principal: &Principal<Id, Key>, holder: &GrantHolder) -> bool
where
    Id: core::fmt::Display,
    Key: core::fmt::Display,
{
    match holder {
        GrantHolder::Everybody => true,
        GrantHolder::Person(person) => principal
            .identity()
            .is_some_and(|identity| identity.user_id.to_string() == *person),
        GrantHolder::Subject(subject) => principal
            .capabilities()
            .iter()
            .any(|held| held.key().to_string() == *subject),
    }
}

/// Count what one subscription has delivered, and say once when a standing
/// request has grown far past what its first delivery was allowed.
///
/// The live set stays the application's to bound (R58 decision 8): an
/// application that does not want a table on a device asks a narrower
/// question. This is so the developer hears it from connetto rather than from
/// a complaint about a slow device. `budget` floors the comparison, so a tiny
/// first delivery does not warn on its second frame.
fn note_delivered<Id, Key>(
    state: &mut SessionState<Id, Key>,
    label: &str,
    bytes: u64,
    budget: u64,
) {
    let Some(row) = state.subs.get_mut(label) else {
        return;
    };
    row.delivered = row.delivered.saturating_add(bytes);
    if row.warned {
        return;
    }
    let Some(first) = row.first_delivery else {
        return;
    };
    if row.delivered > first.max(budget).saturating_mul(GROWTH_WARN_FACTOR) {
        row.warned = true;
        tracing::warn!(
            sub_id = %label,
            delivered = row.delivered,
            first_delivery = first,
            "a standing subscription has delivered far more than its first delivery, so its live set keeps growing"
        );
    }
}

/// Decide whether a page may be delivered, refusing by name when it may not.
///
/// Two refusals, both of them policy the tier owns rather than mechanics the
/// read owns: a row above the ceiling, logged with the three numbers that say
/// whether the ceiling is set too low or the schema stores file-shaped data,
/// and a read that filled a page it cannot resume, which must never be
/// answered with its first rows.
fn admit_page(
    sub_id: &str,
    page: &SnapshotPage,
    max_rows: u32,
    average: u32,
    limits: ReadLimits,
) -> Result<(), SessionError> {
    if page.widest_row > limits.row_ceiling {
        return Err(refuse_read(
            sub_id,
            &SubscribeRefusal::WideRow {
                bytes: page.widest_row,
                ceiling: limits.row_ceiling,
                average,
            },
        ));
    }
    if page.filled && page.next.is_none() {
        return Err(refuse_read(
            sub_id,
            &SubscribeRefusal::Unpageable { cap: max_rows },
        ));
    }
    Ok(())
}

/// What starting or restarting one read needs.
///
/// A bundle rather than five parameters, because a restart passes the same
/// five back and a positional list of them invites getting one wrong.
struct ReadStart {
    /// The request, so a restart re-reads the same set.
    sub: Subscribe,
    /// The engine ids and the translated query.
    reg: RowRegistration,
    /// The caller's tier, which the read limits come from.
    tier: Tier,
    /// The reader-pool share the delivery holds (R39).
    permit: Option<ReaderPermit>,
    /// Whether this read is itself the one restart a failed page gets.
    restarted: bool,
}

/// One initial read still arriving in pages.
///
/// Held by the session rather than by the read, because the pages are paced by
/// the client's delivery credits and the only path that can read an
/// acknowledgement is the same one a read would block (R33). So a page is
/// taken when an acknowledgement arrives and the producer waits here in
/// between.
struct PagedRead {
    /// The client's own label for the subscription.
    label: String,
    /// The request, so a restart can re-read the same set.
    sub: Subscribe,
    /// The engine ids and the translated query the pages are read from.
    reg: RowRegistration,
    /// Where the next page resumes.
    after: PageKey,
    /// How many rows a page of this read may carry, derived from the tier's
    /// byte budget and the table's predicted average row width.
    max_rows: u32,
    /// The tier's read limits, carried so every page of one read is judged by
    /// the limits the read started under.
    limits: ReadLimits,
    /// The table's predicted average row width, kept for the log line a
    /// refused row produces.
    average_width: u32,
    /// The cursor the completing `SnapshotEnd` carries: the first page's, never
    /// a later one's, because resuming from the earliest position can only
    /// re-deliver changes the client already has.
    cursor: Cursor,
    /// Bytes this delivery has carried so far.
    delivered: u64,
    /// Whether this delivery is itself the one restart a failed page gets.
    restarted: bool,
    /// The caller's tier, so a restart is judged by the same limits.
    tier: Tier,
    /// The reader-pool share held for the whole delivery (R39), released when
    /// the last page lands and carried across a restart.
    permit: Option<ReaderPermit>,
}

/// Byte budget for a grouped fold's one-page seed read. Generous next to what
/// a within-budget grouped seed can produce (the engine's group limit times a
/// few numeric cells), so hitting it means the fold would demote anyway.
const GROUPED_SEED_PAGE_BYTES: usize = 4 * 1024 * 1024;

/// Mutable per-session state carried through the run loop.
/// A snapshot whose first page's fence missed transactions, owed their rows from the log.
struct MissedReplay {
    label: String,
    consumer_id: u64,
    fence: ReadFence,
    /// The snapshot's own fenced cursor, which each replayed row carries, so resuming from it would replay them again.
    cursor: Cursor,
}

struct SessionState<Id, Key> {
    credits: u32,
    pending: VecDeque<Deliverable>,
    /// Row subscriptions by client label, each keeping the request that made it
    /// so the server can re-read the same set without asking the client again
    /// (R7).
    subs: HashMap<String, RowSub>,
    /// Reads still arriving in pages, oldest first, so several large
    /// subscriptions take turns rather than one finishing before the next
    /// starts.
    paging: VecDeque<PagedRead>,
    reader_reservation: ReaderReservation,
    /// Snapshots whose fence missed transactions the log may hold, replayed by the run loop before its next frame.
    missed: Vec<MissedReplay>,
    /// Computed subscriptions by client label, one engine id space for every
    /// tier.
    computed_subs: HashMap<String, ComputedSub>,
    outbound: mpsc::UnboundedSender<Outbound>,
    /// The caller, established at handshake and consulted per read and write.
    principal: Arc<Principal<Id, Key>>,
    /// The `MutationHeader` awaiting its paired `MutationPatch`.
    pending_header: Option<MutationHeader>,
    /// The writer this connection writes as (R75), resolved at the handshake
    /// for a number request and set by the `BindDevice` for a device one,
    /// absent before that bind. Its `frontier` is the per-connection cache of
    /// the writer's durable frontier.
    writer_row: Option<WriterRow<Id>>,
    /// The connetto-minted session id from the verified token.
    session_id: SessionId,
    /// The challenge nonce of the round the handshake settled, the message a
    /// device key signs to bind its writer (R75).
    bind_nonce: [u8; 32],
    /// The sequence this connection answered `Indeterminate` that stands
    /// unsettled, so the writes past it are answered the same way rather than
    /// closed, the client resends them while a new one is in flight.
    indeterminate: Option<u64>,
    /// The sequences this connection deferred, each holding the deadline its
    /// deferral named. A write past the frontier that stands behind one waits
    /// behind it rather than closing as a gap.
    deferred: BTreeMap<u64, u64>,
    /// Where the handshake cursor lets every re-declared subscription resume.
    resume: Resume,
    /// What is left of the connection's wait on reconnect-log reads, which every catchup draws from.
    resume_read_budget: Duration,
    /// Known completed subject coverage, absent while unknown or unfinished.
    cursor_subjects: Option<BTreeSet<String>>,
    /// When each held share key dies, in Unix seconds by the key's rendering,
    /// which the run loop sleeps until (R95).
    key_expiry: BTreeMap<String, u64>,
    /// Set when a per-connection abuse threshold crossed, so the run loop ends
    /// after the frame that crossed it. A caller with no identity has no name
    /// to ban, so closing the socket is the whole outcome.
    closing: bool,
    /// The enrolment nonce this session was last handed, spent by its next enrolment request.
    enrol_challenge: Option<crate::device_cert::PendingChallenge>,
}

/// One computed subscription, as a key change has to find it again.
struct ComputedSub {
    /// The engine subscription id.
    id: SubscriptionId,
    /// The request, so a key change can register the same query again.
    sub: Subscribe,
    /// Whether its answer depends on the caller's subject set.
    rebinds: bool,
}

/// Fronts a shared [`Materializer`], routes CDC output to sessions, and runs the
/// write path against a visibility policy, the Postgres write target, and a
/// re-execution connector for aggregate subscriptions.
pub struct SessionManager<
    Snap,
    Auth,
    D,
    C = NoConnector,
    O = InMemoryOplog,
    Id = <D as ConnettoSchema>::Id,
    Key = String,
    S = NoSigner,
> where
    Snap: SnapshotSource<Id, Key>,
    Auth: VisibilityPolicy<Watcher = Arc<Principal<Id, Key>>, Backend = Postgres>,
    C: ReadConnector,
    O: Oplog,
    D: ConnettoSchema<Id = Id>,
    S: ContentTicketSigner,
{
    materializer: Arc<Mutex<Materializer<ParserDB, RuntimeWritableCatalog, C>>>,
    /// The parsed catalog, cloned out of the materializer at construction.
    /// The visibility question holds a row view across an await, so it cannot
    /// borrow one through the materializer's mutex.
    catalog: Arc<ParserDB>,
    routes: Mutex<HashMap<u64, Route<Id, Key>>>,
    /// Held across one event's dispatch and fan-out, and by a session swapping
    /// its share keys, so no patch filtered under the old keys is queued behind
    /// the swap's resends (R95).
    dispatch_gate: Mutex<()>,
    /// Computed-subscription routes keyed by the engine subscription id, one
    /// id space for every tier since the subql bump to `4a500ee`.
    computed_routes: Mutex<HashMap<SubscriptionId, AggRoute>>,
    /// Live connections keyed by the durable session handle, for revocation
    /// and supersession. The per-subscription route map cannot serve either,
    /// because a session with no subscriptions has no route.
    sessions: Mutex<HashMap<SessionId, LiveSession>>,
    snapshot_source: Snap,
    auth: Auth,
    /// Checks the grants a handshake presents and signs the resume credential
    /// it hands back. A runtime trait object so a deployment configures
    /// identity without changing the manager's type. Required at construction
    /// with no default, because the deleted trusting default was itself the
    /// spoofing hole (R2).
    authority: Arc<dyn HandshakeAuthority<Id, Key>>,
    connector: C,
    oplog: O,
    target: PgWriteTarget<D>,
    next_session: AtomicU64,
    next_consumer: AtomicU64,
    config: SessionConfig,
    /// Every counter connetto keeps about a caller, shared with the auth
    /// service so the four abuse signals are defined once each.
    guard: Arc<RequestGuard<Id>>,
    /// Backoff for the authorization-service unreachable path on the change
    /// pipeline. When `may_see` or `may_write` returns an error, the ingest
    /// loop retries the same event using this schedule before moving on.
    auth_retry: RetryPolicy,
    /// Backoff for the re-execution read paths: the one retry of the
    /// unknown class and the in-place retry of the transient class.
    read_retry: RetryPolicy,
    /// Brings the authorization store level with each changed row before that
    /// row reaches anybody.
    ///
    /// Optional because most policies keep no store: row-level security reads
    /// the live table and has nothing to maintain. A manager that holds one
    /// waits for it, because a patch delivered before the store catches up is
    /// answered from facts the change already invalidated, and in the allow
    /// direction no later correction takes the row back.
    upkeep: Option<Arc<dyn crate::openfga::StoreUpkeep>>,
    /// A second executor asked about the row as it is now, alongside the one
    /// that delivers, so a divergence between them fails a run.
    ///
    /// Optional and off by default: it costs one Postgres round trip per watcher
    /// per changed row, which is the whole cost R5b removed.
    second_opinion: OnceLock<Arc<dyn crate::parity::SecondOpinion<Id, Key>>>,
    /// Reads the rows a membership move-out withdraws, on the privileged pool
    /// (R27 decision 6): when a membership ends, the policy that made those
    /// rows visible is exactly what ended, so a read as the caller comes back
    /// empty precisely when there is something to withdraw.
    ///
    /// Optional like the upkeep. Without one, a move-out escalates to the R7
    /// replace instead of withdrawing incrementally.
    withdrawal_source: OnceLock<Snap>,
    /// Issues device certificates (R74). Without one, every enrolment is
    /// refused as [`EnrolRefusal::IssuerUnavailable`].
    device_enrolment: OnceLock<Arc<crate::device_cert::DeviceEnrolment<Id>>>,
    /// The deployment's content ticket signer, called after a successful
    /// visibility check to mint a signed URL the caller may use at the file
    /// server. Generic rather than boxed so a deployment wires it at compile
    /// time without a vtable allocation on the hot ticket path.
    signer: S,
    /// The timeline history last read, `None` before the first read and treated as never promoted.
    history: parking_lot::RwLock<Option<TimelineHistory>>,
    /// Where a reconnect of the change feed resumes, the last row or commit the ingest finished handling.
    resume: ResumePoint,
    /// Run loops that have started and not yet ended, which the shutdown
    /// grace counts because the registry drains at the moment of the close.
    open_sessions: Arc<AtomicUsize>,
    /// Set once the manager has been told to go away, so a handshake that
    /// completes during the shutdown is told the shutdown rather than
    /// registering into the drained registry.
    shutting_down: AtomicBool,
    /// The bot registry that settles a `RegisterBot` on the owner pool (R91),
    /// or `None` when the deployment wired no registry, in which case every
    /// registration fails closed and is refused without saying why.
    bot_registry: Option<PgBotRegistry<D::Bots>>,
    /// The sessions bound to each device writer (R75), so a retirement can
    /// close every connection that writes as the retired writer.
    writer_sessions: Mutex<HashMap<i64, HashSet<SessionId>>>,
}

/// Keeps the open-run-loop count right while one `serve` is in flight.
///
/// The increment happens before the handshake, so a handshake that is still
/// in flight counts, and the drop decrements on every exit of the `serve` it
/// guards, panic included.
struct OpenSessionTally {
    open: Arc<AtomicUsize>,
}

impl OpenSessionTally {
    /// Count one more open run loop.
    fn start(open: Arc<AtomicUsize>) -> Self {
        open.fetch_add(1, Ordering::Relaxed);
        Self { open }
    }
}

impl Drop for OpenSessionTally {
    fn drop(&mut self) {
        self.open.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The manager over the `String` ids and keys every construction shares.
pub(crate) type ConnettoManager<Snap, Auth, D, C, O, S> =
    SessionManager<Snap, Auth, D, C, O, <D as ConnettoSchema>::Id, String, S>;

/// The single assembly every manager construction goes through, which
/// `ManagerBuilder` owns.
#[expect(
    clippy::too_many_arguments,
    reason = "every collaborator the manager owns is named here and a config struct would move the same arity behind another type"
)]
pub(crate) fn assemble_manager<Snap, Auth, C, O, D, S>(
    materializer: Materializer<ParserDB, RuntimeWritableCatalog, C>,
    snapshot_source: Snap,
    auth: Auth,
    authority: Arc<dyn HandshakeAuthority<D::Id>>,
    connector: C,
    oplog: O,
    target: PgWriteTarget<D>,
    guard: Arc<RequestGuard<D::Id>>,
    config: SessionConfig,
    upkeep: Option<Arc<dyn crate::openfga::StoreUpkeep>>,
    signer: S,
    withdrawal_source: Option<Snap>,
    second_opinion: Option<Arc<dyn crate::parity::SecondOpinion<D::Id, String>>>,
    bot_registry: Option<PgBotRegistry<D::Bots>>,
) -> Arc<ConnettoManager<Snap, Auth, D, C, O, S>>
where
    Snap: SnapshotSource<D::Id>,
    Auth: VisibilityPolicy<Watcher = Arc<Principal<D::Id>>, Backend = Postgres>,
    C: ReadConnector,
    C::Error: FailedRead,
    O: Oplog,
    D: ConnettoSchema,
    S: ContentTicketSigner,
{
    Arc::new(SessionManager {
        catalog: Arc::new(materializer.catalog().clone()),
        materializer: Arc::new(Mutex::new(materializer)),
        routes: Mutex::new(HashMap::new()),
        dispatch_gate: Mutex::new(()),
        computed_routes: Mutex::new(HashMap::new()),
        sessions: Mutex::new(HashMap::new()),
        snapshot_source,
        auth,
        authority,
        connector,
        oplog,
        target,
        next_session: AtomicU64::new(1),
        next_consumer: AtomicU64::new(1),
        config,
        guard,
        auth_retry: RetryPolicy::new(),
        read_retry: RetryPolicy::new(),
        upkeep,
        second_opinion: second_opinion.map(OnceLock::from).unwrap_or_default(),
        withdrawal_source: withdrawal_source.map(OnceLock::from).unwrap_or_default(),
        device_enrolment: OnceLock::new(),
        signer,
        history: parking_lot::RwLock::new(None),
        resume: ResumePoint::default(),
        open_sessions: Arc::new(AtomicUsize::new(0)),
        shutting_down: AtomicBool::new(false),
        bot_registry,
        writer_sessions: Mutex::new(HashMap::new()),
    })
}

/// The verdict a device bind settles. `Writer` answers the connection,
/// `Revoked` closes it with `DeviceRevoked`, the way a connected device
/// learns of its revocation.
#[derive(Debug)]
enum BindVerdict {
    Writer(WriterOutcome),
    Revoked,
}

impl<Snap, Auth, C, O, Id, Key, D, S> SessionManager<Snap, Auth, D, C, O, Id, Key, S>
where
    Snap: SnapshotSource<Id, Key>,
    Auth: VisibilityPolicy<Watcher = Arc<Principal<Id, Key>>, Backend = Postgres>,
    Auth::Error: core::fmt::Display + FailedAuthorization,
    C: ReadConnector,
    C::Error: FailedRead,
    O: Oplog,
    Id: core::fmt::Display + Clone + Send + Sync + 'static,
    Key: CapabilityKey,
    D: ConnettoSchema<Id = Id>,
    S: ContentTicketSigner,
{
    /// Ask a second executor about every current row alongside the one that
    /// delivers, so a divergence between them is counted and named.
    ///
    /// Set once, for the same reason the upkeep is: replacing a live one would
    /// compare events either side of the swap against two different executors.
    /// Off by default, because it costs one Postgres round trip per watcher per
    /// changed row.
    ///
    /// # Errors
    ///
    /// The executor handed over, when one is already installed.
    pub fn install_second_opinion(
        &self,
        second: Arc<dyn crate::parity::SecondOpinion<Id, Key>>,
    ) -> Result<(), Arc<dyn crate::parity::SecondOpinion<Id, Key>>> {
        self.second_opinion.set(second)
    }

    /// Read move-out withdrawals on the privileged pool (R27 decision 6).
    ///
    /// Set once, after construction, like the store upkeep. The source's pool
    /// is what makes it privileged: the caller binding is inert where
    /// row-level security does not apply, and nothing read through it is sent
    /// as data, only denied keys as indirect deletes.
    ///
    /// # Errors
    ///
    /// The source handed over, when one is already installed.
    pub fn install_withdrawal_source(&self, source: Snap) -> Result<(), Snap> {
        self.withdrawal_source.set(source)
    }

    /// Enrol devices through `enrolment` (R74), set once after construction.
    ///
    /// # Errors
    ///
    /// The enrolment handed over, when one is already installed.
    pub fn install_device_enrolment(
        &self,
        enrolment: Arc<crate::device_cert::DeviceEnrolment<Id>>,
    ) -> Result<(), Arc<crate::device_cert::DeviceEnrolment<Id>>> {
        self.device_enrolment.set(enrolment)
    }

    /// Which refusal a transition failure is, holding the event only for a failure that can clear (R6 decision 4).
    fn transition_refusal(
        &self,
        event: &PgChangeEvent,
        err: TransitionError<Auth::Error>,
    ) -> SessionError {
        match err {
            TransitionError::Policy(err) if err.clears_by_itself() => {
                SessionError::AuthUnavailable(err.to_string())
            }
            TransitionError::Policy(err) => SessionError::AuthorizationUnanswerable {
                table: self.event_table(event),
                reason: err.to_string(),
            },
            // `NotARowEvent` is unreachable, because a truncate is answered
            // before the question is put. Refusing is the direction to fail in
            // if that ever stops being true.
            TransitionError::IncompletePreviousImage
            | TransitionError::UnknownTable
            | TransitionError::NotARowEvent => {
                SessionError::ChangeStreamUnusable(self.event_table(event))
            }
        }
    }

    /// The event's table, for a message a person has to act on.
    fn event_table(&self, event: &PgChangeEvent) -> String {
        let catalog = self.catalog.as_ref();
        let id = event.table_id(catalog);
        usize::try_from(id)
            .ok()
            .and_then(|index| catalog.table_by_id(index))
            .map_or_else(
                || format!("table {id}"),
                |table| table.table_name().to_owned(),
            )
    }

    /// The changed row's primary key, as connetto observed it on the event.
    ///
    /// Empty when the event carries no readable image, which an audit row
    /// records as a change naming no row rather than as a wrong one.
    fn event_key(&self, event: &PgChangeEvent) -> Vec<subql::backend::Value<Postgres>> {
        let catalog = self.catalog.as_ref();
        let Some(row) =
            EventRow::current(event, catalog).or_else(|| EventRow::previous(event, catalog))
        else {
            return Vec::new();
        };
        event
            .pk_columns(catalog)
            .into_iter()
            .map_while(|column| subql::visibility::RowView::value_at(&row, column).ok())
            .collect()
    }

    /// Ask the second opinion about the row as it is now, when one is installed.
    ///
    /// Only the current row, and only when the event has one: row-level security
    /// reads the live table, so it cannot answer about a previous version and
    /// answers no for everyone about a deleted row. A watcher was told to deliver
    /// exactly when the shipped executor allowed the current row, which is what
    /// makes the comparison recoverable here without asking twice.
    async fn ask_second_opinion(
        &self,
        event: &PgChangeEvent,
        watchers: &[Arc<Principal<Id, Key>>],
        verdicts: &[Transition],
    ) {
        let Some(second) = self.second_opinion.get() else {
            return;
        };
        let Some(row) = EventRow::current(event, self.catalog.as_ref()) else {
            return;
        };
        let shipped: Vec<Verdict> = verdicts
            .iter()
            .map(|verdict| {
                if *verdict == Transition::Deliver {
                    Verdict::Allow
                } else {
                    Verdict::Deny
                }
            })
            .collect();
        second.compare(&row, watchers, &shipped).await;
    }

    fn next_connection_num(&self) -> u64 {
        self.next_session.fetch_add(1, Ordering::Relaxed)
    }

    fn next_consumer_id(&self) -> u64 {
        self.next_consumer.fetch_add(1, Ordering::Relaxed)
    }

    /// Who a signal is attributed to: the handle for the rate limit, the person
    /// for the abuse tally.
    pub(crate) fn caller(principal: &Principal<Id, Key>) -> Caller<'_, Id> {
        Caller {
            session: principal.session_id(),
            user: principal.identity().map(|identity| &identity.user_id),
        }
    }

    /// Close `session_id`'s live connection, if one exists, sending `reason`
    /// as a fatal frame first. Returns whether a live connection was found.
    ///
    /// The revocation path (`FatalErrorReason::SessionRevoked`): revoking a
    /// session closes its live connection rather than only refusing its next
    /// handshake.
    pub async fn close_session(&self, session_id: SessionId, reason: FatalErrorReason) -> bool {
        let live = { self.sessions.lock().await.remove(&session_id) };
        match live {
            Some(live) => {
                tracing::info!(session = %session_id, reason = ?reason, "closing a live connection");
                let _ = live.tx.send(Outbound::Fatal(FatalError::new(reason)));
                true
            }
            None => false,
        }
    }

    /// Close every live connection the identity rendering as `user` holds,
    /// telling them nothing, and report how many. A person may hold one per
    /// device, so a ban that closed only the connection it was detected on
    /// would leave the others streaming.
    ///
    /// The registry is small and a ban is rare, so this scans rather than
    /// keeping a second index to fall out of step.
    pub async fn close_person(&self, user: &str) -> usize {
        let closing: Vec<_> = {
            let mut sessions = self.sessions.lock().await;
            let handles: Vec<SessionId> = sessions
                .iter()
                .filter(|(_, live)| live.user.as_deref() == Some(user))
                .map(|(handle, _)| *handle)
                .collect();
            handles
                .into_iter()
                .filter_map(|handle| sessions.remove(&handle))
                .collect()
        };
        for live in &closing {
            let _ = live.tx.send(Outbound::Drop);
        }
        if !closing.is_empty() {
            tracing::info!(
                closed = closing.len(),
                "closing a banned identity's connections"
            );
        }
        closing.len()
    }

    /// Close every live connection with
    /// [`FatalErrorReason::ServerShuttingDown`], returning how many were told.
    ///
    /// A client that learns the server is going away backs off instead of
    /// reconnecting immediately into a dying process. The flag is set before
    /// the drain, so a handshake racing the shutdown is told the shutdown at
    /// its registration instead of registering into the drained registry.
    pub async fn shutdown(&self) -> usize {
        self.shutting_down.store(true, Ordering::Release);
        self.close_all(FatalErrorReason::ServerShuttingDown).await
    }

    /// How many connections the registry holds right now.
    ///
    /// The handshake ack is written by `run_handshake` and the connection is
    /// registered afterwards by `run_session`, so a client holding its ack is
    /// not necessarily counted here yet. A caller that needs both to be true
    /// waits for this to reach the number it expects.
    pub async fn live_connections(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// How many run loops have started and not yet ended.
    ///
    /// The registry drains at the moment a close is issued, so the shutdown
    /// grace counts these instead, and a handshake still in flight counts
    /// before it registers.
    pub fn open_sessions(&self) -> usize {
        self.open_sessions.load(Ordering::Relaxed)
    }

    /// Store the timeline history read before the feed opens, closing every live connection when it changed.
    ///
    /// A live connection never presents its cursor again, so closing it is what gets that cursor judged (R73).
    pub async fn reconcile_history(&self, history: TimelineHistory) {
        let to = history.current();
        let from = {
            let mut stored = self.history.write();
            if stored.as_ref() == Some(&history) {
                return;
            }
            match stored.replace(history) {
                None => return,
                Some(held) => held.current(),
            }
        };
        // A position past the switch names changes the new primary never had, and resuming after it would skip newer ones.
        self.resume.set(None);
        let closed = self
            .close_all(FatalErrorReason::DatabaseTimelineChanged)
            .await;
        tracing::warn!(
            from,
            to,
            closed,
            "the database moved to another timeline, so every live connection \
             was closed and each cursor past where its timeline ended resyncs"
        );
    }

    /// `at` as a cursor stamped with the timeline last read.
    fn stamp(&self, at: PgCommitPosition) -> Vec<u8> {
        match self.history.read().as_ref() {
            Some(history) => history.stamp(at),
            None => TimelineHistory::default().stamp(at),
        }
    }

    /// A position in `Checkpoint::to_opaque` form stamped with the timeline last read, empty staying empty.
    fn stamp_opaque(&self, opaque: &[u8]) -> Vec<u8> {
        PgCommitPosition::from_opaque(&OpaqueCheckpoint(opaque.to_vec()))
            .map_or_else(Vec::new, |at| self.stamp(at))
    }

    /// Where `cursor` lets a connection resume, against the history last read.
    fn resume_from(&self, cursor: Option<&Cursor>) -> Resume {
        match self.history.read().as_ref() {
            Some(history) => Resume::of(cursor, history),
            None => Resume::of(cursor, &TimelineHistory::default()),
        }
    }

    /// Reconcile the change feed's resume position against what the log holds,
    /// declaring a resync epoch when the feed skipped a stretch.
    ///
    /// Called before each connect with the position the stream is about to
    /// resume from, the slot's confirmed position. The slot is only ever
    /// released to the end of a commit the log recorded first
    /// ([`Oplog::record_commit`]), so in ordinary operation the resume position
    /// equals that end or trails it, and this does nothing. A resume position
    /// **past** the recorded end means changes happened that the feed
    /// never delivered: an invalidated slot the deployment recreated, a
    /// database restored from a backup, or a slot dropped under a running
    /// server. Detecting the hole rather than the cause is deliberate, since
    /// no layer here distinguishes an invalidation from an ordinary
    /// disconnection and matching on an error string would pin this to one
    /// Postgres version and to the causes somebody enumerated (R32).
    ///
    /// **The boundary reported is the resume position, not the last record
    /// ingested.** It is where the epoch starts, and it is recorded as the last
    /// commit, so the next check before any new traffic is not another gap.
    ///
    /// Three things follow, and all are needed. The log forgets everything
    /// through the boundary, so every later handshake is judged against what
    /// can still be proven. The feed's [`ResumePoint`] is cleared, so the next
    /// stream starts where the slot is rather than after a position this
    /// database may never have had. And every live connection is closed, because a
    /// connection never asks that question again: reconnecting re-declares its
    /// subscriptions through the ordinary path, which rebuilds a running total
    /// from its source rather than repairing one that accumulated across the
    /// hole.
    ///
    /// Returns the boundary when an epoch was declared.
    ///
    /// # Errors
    ///
    /// [`SessionError`] when the log could not be read or trimmed. The caller
    /// must not begin streaming on an error: an undeclared gap is the silence
    /// this exists to remove.
    pub async fn reconcile_stream(&self, resume_lsn: u64) -> Result<Option<u64>, SessionError> {
        let Some(ingested) = self.oplog.last_commit().await.map_err(oplog_err)? else {
            // Nothing recorded, so there is nothing to be past. A log in that
            // state already resyncs every client that presents a cursor.
            return Ok(None);
        };
        let ingested = ingested.end_lsn().0;
        if resume_lsn <= ingested {
            return Ok(None);
        }
        let boundary = PgCommitPosition::before_commit(PgLsn(resume_lsn));
        self.oplog
            .forget_through(boundary)
            .await
            .map_err(oplog_err)?;
        // The feed resumes at the boundary now, so the next check without new traffic is not another gap.
        self.oplog
            .record_commit(PgCommit::new(boundary, PgLsn(resume_lsn)))
            .await
            .map_err(oplog_err)?;
        self.resume.set(None);
        let closed = self.close_all(FatalErrorReason::ChangeStreamGap).await;
        tracing::error!(
            ingested,
            resume_lsn,
            missing_bytes = resume_lsn.saturating_sub(ingested),
            closed,
            "change feed resumed past what it delivered, so a stretch of changes \
             was never seen: the reconnect log is trimmed to the resume point and \
             every client will resynchronise"
        );
        Ok(Some(resume_lsn))
    }

    /// Settle the cluster and timeline, then read whether the slot resumes past the reconnect log, leaving the log untouched (R73, R32, R70).
    ///
    /// A caller that revokes sessions on a gap trims the log with [`reconcile_stream`](Self::reconcile_stream) only once the revocation held, so a failed revocation meets the same gap again on the next try.
    ///
    /// # Errors
    ///
    /// [`StreamCheckError`] when a read fails, and the feed must then stay closed.
    pub async fn check_before_stream(
        &self,
        database_url: &str,
        pool: &Pool<AsyncPgConnection>,
        slot: &str,
    ) -> Result<StreamCheck, StreamCheckError> {
        let history = crate::timeline::read_history(database_url).await?;
        let system = history.system();
        self.reconcile_history(history).await;
        let gap = match crate::slot::resume_position(pool, slot).await? {
            Some(resume) => {
                // The slot resumes exactly at the end of the last commit acknowledged, and that commit was recorded first.
                let ingested = self.oplog.last_commit().await.map_err(oplog_err)?;
                ingested
                    .is_some_and(|ingested| resume > ingested.end_lsn().0)
                    .then_some(resume)
            }
            None => None,
        };
        Ok(StreamCheck { system, gap })
    }

    /// Settle the cluster and timeline, then the slot's resume position, before each connect of the change feed (R73, R32).
    ///
    /// # Errors
    ///
    /// [`StreamCheckError`] when a read or the trim fails, and the feed must then stay closed.
    pub async fn reconcile_before_stream(
        &self,
        database_url: &str,
        pool: &Pool<AsyncPgConnection>,
        slot: &str,
    ) -> Result<StreamCheck, StreamCheckError> {
        let check = self.check_before_stream(database_url, pool, slot).await?;
        if let Some(resume) = check.gap {
            self.reconcile_stream(resume).await?;
        }
        Ok(check)
    }

    /// Close every live connection with `reason`, returning how many were told.
    async fn close_all(&self, reason: FatalErrorReason) -> usize {
        let live: Vec<_> = {
            let mut sessions = self.sessions.lock().await;
            sessions.drain().map(|(_, live)| live.tx).collect()
        };
        for tx in &live {
            let _ = tx.send(Outbound::Fatal(FatalError::new(reason.clone())));
        }
        live.len()
    }

    /// Send a control frame to every currently live session without removing
    /// any entry from the session registry.
    async fn broadcast_control(&self, msg: ControlMessage) {
        let txs: Vec<_> = {
            self.sessions
                .lock()
                .await
                .values()
                .map(|live| live.tx.clone())
                .collect()
        };
        for tx in txs {
            let _ = tx.send(Outbound::Control(msg.clone()));
        }
    }

    /// Claim `session_id` for this connection, superseding whatever held it.
    ///
    /// One live connection per durable handle, newer wins. Two connections
    /// must not share a handle, because the handle keys the per-subscription
    /// cursors and the pending buffer, and two readers would each consume the
    /// other's changes. Last-wins also makes a reconnect racing its own
    /// half-dead socket self-heal.
    ///
    /// Refused while the manager is shutting down, reporting whether the
    /// claim registered, so a handshake completing over the drain is told the
    /// shutdown instead of stranding an entry the drain already emptied.
    async fn register_connection(
        &self,
        session_id: SessionId,
        connection_num: u64,
        user: Option<String>,
        tx: &mpsc::UnboundedSender<Outbound>,
    ) -> bool {
        let superseded = {
            let mut sessions = self.sessions.lock().await;
            if self.shutting_down.load(Ordering::Acquire) {
                return false;
            }
            sessions.insert(
                session_id,
                LiveSession {
                    connection_num,
                    tx: tx.clone(),
                    user,
                },
            )
        };
        if let Some(old) = superseded {
            tracing::warn!(
                session = %session_id,
                superseded = old.connection_num,
                "a newer connection claimed this session handle"
            );
            let _ = old.tx.send(Outbound::Fatal(FatalError::new(
                FatalErrorReason::ConnectionSuperseded,
            )));
        }
        true
    }

    /// Drop the registry entry only if this connection still owns it: a
    /// superseded connection's cleanup must not evict its successor.
    async fn unregister_connection(&self, session_id: SessionId, connection_num: u64) {
        let mut sessions = self.sessions.lock().await;
        if sessions
            .get(&session_id)
            .is_some_and(|live| live.connection_num == connection_num)
        {
            sessions.remove(&session_id);
        }
    }

    async fn add_route(&self, consumer_id: u64, route: Route<Id, Key>) {
        self.routes.lock().await.insert(consumer_id, route);
    }

    async fn remove_route(&self, consumer_id: u64) {
        self.routes.lock().await.remove(&consumer_id);
    }

    async fn add_computed_route(&self, subscription_id: SubscriptionId, route: AggRoute) {
        self.computed_routes
            .lock()
            .await
            .insert(subscription_id, route);
    }

    async fn remove_computed_route(&self, subscription_id: SubscriptionId) {
        self.computed_routes.lock().await.remove(&subscription_id);
    }

    /// Dispatch one CDC event: fan row patches to sessions and deliver every
    /// computed-result change the engine produced. Since the subql `4a500ee`
    /// bump the engine services its own re-execution reads inline through the
    /// materializer's connector, so this holds the materializer lock across
    /// those reads, each bounded by its registration's budget
    /// (`docs/upstream-subql-nonblocking-read-tier-drive.md` is the recorded
    /// exit from that).
    ///
    /// # Errors
    ///
    /// [`SessionError`] when dispatch, a triggered read, a cursor advance, or
    /// the oplog append fails.
    pub async fn dispatch_event(&self, event: &PgChangeEvent) -> Result<(), SessionError> {
        self.dispatch_with_grants(event, &[]).await
    }

    /// [`dispatch_event`](Self::dispatch_event) with this event's grant moves,
    /// as the ingest loop computed them before dispatching: a membership
    /// move-out may withdraw rows only when the same event moved a grant
    /// reaching the subscribed table for that watcher, because only then did
    /// policy visibility of held rows flip (see `move_out`).
    async fn dispatch_with_grants(
        &self,
        event: &PgChangeEvent,
        grant_moves: &[GrantMove],
    ) -> Result<(), SessionError> {
        let _gate = self.dispatch_gate.lock().await;
        // Three classes, three dispositions (R89 decision 1). A timeout is
        // policy and ends its subscription, retrying it replaces nothing. The
        // unknown class gets one retry per subscription and a second failure
        // ends it, so a poisoned query costs one extra read and a blip costs
        // one read and survives. Each retry draws the policy's
        // first-attempt wait from a fresh episode rather than one shared
        // escalating schedule, so one poisoned migration ending many
        // subscriptions costs one short wait each. A transient failure
        // returns to the ingest loop, which pauses delivery in place (R89
        // decision 2), never a change-stream teardown. Each pass ends at most
        // one subscription, so the loop terminates.
        let mut unknown_attempts: HashMap<SubscriptionId, u32> = HashMap::new();
        let mut dispatched = loop {
            let outcome = {
                counters::timed_lock(&self.materializer)
                    .await
                    .dispatch(event)
                    .await
            };
            match outcome {
                Ok(dispatched) => break dispatched,
                Err(MaterializerError::Read {
                    subscription,
                    class: ReadFailure::Timeout,
                    detail,
                }) => {
                    self.refuse_computed(subscription, ReadFailure::Timeout, 1, &detail)
                        .await;
                }
                Err(MaterializerError::Read {
                    subscription,
                    class: ReadFailure::Other,
                    detail,
                }) => {
                    let seen = unknown_attempts.entry(subscription).or_insert(0);
                    *seen = seen.saturating_add(1);
                    if *seen > Self::UNKNOWN_READ_RETRIES {
                        self.refuse_computed(subscription, ReadFailure::Other, *seen, &detail)
                            .await;
                    } else if let Some(wait) = self.read_retry.start().next_wait() {
                        tokio::time::sleep(wait).await;
                    }
                }
                Err(MaterializerError::Read {
                    class: ReadFailure::Transient,
                    detail,
                    ..
                }) => return Err(SessionError::ReadUnavailable(detail)),
                Err(err) => return Err(err.into()),
            }
        };

        // Record the event in the oplog before fan-out. The append is per event,
        // not per consumer, since reconnect catchup re-filters per client, and
        // the record carries the patch dispatch built so catchup never folds
        // the event again.
        if let Some(record) = dispatched.record.take() {
            self.oplog.append(record).await.map_err(oplog_err)?;
        }

        // Every patch this event produced, paired with the route it goes to.
        // Collected before the visibility question because that question names
        // every watcher at once.
        let mut deliveries = Vec::with_capacity(dispatched.patches.len());
        for patch in dispatched.patches {
            let route = { self.routes.lock().await.get(&patch.consumer_id).cloned() };
            let Some(route) = route else { continue };
            counters::add(&counters::FANOUT_ROUTE_CLONES, 1);
            deliveries.push((patch, route));
        }
        self.fan_out_rows(event, deliveries).await?;
        self.fan_out_moves(event, dispatched.narrowings, grant_moves)
            .await;

        // Computed results are global by construction (subql refuses shared
        // state on RLS tables), so no per-row read filter applies: deliver
        // each change unconditionally to its owning session.
        for change in dispatched.computed {
            self.deliver_computed(change).await;
        }
        Ok(())
    }

    /// Decide what one event does to every matched caller's copy of the row, and
    /// send it (R6, the two-check form).
    ///
    /// `Deliver` sends the patch this event produced, `Withdraw` sends a plain
    /// delete that takes the row back, and `Nothing` sends nothing at all, which
    /// is what stops a deleted row's key reaching a caller who could never see
    /// it.
    ///
    /// # Errors
    ///
    /// [`SessionError::AuthUnavailable`] when the policy could not answer, so the
    /// ingest loop holds the event, [`SessionError::ChangeStreamUnusable`] when
    /// the stream cannot report the previous version at all, and
    /// [`SessionError::Materializer`] when a cursor advance fails.
    async fn fan_out_rows(
        &self,
        event: &PgChangeEvent,
        deliveries: Vec<(MatchedPatch, Route<Id, Key>)>,
    ) -> Result<(), SessionError> {
        let watchers: Vec<_> = deliveries
            .iter()
            .map(|(_, route)| Arc::clone(&route.principal))
            .collect();
        // A truncate names no row, so neither version exists and no question can
        // be put, and it folds to a patchset with no operations, so delivering it
        // applies nothing and leaves the emptied table populated for ever. The
        // subscription is replaced instead (R48): the client deletes the table
        // and takes a fresh snapshot, which is the cheapest replacement there is
        // because the table is now empty and the snapshot returns no rows.
        //
        // The cursor is deliberately not advanced here. The replacement carries
        // its own, and a client that reconnects before the replacement lands
        // meets the same truncate again in catchup and resyncs there, which is
        // idempotent. Advancing first would lose the event with nothing having
        // acted on it.
        if event.kind() == EventKind::Truncate {
            let table = self.event_table(event);
            for (_, route) in deliveries {
                let _ = route.tx.send(Outbound::Resnapshot {
                    sub_id: route.label,
                    reason: FullResyncReason::TableTruncated {
                        table: table.clone(),
                    },
                });
            }
            return Ok(());
        }
        let mut verdicts = Transitions::new();
        if !watchers.is_empty() {
            transitions(
                &self.auth,
                event,
                self.catalog.as_ref(),
                &watchers,
                &mut verdicts,
            )
            .await
            .map_err(|err| self.transition_refusal(event, err))?;
            self.ask_second_opinion(event, &watchers, verdicts.get())
                .await;
        }

        // What a caller who may no longer see the row receives. **A delete's own
        // patch already is exactly that**, one unmarked delete keyed by the image
        // the caller holds, so only an update needs a second fold: its own patch
        // carries the new row values the caller has just lost the right to read.
        // Built once per event when it is needed at all, exactly as the departure
        // notice is, because the bytes carry a table and a key and nothing
        // caller-specific.
        let withdrawal = if event.kind() == EventKind::Delete
            || !verdicts.get().contains(&Transition::Withdraw)
        {
            None
        } else {
            let built = counters::timed_lock(&self.materializer)
                .await
                .withdrawal_patch(event)?;
            Some(built.ok_or_else(|| {
                MaterializerError::Emit(
                    "a row has to be taken back from a caller and the event folded to no \
                     operation to take it back with"
                        .to_owned(),
                )
            })?)
        };

        for ((patch, route), verdict) in deliveries.into_iter().zip(verdicts.get().iter().copied())
        {
            // R44's departure notice is no longer exempt from the visibility
            // question, and retiring that exemption is R6's decision 6. The
            // exemption existed because a denied subscriber would otherwise be
            // told nothing and keep the row for ever, which the withdrawal above
            // now answers properly. What it cost was the notice carrying a key to
            // a caller who could never see the row.
            let payload = match verdict {
                Transition::Nothing => continue,
                Transition::Deliver => patch.payload_zstd,
                Transition::Withdraw => withdrawal.clone().unwrap_or(patch.payload_zstd),
            };
            let cursor = self.stamp_opaque(&patch.cursor);
            let advanced = {
                counters::timed_lock(&self.materializer)
                    .await
                    .advance_cursor(route.session_key, route.sub_id, &cursor)
            };
            match advanced {
                Ok(()) => {}
                Err(MaterializerError::Cursor(AdvanceCursorError::NonMonotonic { .. })) => {
                    counters::add(&counters::CURSOR_REWINDS, 1);
                    let missed = route
                        .fence
                        .as_ref()
                        .is_some_and(|fence| fence.seen(event.position()) == Seen::Missed);
                    // After a restart the slot re-delivers rows the durable log already served this route through catchup.
                    if !missed {
                        tracing::debug!(sub_id = %route.label, position = ?event.position(), "the route is already past this re-delivered row");
                        continue;
                    }
                    tracing::debug!(sub_id = %route.label, position = ?event.position(), "delivering a transaction the route's snapshot missed below its cursor");
                }
                Err(err) => return Err(err.into()),
            }
            let live = LivePatch::new(route.label, Cursor::new(cursor), payload);
            // A dropped session receiver just means the client is gone.
            let _ = route.tx.send(Outbound::Live(live));
        }
        Ok(())
    }

    /// How many times a membership move read retries in place before the
    /// subscription is replaced through the R7 machinery instead.
    const MOVE_ATTEMPTS: u32 = 3;

    /// How many scalar reads a first answer takes before refusing the
    /// subscription, each read again because a change it missed removed its answer.
    const SCALAR_READ_ATTEMPTS: u32 = 3;

    /// How many short-backoff retries the unknown read class gets before its
    /// subscription ends (R89 decision 1).
    const UNKNOWN_READ_RETRIES: u32 = 1;

    /// Serve the rows one membership move affects (R27 step 4): a value that
    /// entered a subscription's set is answered with the subscription's own
    /// SELECT narrowed to that value, and a value that left with an indirect
    /// delete per key the policy no longer grants.
    ///
    /// A failure never fails the event and never skips silently: the engine's
    /// membership set has already moved, so a redispatched event would re-fire
    /// no narrowing, and instead the subscription is replaced whole through
    /// the same ordered notice-and-replacement instruction a moved grant uses
    /// (R7). The healthy path stays incremental, which is what the phase's
    /// proof asserts.
    async fn fan_out_moves(
        &self,
        event: &PgChangeEvent,
        moves: Vec<TermMove>,
        grant_moves: &[GrantMove],
    ) {
        if moves.is_empty() {
            return;
        }
        let cursor = self.stamp(event.position());
        for term_move in moves {
            let route = {
                self.routes
                    .lock()
                    .await
                    .values()
                    .find(|route| route.sub_id == term_move.sub_id)
                    .cloned()
            };
            let Some(route) = route else { continue };
            let served = if term_move.entered {
                self.move_in(&route, &term_move, &cursor).await
            } else {
                self.move_out(&route, &term_move, &cursor, grant_moves)
                    .await
            };
            if !served {
                let _ = route.tx.send(Outbound::Resnapshot {
                    sub_id: route.label.clone(),
                    reason: FullResyncReason::AuthorizationChange,
                });
            }
        }
    }

    /// Deliver the rows a value entering the set admits: the subscription's
    /// own SELECT narrowed to the value, read as the caller under row-level
    /// security, which is the snapshot-time visibility question, so a row the
    /// policy forbids never arrives however much the term admits it. Returns
    /// whether the move was served.
    async fn move_in(&self, route: &Route<Id, Key>, term_move: &TermMove, cursor: &[u8]) -> bool {
        let Some(sql) = narrowed_sql(&route.pg_sql, &term_move.pairs) else {
            return false;
        };
        let Some(snapshot) = self
            .move_page(&self.snapshot_source, &sql, &route.binds, route)
            .await
        else {
            return false;
        };
        let has_rows = matches!(
            ParsedDiffSet::parse(&snapshot.patchset),
            Ok(ParsedDiffSet::Patchset(set)) if set.iter().next().is_some()
        );
        if !has_rows {
            // The policy admitted nothing under this value. Delivering an
            // empty patch would say something moved when nothing did.
            return true;
        }
        let Ok(payload) = compress(&snapshot.patchset) else {
            return false;
        };
        self.send_move(route, cursor, payload).await
    }

    /// Read one page of a move's narrowed query as `route`'s caller, retrying a
    /// failing read the way the ingest loop retries an unreachable
    /// authorization service.
    ///
    /// [`None`] when the move cannot be served this way, which the callers turn
    /// into a replacement of the whole subscription. A move wider than one page
    /// is one of those cases: it is neither truncated nor assembled whole, and
    /// the replacement is read in pages (R58).
    async fn move_page(
        &self,
        source: &Snap,
        sql: &str,
        binds: &[BindValue],
        route: &Route<Id, Key>,
    ) -> Option<SnapshotPage> {
        let limits = self.guard.read_limits(Tier::of(&route.principal));
        // The same page budget the subscription's own read uses, so a move
        // cannot deliver more at once than a snapshot may.
        let estimate = source.estimate(sql, binds, &route.principal).await.ok()?;
        let mut attempt: u32 = 0;
        loop {
            let spec = PageSpec {
                after: None,
                max_rows: page_rows(limits.page_bytes, estimate.width),
                timeout: limits.timeout,
            };
            match source
                .snapshot_page(sql, binds, &route.principal, &spec)
                .await
            {
                Ok(page) if page.filled => {
                    tracing::warn!(
                        sub_id = %route.label,
                        "a move read filled its page, replacing the subscription"
                    );
                    return None;
                }
                Ok(page) => return Some(page),
                Err(err) => {
                    attempt = attempt.saturating_add(1);
                    if attempt >= Self::MOVE_ATTEMPTS {
                        tracing::warn!(
                            sub_id = %route.label,
                            error = %err,
                            "a move read kept failing, replacing the subscription"
                        );
                        return None;
                    }
                    tokio::time::sleep(self.auth_retry.backoff(attempt)).await;
                }
            }
        }
    }

    /// Withdraw what a value leaving the set no longer shows: the rows under
    /// the moved value, read on the privileged pool per decision 6, because
    /// the policy that made them visible is exactly what ended and a read as
    /// the caller finds nothing precisely when there is something to
    /// withdraw. Each row still goes through the change-path executor, and
    /// only what is denied is sent, keys only, as indirect deletes: a row the
    /// policy still admits through something other than the term stays put,
    /// and the replica's own membership copy answers the local query. Returns
    /// whether the move was served.
    async fn move_out(
        &self,
        route: &Route<Id, Key>,
        term_move: &TermMove,
        cursor: &[u8],
        grant_moves: &[GrantMove],
    ) -> bool {
        // Only an event that moved a grant reaching the subscribed table for
        // this watcher can have flipped the policy's answer for rows the
        // client held. Any other membership exit is interest-only: nothing is
        // sent, and the replica's own membership copy stops the local query
        // matching. The deny-now set under a parent also contains keys the
        // caller never held, and a delete for a never-held key is the
        // disclosure R6 forbids, which is what this gate closes.
        let policy_moved = grant_moves.iter().any(|moved| {
            route
                .table
                .as_deref()
                .is_some_and(|table| moved.tables.iter().any(|reached| reached == table))
                && concerns(&route.principal, &moved.holder)
        });
        if !policy_moved {
            return true;
        }
        let Some(source) = self.withdrawal_source.get() else {
            return false;
        };
        let base = format!(
            "SELECT * FROM {}",
            connetto_core::quote_ident(&term_move.table)
        );
        let Some(sql) = narrowed_sql(&base, &term_move.pairs) else {
            return false;
        };
        let Some(snapshot) = self.move_page(source, &sql, &[], route).await else {
            return false;
        };
        let Ok(ParsedDiffSet::Patchset(set)) = ParsedDiffSet::parse(&snapshot.patchset) else {
            return false;
        };
        let Some(table_id) = subql::catalog_helpers::table_id::<Postgres, _>(
            self.catalog.as_ref(),
            &term_move.table,
        ) else {
            return false;
        };
        let mut deletes = PatchSet::<TableSchema<String>, String, Vec<u8>>::new();
        let mut any = false;
        for op in set.iter() {
            let PatchsetOp::Insert { values, .. } = &op else {
                continue;
            };
            let row = crate::pk::row_from_wire(self.catalog.as_ref(), table_id, values);
            let view = ValuesRow::new(table_id, &row);
            let watchers = [Arc::clone(&route.principal)];
            let mut verdicts = Vec::new();
            let mut asked: u32 = 0;
            let allowed = loop {
                Verdict::reset(&mut verdicts, watchers.len());
                match self.auth.may_see(&view, &watchers, &mut verdicts).await {
                    Ok(()) => break matches!(verdicts.as_slice(), [Verdict::Allow, ..]),
                    Err(err) => {
                        asked = asked.saturating_add(1);
                        if asked >= Self::MOVE_ATTEMPTS {
                            tracing::warn!(
                                sub_id = %route.label,
                                error = %err,
                                "a move-out visibility question kept failing, replacing the subscription"
                            );
                            return false;
                        }
                        tokio::time::sleep(self.auth_retry.backoff(asked)).await;
                    }
                }
            };
            if allowed {
                continue;
            }
            deletes = deletes
                .delete(PatchDelete::new(op.table().clone(), op.primary_key()).indirect(true));
            any = true;
        }
        if !any {
            return true;
        }
        let Ok(payload) = compress(&deletes.build()) else {
            return false;
        };
        self.send_move(route, cursor, payload).await
    }

    /// Advance the subscription's cursor to the causing event and queue one
    /// live patch for it. Returns whether it was queued, and a refused advance
    /// is logged, since the caller replaces the subscription in its place.
    async fn send_move(&self, route: &Route<Id, Key>, cursor: &[u8], payload: Vec<u8>) -> bool {
        let advanced = {
            counters::timed_lock(&self.materializer)
                .await
                .advance_cursor(route.session_key, route.sub_id, cursor)
        };
        if let Err(err) = advanced {
            counters::add(&counters::CURSOR_REWINDS, 1);
            let rewound = match &err {
                MaterializerError::Cursor(AdvanceCursorError::NonMonotonic {
                    previous,
                    attempted,
                }) => Some((
                    Position::from_cursor_bytes(&previous.0),
                    Position::from_cursor_bytes(&attempted.0),
                )),
                _ => None,
            };
            tracing::error!(
                sub_id = %route.label,
                error = %err,
                ?rewound,
                "a membership move's cursor advance was refused, replacing the subscription instead"
            );
            return false;
        }
        let live = LivePatch::new(route.label.clone(), Cursor::new(cursor.to_vec()), payload);
        // A dropped session receiver just means the client is gone.
        let _ = route.tx.send(Outbound::Live(live));
        true
    }

    /// Bring the authorization store level with `event`, if one is maintained.
    ///
    /// **Called once per event, before it is dispatched, and deliberately not
    /// from `dispatch_event`.** Until the store holds what the row moved, every
    /// question about a row those facts reach is answered from a world that has
    /// moved. But a difference is applied once: an event held through an
    /// outage is dispatched again when the answer comes back, and re-applying a
    /// difference already in the store writes facts that are already there,
    /// which the service refuses. Reached through the ingest loop, which holds
    /// the event, so the retry retries the question and not the write.
    ///
    /// Catchup does not call it, and must not: it replays history whose
    /// differences were applied when those events were live.
    ///
    /// # Errors
    ///
    /// [`SessionError::AuthUnavailable`] for a store that could not be brought level, [`SessionError::ChangeStreamUnusable`] and [`SessionError::AuthorizationUnanswerable`] for a failure that cannot clear.
    async fn keep_store_current(
        &self,
        event: &PgChangeEvent,
    ) -> Result<Vec<GrantMove>, SessionError> {
        match &self.upkeep {
            Some(upkeep) => match upkeep.keep_current(event).await {
                Ok(moves) => Ok(moves),
                Err(crate::openfga::UpkeepError::IncompletePreviousImage) => {
                    Err(SessionError::ChangeStreamUnusable(self.event_table(event)))
                }
                Err(err) if err.clears_by_itself() => {
                    Err(SessionError::AuthUnavailable(err.to_string()))
                }
                Err(err) => Err(SessionError::AuthorizationUnanswerable {
                    table: self.event_table(event),
                    reason: err.to_string(),
                }),
            },
            None => Ok(Vec::new()),
        }
    }

    /// Tell every live subscription a moved grant reaches to replace its rows.
    ///
    /// The instruction goes on the session's own outbound queue, so the notice
    /// and its replacement are produced by the task that holds the transport.
    /// A dropped receiver just means the client has gone.
    ///
    /// One audit row per connection told, which is connetto's own act: a
    /// permission change nobody is connected for records nothing here, and the
    /// grant row itself is the application's to keep (R7 decision 8).
    async fn announce_grant_moves(&self, event: &PgChangeEvent, moves: &[GrantMove]) {
        if moves.is_empty() {
            return;
        }
        let moved_table = self.event_table(event);
        let told: Vec<(SessionId, Option<Id>, String)> = {
            let routes = self.routes.lock().await;
            routes
                .values()
                .filter_map(|route| {
                    let table = route.table.as_deref()?;
                    let concerned = moves.iter().any(|moved| {
                        moved.tables.iter().any(|reached| reached == table)
                            && concerns(&route.principal, &moved.holder)
                    });
                    if !concerned {
                        return None;
                    }
                    // A subscription whose own term watches the moved grant's
                    // table is served incrementally by the membership move
                    // this same event produces (R27 decision 2). The resend
                    // would double-deliver what the move already sends, and
                    // the phase's proof asserts its absence.
                    if route
                        .member_tables
                        .iter()
                        .any(|member| member.table == moved_table)
                    {
                        return None;
                    }
                    let sent = route.tx.send(Outbound::Resnapshot {
                        sub_id: route.label.clone(),
                        reason: FullResyncReason::AuthorizationChange,
                    });
                    sent.is_ok().then(|| {
                        (
                            route.principal.session_id(),
                            route
                                .principal
                                .identity()
                                .map(|identity| identity.user_id.clone()),
                            route.label.clone(),
                        )
                    })
                })
                .collect()
        };
        let grant_row = self.event_table(event);
        let grant_key = self.event_key(event);
        for (session, user_id, label) in told {
            tracing::info!(
                sub_id = %label,
                grant_table = %grant_row,
                "a permission change reached this subscription, replacing its rows"
            );
            self.guard.record(
                AuthEvent::new(session, user_id, AuthOp::PermissionChange)
                    .about_row(grant_row.clone(), grant_key.clone()),
            );
        }
    }

    /// Drive a CDC source to completion, dispatching every row and, at each
    /// commit, recording it and acking it so the upstream can recycle its log.
    ///
    /// When `dispatch_event` returns [`SessionError::AuthUnavailable`] or
    /// [`SessionError::ReadUnavailable`] the loop holds the event, broadcasts
    /// [`ControlMessage::DeliveryPaused`] to every live session with the
    /// matching cause (once per outage, not per retry), and retries after the
    /// shared backoff. On recovery it broadcasts
    /// [`ControlMessage::DeliveryResumed`] and moves on. The source checkpoint
    /// is not acknowledged until dispatch succeeds, so the replication slot never
    /// advances past an unanswered event. Neither pause touches the stream.
    ///
    /// # Errors
    ///
    /// [`SessionError`] when a non-auth dispatch fails or the source errors.
    pub async fn ingest<Src>(
        &self,
        source: &mut Src,
        on_event: &mut impl FnMut(ReconnectEvent<'_>),
    ) -> Result<(), SessionError>
    where
        Src: CdcSource<Event = PgChangeEvent, Commit = PgCommit>,
        Src::Error: core::fmt::Display,
    {
        loop {
            match source.next_item().await {
                Ok(Some(SourceItem::Commit(commit))) => {
                    // Recorded before the acknowledgement, so the slot never resumes past a commit the log does not hold.
                    self.oplog.record_commit(commit).await.map_err(oplog_err)?;
                    source
                        .ack(commit.position())
                        .await
                        .map_err(|err| SessionError::Transport(err.to_string()))?;
                    self.resume.set(Some(commit.position()));
                }
                Ok(Some(SourceItem::Event(event))) => {
                    // One hold loop for both pause causes (R89 decision 2):
                    // an unreachable auth service and a transient computed
                    // read share the arm, each with its own cause and shared
                    // schedule, and the change stream is never touched.
                    let mut auth_backoff = self.auth_retry.start();
                    let mut read_backoff = self.read_retry.start();
                    let mut paused: Option<PauseCause> = None;
                    // Applied once, then only the question is retried. See
                    // `keep_store_current` for why re-applying is refused.
                    let mut levelled = false;
                    // Remembered across auth retries: the store is levelled
                    // once, so the moves exist only on the first attempt, and
                    // a retried dispatch still owes the withdrawal they gate.
                    let mut grant_moves: Vec<GrantMove> = Vec::new();
                    loop {
                        let attempt = async {
                            if !levelled {
                                // Announced here rather than after dispatch, so
                                // the notice cannot be produced twice by the
                                // retry that re-asks the question, and so the
                                // replacement is read against a level store.
                                let moved = self.keep_store_current(&event).await?;
                                levelled = true;
                                self.announce_grant_moves(&event, &moved).await;
                                grant_moves = moved;
                            }
                            self.dispatch_with_grants(&event, &grant_moves).await
                        };
                        match attempt.await {
                            Ok(()) => {
                                if paused.take().is_some() {
                                    self.broadcast_control(ControlMessage::DeliveryResumed)
                                        .await;
                                }
                                break;
                            }
                            Err(SessionError::AuthUnavailable(err)) => {
                                // The internal schedules carry no attempt cap. A capped one
                                // would keep the pause held at the ceiling.
                                let backoff = auth_backoff
                                    .next_wait()
                                    .unwrap_or_else(|| self.auth_retry.max_backoff());
                                if paused != Some(PauseCause::AuthServiceUnreachable) {
                                    self.broadcast_control(ControlMessage::DeliveryPaused {
                                        cause: PauseCause::AuthServiceUnreachable,
                                    })
                                    .await;
                                    paused = Some(PauseCause::AuthServiceUnreachable);
                                }
                                on_event(ReconnectEvent::AuthRetrying {
                                    attempt: auth_backoff.attempt(),
                                    backoff,
                                    error: &err,
                                });
                                tokio::time::sleep(backoff).await;
                            }
                            Err(SessionError::ReadUnavailable(err)) => {
                                let backoff = read_backoff
                                    .next_wait()
                                    .unwrap_or_else(|| self.read_retry.max_backoff());
                                if paused != Some(PauseCause::DatabaseUnreachable) {
                                    self.broadcast_control(ControlMessage::DeliveryPaused {
                                        cause: PauseCause::DatabaseUnreachable,
                                    })
                                    .await;
                                    paused = Some(PauseCause::DatabaseUnreachable);
                                }
                                on_event(ReconnectEvent::ReadRetrying {
                                    attempt: read_backoff.attempt(),
                                    backoff,
                                    error: &err,
                                });
                                tokio::time::sleep(backoff).await;
                            }
                            Err(other) => return Err(other),
                        }
                    }
                    // A row is acknowledged with its commit, since acknowledging it alone moves nothing.
                    self.resume.set(Some(event.position()));
                }
                Ok(None) => return Ok(()),
                Err(err) => return Err(SessionError::Transport(err.to_string())),
            }
        }
    }

    /// Ingest CDC events, reconnecting the source with backoff when the stream
    /// fails.
    ///
    /// `connect` produces a fresh source each time and is handed where to
    /// resume, a [`ResumePoint`] whose [`get`](ResumePoint::get) goes to the
    /// source's `start`. It names the last row or commit this manager handled,
    /// or nothing before the first, when the slot's confirmed position decides.
    /// Resuming exactly after it keeps an engine cursor from ever seeing a
    /// position twice, and loses nothing because the slot was only released
    /// past commits already handled. Read it after any
    /// [`check_before_stream`](Self::check_before_stream), which clears it when
    /// the timeline changed or the feed skipped a stretch. `on_event` observes each retry and the final give-up, for logging
    /// or metrics. Returns `Ok(())` when a source signals a clean shutdown, or
    /// an error only once `policy` exhausts its attempts (a policy with no
    /// `max_attempts` retries forever).
    ///
    /// # Errors
    ///
    /// [`SessionError`] when the reconnect policy gives up, or when a dispatch
    /// fails.
    pub async fn ingest_with_reconnect<Src, Connect, F, E>(
        &self,
        mut connect: Connect,
        policy: &ReconnectPolicy,
        mut on_event: impl FnMut(ReconnectEvent<'_>),
    ) -> Result<(), SessionError>
    where
        Src: CdcSource<Event = PgChangeEvent, Commit = PgCommit>,
        Src::Error: core::fmt::Display,
        Connect: FnMut(ResumePoint) -> F,
        F: core::future::Future<Output = Result<Src, E>>,
        E: core::fmt::Display,
    {
        let mut episode = policy.start();
        loop {
            let error = match connect(self.resume.clone()).await {
                Ok(mut source) => {
                    let started = Instant::now();
                    match self.ingest(&mut source, &mut on_event).await {
                        Ok(()) => return Ok(()),
                        // The same event meets the same refusal after a reconnect (R6 decision 4).
                        Err(
                            err @ (SessionError::ChangeStreamUnusable(_)
                            | SessionError::AuthorizationUnanswerable { .. }),
                        ) => return Err(err),
                        Err(err) => {
                            if started.elapsed() >= policy.healthy_after {
                                episode.reset();
                            }
                            err.to_string()
                        }
                    }
                }
                Err(err) => err.to_string(),
            };
            // The failed connect is itself an attempt, so Some(n) stops on
            // the nth failure. The driver's own cap counts the waits it
            // hands out, one fewer than this loop's failures, so the limit
            // is checked against the failures here.
            let failures = episode.attempt() + 1;
            let Some(backoff) = episode
                .next_wait()
                .filter(|_| !attempt_limit_reached(policy.max_attempts(), failures))
            else {
                on_event(ReconnectEvent::GaveUp {
                    attempts: failures,
                    error: &error,
                });
                return Err(SessionError::Transport(format!(
                    "cdc ingest gave up after {failures} attempts: {error}"
                )));
            };
            on_event(ReconnectEvent::Retrying {
                attempt: episode.attempt(),
                backoff,
                error: &error,
            });
            tokio::time::sleep(backoff).await;
        }
    }

    /// Send one computed-result change to the session owning its
    /// subscription, if routed.
    async fn deliver_computed(&self, change: ComputedChange) {
        let route = {
            self.computed_routes
                .lock()
                .await
                .get(&change.subscription_id)
                .cloned()
        };
        let Some(route) = route else { return };
        let update = AggregateUpdate {
            sub_id: route.label,
            group_key: change.group_key,
            group_values_json: change.group_values_json,
            result_json: change.result_json,
            is_full_result: change.is_full_result,
        };
        let _ = route.tx.send(Outbound::Aggregate(update));
    }

    /// End one computed subscription because its read was refused, telling the
    /// client only what every refusal tells it.
    ///
    /// The wire carries R38's one fixed phrase and the log carries the cause, so
    /// a caller cannot tell an unusably heavy query from any other refusal while
    /// the developer reads the reason. Called from paths that hold no transport
    /// of their own, so the frame travels the route's channel the same way a
    /// computed value does.
    ///
    /// The session's own `computed_subs` entry is left in place: a later
    /// unsubscribe naming it removes nothing and reports nothing, which is what
    /// an already ended subscription should do.
    async fn refuse_computed<E: core::fmt::Display>(
        &self,
        subscription_id: SubscriptionId,
        class: ReadFailure,
        attempts: u32,
        cause: &E,
    ) {
        let route = { self.computed_routes.lock().await.remove(&subscription_id) };
        self.materializer.lock().await.unregister(subscription_id);
        let Some(route) = route else { return };
        tracing::warn!(
            sub_id = %route.label,
            class = %class,
            attempts,
            cause = %cause,
            "a computed subscription's read was refused, ending the subscription"
        );
        let _ = route
            .tx
            .send(Outbound::Control(ControlMessage::NonFatalError(
                NonFatalError {
                    related_to: Some(route.label),
                    detail: SUBSCRIPTION_REFUSED.to_owned(),
                },
            )));
    }

    /// The connection's opening exchange (R91). The server sends the
    /// challenge and the peer answers with its handshake or a bot's
    /// registration, the loop repeating on a fresh nonce until one of the two
    /// settles.
    ///
    /// A settled handshake is handed to the handshake with its nonce spent. A
    /// settled registration is answered with the bot id and a refused one
    /// with the refusal frame, and the loop carries on either way. The first
    /// frame read is bounded by the first-frame budget, so a silent peer
    /// holds no connection for the budget's length.
    ///
    /// Returns the peer's handshake, or `None` when the peer closed, the
    /// manager is shutting down, or the connection's refusals crossed its
    /// abuse limit.
    ///
    /// # Errors
    ///
    /// [`SessionError::Protocol`] when the peer sends neither a handshake nor
    /// a registration, or stays silent until the deadline, and
    /// [`SessionError::Registry`] when the registry cannot settle a
    /// registration.
    async fn registration_gate<T: Transport>(
        &self,
        transport: &mut T,
    ) -> Result<Option<(Handshake, [u8; 32])>, SessionError> {
        // The tally of a connection that never proves an identity keys on the
        // connection alone, so the gate mints the id the tally names.
        let session = SessionId::from_uuid(Uuid::new_v4());
        let mut nonce = Self::mint_nonce();
        let result: Result<Option<(Handshake, [u8; 32])>, SessionError> =
            loop {
                if self.shutting_down.load(Ordering::Acquire) {
                    let _ = transport
                        .send_control(ControlMessage::FatalError(FatalError::new(
                            FatalErrorReason::ServerShuttingDown,
                        )))
                        .await;
                    break Ok(None);
                }
                if let Err(err) = transport
                    .send_control(ControlMessage::Challenge(Challenge { nonce }))
                    .await
                    .map_err(transport_err)
                {
                    break Err(err);
                }
                let frame =
                    match tokio::time::timeout(self.config.first_frame_budget(), transport.recv())
                        .await
                    {
                        Ok(frame) => frame.map_err(transport_err),
                        Err(_) => Err(SessionError::Protocol(
                            "no first frame before the deadline".into(),
                        )),
                    };
                match frame {
                    Err(err) => break Err(err),
                    Ok(None) => break Ok(None),
                    Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(handshake)))) => {
                        break Ok(Some((handshake, nonce)));
                    }
                    Ok(Some(IncomingFrame::Control(ControlMessage::RegisterBot(registration)))) => {
                        match self.settle_registration(&registration, &nonce).await {
                            Ok(RegistrationOutcome::Registered(bot)) => {
                                if let Err(err) = transport
                                    .send_control(ControlMessage::BotRegistered(BotRegistered {
                                        bot_id: bot.to_string(),
                                    }))
                                    .await
                                    .map_err(transport_err)
                                {
                                    break Err(err);
                                }
                            }
                            Ok(RegistrationOutcome::Refused(refusal)) => {
                                tracing::warn!(?refusal, "a registration was refused");
                                if let Err(err) = transport
                                    .send_control(ControlMessage::RegistrationRefused)
                                    .await
                                    .map_err(transport_err)
                                {
                                    break Err(err);
                                }
                                // The refusal is metered at the tier that has not
                                // proved an identity, the way a handshake's
                                // refused grants are.
                                if self.guard.refused_grants(
                                    Caller {
                                        session,
                                        user: None,
                                    },
                                    1,
                                ) == Reaction::Close
                                {
                                    break Ok(None);
                                }
                            }
                            Err(err) => break Err(err),
                        }
                    }
                    Ok(Some(_)) => {
                        break Err(SessionError::Protocol(
                            "expected a handshake or a registration first".into(),
                        ));
                    }
                }
                // A settlement that landed on the shutdown flag is told
                // the shutdown instead of opening another round.
                if self.shutting_down.load(Ordering::Acquire) {
                    let _ = transport
                        .send_control(ControlMessage::FatalError(FatalError::new(
                            FatalErrorReason::ServerShuttingDown,
                        )))
                        .await;
                    break Ok(None);
                }
                nonce = Self::mint_nonce();
            };
        // The tally id is minted here and is not the session id run_session retires.
        self.guard.forget_connection(session);
        result
    }

    /// Settle a registration on the owner pool before identity (R91).
    ///
    /// The checks run in the order list, then signature, then code, and only
    /// a registration that clears the first two reaches the registry's
    /// transaction, so a bad list or a bad signature never touches the
    /// database and the code is looked up only when it will be spent. A
    /// registry failure is a [`SessionError::Registry`], not a refusal, so a
    /// database outage does not spend the bot's only code.
    ///
    /// # Errors
    ///
    /// [`SessionError::Registry`] when the registry's pool or a statement
    /// fails.
    async fn settle_registration(
        &self,
        registration: &RegisterBot,
        nonce: &[u8; 32],
    ) -> Result<RegistrationOutcome, SessionError> {
        let Some(registry) = &self.bot_registry else {
            return Ok(RegistrationOutcome::Refused(RegistrationRefusal::Code));
        };
        let mut list = Vec::with_capacity(registration.list.len());
        for entry in &registration.list {
            let synced = self
                .catalog
                .tables()
                .any(|table| table.stored_table_name() == entry.table);
            if !synced {
                return Ok(RegistrationOutcome::Refused(
                    RegistrationRefusal::TableNotSynced {
                        table: entry.table.clone(),
                    },
                ));
            }
            let Some(verb) = Verb::parse(&entry.verb) else {
                return Ok(RegistrationOutcome::Refused(
                    RegistrationRefusal::UnknownVerb {
                        verb: entry.verb.clone(),
                    },
                ));
            };
            list.push(ListEntry {
                table: entry.table.clone(),
                verb,
                optional: entry.optional,
            });
        }
        let message = bot_registration_message(nonce);
        let key = UnparsedPublicKey::new(&ED25519, &registration.public_key);
        if key.verify(&message, &registration.signature).is_err() {
            return Ok(RegistrationOutcome::Refused(RegistrationRefusal::Signature));
        }
        let code_hash: [u8; 32] =
            Sha256::digest(connetto_core::bots::canonical_code(&registration.code).as_bytes())
                .into();
        match registry
            .register(
                code_hash,
                registration.public_key,
                registration.name.clone(),
                &list,
            )
            .await
        {
            Ok(registered) => Ok(RegistrationOutcome::Registered(registered.bot)),
            Err(RegistryError::Refused) => {
                Ok(RegistrationOutcome::Refused(RegistrationRefusal::Code))
            }
            Err(error) => Err(SessionError::Registry(error.to_string())),
        }
    }

    /// The 32-byte nonce of one registration round (R91), filled from the
    /// system random source the way the enrolment nonce is.
    fn mint_nonce() -> [u8; 32] {
        let mut nonce = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .expect("the system random source fills a 32-byte nonce");
        nonce
    }

    /// Validate the handshake the gate received, resolve the writer the
    /// connection writes as, decode the resume cursor, and reply with the ack
    /// carrying the server's current cursor and the writer's grant.
    ///
    /// Returns the session identity, or `None` when the manager is shutting
    /// down.
    #[expect(
        clippy::too_many_lines,
        reason = "registration must sit between the grant checks and the ack, so splitting it would let a revocation cross the gap again"
    )]
    async fn run_handshake<T: Transport>(
        &self,
        transport: &mut T,
        handshake: Handshake,
        nonce: [u8; 32],
    ) -> Result<Option<HandshakeOutcome<Id, Key>>, SessionError> {
        if handshake.protocol_version != PROTOCOL_VERSION {
            // Outside any connection context on purpose: no session exists yet,
            // so the handle is absent rather than a stand-in.
            tracing::warn!(
                client_id = %handshake.client_id,
                expected = PROTOCOL_VERSION,
                got = handshake.protocol_version,
                "handshake refused, protocol version mismatch"
            );
            let _ = transport
                .send_control(ControlMessage::FatalError(FatalError::new(
                    FatalErrorReason::ProtocolVersionMismatch {
                        expected: PROTOCOL_VERSION,
                        got: handshake.protocol_version,
                    },
                )))
                .await;
            return Err(SessionError::Protocol(format!(
                "protocol version mismatch: server {PROTOCOL_VERSION}, client {}",
                handshake.protocol_version
            )));
        }

        let connection_num = self.next_connection_num();
        // The handle comes before the grants on purpose: a run has one whether
        // or not anybody is signed in, and having it first is what lets the
        // logging context cover the grant checks below. Identity is resolved
        // only from checked grants, never from the client-supplied `client_id`,
        // which stays a pure correlation label.
        let handle = self.resume_handle(handshake.resume_token.as_deref(), &handshake.client_id);
        // A span attaches its values only when its own level passes the filter,
        // so the context has to be at least as severe as the least verbose
        // event that must carry it. That event is a refused grant, at warn, and
        // it is the one line where losing the handle would matter most: an
        // operator who quiets this process to warn would otherwise keep exactly
        // the security-relevant line and lose the run it belongs to.
        let span = tracing::warn_span!(
            "connection",
            session = %handle,
            user = tracing::field::Empty,
            connection = connection_num,
        );
        let ResolvedGrants {
            principal,
            key_expiry,
            refusals: refused_grants,
            wait: grant_wait,
        } = self
            .resolve_grants(
                handle,
                &handshake.grants,
                GrantSource::Handshake(&handshake.client_id),
            )
            .instrument(span.clone())
            .await;
        if let Some(identity) = principal.identity() {
            span.record("user", tracing::field::display(&identity.user_id));
        }
        let session_id = principal.session_id();
        let tier = Tier::of(&principal);
        if self
            .refuse_over_limit(transport, session_id, tier, grant_wait, &span)
            .await
        {
            // The refusals still count. A rate limit caps how fast a signal can
            // accumulate and must never erase what it already saw, or the caller
            // spraying keys fast enough to trip it would be the one caller this
            // phase cannot see. The reaction is ignored because this connection
            // is ending either way, and a ban that lands closes the caller's
            // other connections through the hook.
            //
            // This and the announcement in `run_session` are the two ends of one
            // count and are mutually exclusive. The ban refusal below needs
            // neither: that caller is already banned, so tallying more would only
            // re-ask the application about a decision it has taken.
            let _ = span.in_scope(|| {
                self.guard
                    .refused_grants(Self::caller(&principal), refused_grants)
            });
            // None: no session to run, so `serve` completes cleanly.
            return Ok(None);
        }

        if self.refuse_if_banned(&principal, &span).await? {
            return Ok(None);
        }

        let mut resume_read_budget = self.config.resume_read_budget;
        let current_position =
            read_log::<O, _, _>(&mut resume_read_budget, || self.oplog.current_position()).await?;
        let user_id = principal
            .identity()
            .map(|identity| identity.user_id.clone());
        // A number writer issued to a caller with no identity belongs to its run (R75).
        let bind_session = user_id.is_none().then(|| *session_id.as_uuid());
        // The writer reads are the handshake's reader-pool checkouts, so an unidentified caller takes a share permit for them (R39).
        let Some(reader_permit) = self
            .handshake_reader_permit(transport, tier, &principal, refused_grants, &span)
            .await
        else {
            return Ok(None);
        };
        let mut writer_row: Option<WriterRow<Id>> = None;
        let mut writer_grant = None;
        match handshake.writer {
            WriterRequest::Issue => {
                let (writer, frontier) = self
                    .target
                    .issue_writer(user_id.clone(), bind_session)
                    .await
                    .map_err(|err| SessionError::WriteTarget(err.detail()))?;
                writer_grant = Some(WriterGrant {
                    number: u64::try_from(writer).unwrap_or(0),
                    frontier: u64::try_from(frontier).unwrap_or(0),
                });
                writer_row = Some(WriterRow {
                    writer,
                    user_id,
                    device_key: None,
                    frontier,
                    head: None,
                    retired_at: None,
                });
            }
            WriterRequest::Number(number) => {
                let writer = i64::try_from(number).unwrap_or(i64::MAX);
                match self
                    .target
                    .writer_by_number(writer, user_id.as_ref(), bind_session.as_ref())
                    .await
                    .map_err(|err| SessionError::WriteTarget(err.detail()))?
                {
                    Some(row) if row.retired_at.is_some() => {
                        // A retired writer still retires its settled records at the handshake.
                        if let Some(settled_through) = handshake.settled_through {
                            self.target
                                .prune_settled(row.writer, settled_through)
                                .await
                                .map_err(|err| SessionError::WriteTarget(err.detail()))?;
                        }
                        let _ = transport
                            .send_control(ControlMessage::FatalError(FatalError::new(
                                FatalErrorReason::WriterRetired,
                            )))
                            .await;
                        return Ok(None);
                    }
                    Some(row) => {
                        writer_grant = Some(WriterGrant {
                            number,
                            frontier: u64::try_from(row.frontier).unwrap_or(0),
                        });
                        writer_row = Some(row);
                    }
                    None => {
                        let _ = transport
                            .send_control(ControlMessage::FatalError(FatalError::new(
                                FatalErrorReason::WriterUnknown,
                            )))
                            .await;
                        return Ok(None);
                    }
                }
            }
            WriterRequest::Device => {}
        }
        if let (Some(settled_through), Some(row)) = (handshake.settled_through, &writer_row) {
            self.target
                .prune_settled(row.writer, settled_through)
                .await
                .map_err(|err| SessionError::WriteTarget(err.detail()))?;
        }
        drop(reader_permit);
        let resume_token = self
            .authority
            .mint_handle(session_id)
            .map_err(|err| SessionError::Handle(err.to_string()))?;
        // Register BEFORE sending the ack. The ack is the client's signal that
        // this session handle is addressable: close_session and revocation hooks
        // fire as soon as the ack arrives. Without the entry already in the map
        // those calls see None and the fatal frame is never delivered.
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Outbound>();
        if !self
            .register_connection(
                session_id,
                connection_num,
                principal
                    .identity()
                    .map(|identity| identity.user_id.to_string()),
                &outbound_tx,
            )
            .await
        {
            // The shutdown began while this handshake ran, so the session is
            // told to go away rather than registered into the drained registry.
            let _ = transport
                .send_control(ControlMessage::FatalError(FatalError::new(
                    FatalErrorReason::ServerShuttingDown,
                )))
                .await;
            return Ok(None);
        }
        // Judged only once registered, so a history read that lands meanwhile
        // either shows here or closes this connection (R73).
        let resume = self.resume_from(handshake.last_cursor.as_ref());
        let current_cursor =
            Cursor::new(current_position.map_or_else(Vec::new, |at| self.stamp(at)));

        if let Err(err) = transport
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: format!("connection-{connection_num}"),
                session_token: session_id.to_string(),
                resume_token,
                current_cursor,
                schema_version: self.config.schema_version.clone(),
                initial_credits: self.config.initial_credits,
                writer: writer_grant,
            }))
            .await
        {
            // Registering before the ack means an ack that never leaves would
            // otherwise strand the entry, since no run loop follows to drop it.
            self.unregister_connection(session_id, connection_num).await;
            return Err(transport_err(err));
        }
        Ok(Some(HandshakeOutcome {
            connection_num,
            principal: Arc::new(principal),
            resume,
            resume_read_budget,
            writer_row,
            bind_nonce: nonce,
            refused_grants,
            span,
            outbound_tx,
            outbound_rx,
            key_expiry,
            cursor_subjects: handshake
                .cursor_subjects
                .map(|subjects| subjects.into_iter().collect()),
        }))
    }

    /// Take the handshake's reader-share permit (R39), refusing the connection with R19's fatal shape while the unreserved share stays full.
    async fn handshake_reader_permit<T: Transport>(
        &self,
        transport: &mut T,
        tier: Tier,
        principal: &Principal<Id, Key>,
        refused_grants: u32,
        span: &tracing::Span,
    ) -> Option<ReaderPermit> {
        match self.guard.reader_permit(tier).await {
            Ok(permit) => Some(permit),
            Err(wait) => {
                let retry_after_ms = retry_ms(wait);
                span.in_scope(|| {
                    tracing::warn!(
                        retry_after_ms,
                        "connection refused, the unreserved reader share is full"
                    );
                });
                let _ = transport
                    .send_control(ControlMessage::FatalError(FatalError::new(
                        FatalErrorReason::RateLimited { retry_after_ms },
                    )))
                    .await;
                let _ = span.in_scope(|| {
                    self.guard
                        .refused_grants(Self::caller(principal), refused_grants)
                });
                None
            }
        }
    }

    /// Refuse a caller that is over a rate limit, reporting whether it was.
    ///
    /// The credential count short-circuits the connection one, so a caller
    /// already being turned away for it does not also spend a connection, and
    /// the check runs before any store work.
    async fn refuse_over_limit<T: Transport>(
        &self,
        transport: &mut T,
        session_id: SessionId,
        tier: Tier,
        grant_wait: Option<Duration>,
        span: &tracing::Span,
    ) -> bool {
        let refused = grant_wait
            .map(|wait| ("credential refusal limit", wait))
            .or_else(|| {
                self.guard
                    .connection(session_id, tier)
                    .map(|wait| ("connection limit", wait))
            });
        let Some((limit, wait)) = refused else {
            return false;
        };
        let retry_after_ms = retry_ms(wait);
        // Inside the connection context, so the line names the handle it
        // refused. Unlike a version mismatch, a run exists here.
        span.in_scope(|| {
            tracing::warn!(
                retry_after_ms,
                limit,
                "connection refused, rate limit reached"
            );
        });
        let _ = transport
            .send_control(ControlMessage::FatalError(FatalError::new(
                FatalErrorReason::RateLimited { retry_after_ms },
            )))
            .await;
        true
    }

    /// Take the mutation's reader-share permit (R39) and then charge its
    /// compressed bytes to the caller's window, in that order so a write the
    /// share defers has spent nothing and is not charged twice on resend. Either
    /// refusal defers the mutation in R19's shape and reports [`None`].
    ///
    /// The refusal is correlated by the `client_seq` rendered as a string,
    /// exactly as `NonFatalError` correlates, and records the deferral so every
    /// later sequence on this connection waits behind it. The mutation is
    /// neither applied nor acknowledged, so it stays pending on the client and
    /// replays in order. The byte window is keyed by identity, and by the
    /// session handle for a caller with none, so unidentified runs never share
    /// one bucket.
    async fn mutation_permit<T: Transport>(
        &self,
        transport: &mut T,
        patch: &MutationPatch,
        state: &mut SessionState<Id, Key>,
    ) -> Result<Option<ReaderPermit>, SessionError> {
        let client_seq = patch.client_seq;
        let permit = match self.guard.reader_permit(Tier::of(&state.principal)).await {
            Ok(permit) => permit,
            Err(wait) => {
                tracing::warn!(
                    client_seq,
                    retry_after_ms = retry_ms(wait),
                    "mutation deferred, the unreserved reader share is full"
                );
                self.defer_mutation(transport, client_seq, wait).await?;
                state.deferred.insert(client_seq, retry_ms(wait));
                return Ok(None);
            }
        };
        let key = crate::capability::meter_key(&state.principal, state.session_id);
        let patch_len = u64::try_from(patch.patchset_zstd.len()).unwrap_or(u64::MAX);
        match self.guard.bytes().allow_mutation_bytes(&key, patch_len) {
            Ok(()) => Ok(Some(permit)),
            Err(wait) => {
                tracing::warn!(
                    client_seq,
                    patch_len,
                    retry_after_ms = retry_ms(wait),
                    "mutation deferred, the caller's byte window is spent"
                );
                self.defer_mutation(transport, client_seq, wait).await?;
                state.deferred.insert(client_seq, retry_ms(wait));
                Ok(None)
            }
        }
    }

    /// Answer `RateLimited` for `client_seq`, leaving it pending on the client to replay.
    async fn defer_mutation<T: Transport>(
        &self,
        transport: &mut T,
        client_seq: u64,
        wait: Duration,
    ) -> Result<(), SessionError> {
        transport
            .send_control(ControlMessage::RateLimited(RateLimited {
                related_to: Some(client_seq.to_string()),
                retry_after_ms: retry_ms(wait),
            }))
            .await
            .map_err(transport_err)
    }

    /// The mutation gate before the watermark. The header and patch must agree
    /// on the sequence, refused with a reject the client rolls back, since the
    /// pair can never be resent as it is. The per-write measurement an
    /// operator sizes the meter from is logged. `false` means the mutation was
    /// answered here.
    async fn admit_mutation<T: Transport>(
        &self,
        transport: &mut T,
        header: &MutationHeader,
        patch: &MutationPatch,
    ) -> Result<bool, SessionError> {
        let client_seq = patch.client_seq;
        let patch_len = patch.patchset_zstd.len();
        tracing::debug!(
            client_seq,
            op_count = header.op_count,
            patch_bytes = patch_len,
            "mutation received"
        );
        let refusal = (header.client_seq != client_seq)
            .then(|| "mutation header and patch client_seq disagree".to_owned());
        if let Some(detail) = refusal {
            self.reject(
                transport,
                client_seq,
                MutationRejectReason::Other { detail },
            )
            .await?;
            return Ok(false);
        }
        Ok(true)
    }

    /// Take the content ticket's reader-share permit (R39), or defer the
    /// request in R19's nonfatal shape and report [`None`].
    ///
    /// Visibility runs on the reader pool, so the same gate that protects
    /// subscription and mutation reads protects the ticket path. The refusal
    /// is correlated by the request id.
    async fn ticket_reader_permit<T: Transport>(
        &self,
        transport: &mut T,
        request_id: &str,
        state: &SessionState<Id, Key>,
    ) -> Result<Option<ReaderPermit>, SessionError> {
        match self.guard.reader_permit(Tier::of(&state.principal)).await {
            Ok(permit) => Ok(Some(permit)),
            Err(wait) => {
                let retry_after_ms = retry_ms(wait);
                tracing::warn!(
                    request_id,
                    retry_after_ms,
                    "content ticket deferred, the unreserved reader share is full"
                );
                transport
                    .send_control(ControlMessage::RateLimited(RateLimited {
                        related_to: Some(request_id.to_owned()),
                        retry_after_ms,
                    }))
                    .await
                    .map_err(transport_err)?;
                Ok(None)
            }
        }
    }

    /// Whether the caller is banned, checked one frame after the grant that
    /// named them because nothing identifies a caller earlier and a browser
    /// cannot read the status of a refused upgrade anyway.
    ///
    /// A banned caller is told nothing: no frame and no reason, with the ban
    /// going to the structured log. A ban list that cannot be read refuses the
    /// connection, so a ban never lapses because a table was briefly unreadable
    /// and an attacker who can cause an outage cannot suspend their own ban.
    async fn refuse_if_banned(
        &self,
        principal: &Principal<Id, Key>,
        span: &tracing::Span,
    ) -> Result<bool, SessionError> {
        let Some(identity) = principal.identity() else {
            return Ok(false);
        };
        let ban = span
            .in_scope(|| self.guard.banned(&identity.user_id))
            .await
            .map_err(|err| SessionError::BanList(err.detail().to_owned()))?;
        let Some(ban) = ban else {
            return Ok(false);
        };
        span.in_scope(|| {
            tracing::warn!(
                reason = %ban.reason,
                permanent = ban.expires_at.is_none(),
                "handshake refused, identity banned"
            );
        });
        Ok(true)
    }

    /// The handle this run continues on: the one inside a resume credential
    /// this server signed, or a fresh one when there is none or it does not
    /// check out. An identified run replaces it with its login grant's handle.
    ///
    /// Refusing an unsigned credential is what stops a caller choosing the key
    /// to its own server-side state, or resuming as a visitor whose handle it
    /// obtained.
    fn resume_handle(&self, presented: Option<&str>, client_id: &str) -> SessionId {
        let Some(blob) = presented else {
            return SessionId::from_uuid(uuid::Uuid::new_v4());
        };
        self.authority.read_handle(blob).unwrap_or_else(|err| {
            tracing::warn!(
                client_id = %client_id,
                error = %err,
                "resume credential refused, starting a fresh run"
            );
            SessionId::from_uuid(uuid::Uuid::new_v4())
        })
    }

    /// Check every grant on its own and fold what resolved into the caller,
    /// returning when each resolved key dies, how many grants were refused, and
    /// the wait the rate limit imposed.
    ///
    /// A refusal is recorded here and nowhere else. It does not end the
    /// connection and the reply says nothing about it, so this log line is the
    /// entire visibility story: without it a checker that refuses everything
    /// and one that accepts everything look identical from the client.
    ///
    /// The count travels rather than being tallied here, because a login grant
    /// may follow a bad key in the list, so who to attribute the refusals to is
    /// not known until the loop finishes.
    ///
    /// Tripping the refusal limit stops the loop. One handshake carries as many
    /// grants as fit in a frame, so continuing would buy the caller every
    /// remaining signature check after the limit already said no, and the
    /// connection is closed on the returned wait regardless.
    ///
    /// A key swap keeps the identity the handshake resolved, so a grant naming
    /// a person there is refused like one that fails to check.
    async fn resolve_grants(
        &self,
        handle: SessionId,
        grants: &[Grant],
        source: GrantSource<'_>,
    ) -> ResolvedGrants<Id, Key> {
        let mut resolved = ResolvedGrants {
            principal: Principal::unidentified(handle),
            key_expiry: BTreeMap::new(),
            refusals: 0,
            wait: None,
        };
        let mut unbounded = BTreeSet::new();
        for (position, grant) in grants.iter().enumerate() {
            let position = u64::try_from(position).unwrap_or(u64::MAX);
            let refused = match self.authority.check_grant(grant).await {
                Ok(CheckedGrant {
                    subject: Subject::Identity(_),
                    ..
                }) if matches!(source, GrantSource::Swap(_)) => {
                    source.log_refusal(position, "identity", "a key swap keeps its identity");
                    true
                }
                Ok(CheckedGrant {
                    subject,
                    expires_at,
                }) => {
                    let kind = subject_kind(&subject);
                    let key = match &subject {
                        Subject::Capability(capability) => Some(capability.key().to_string()),
                        Subject::Identity(_) => None,
                    };
                    let ambiguous = resolved.principal.accept(subject).is_err();
                    if ambiguous {
                        source.log_refusal(position, "ambiguous", kind);
                    } else if let Some(key) = key {
                        match expires_at {
                            Some(expires_at) if !unbounded.contains(&key) => {
                                let at = resolved.key_expiry.entry(key).or_insert(expires_at);
                                *at = (*at).max(expires_at);
                            }
                            None => {
                                resolved.key_expiry.remove(&key);
                                unbounded.insert(key);
                            }
                            Some(_) => {}
                        }
                    }
                    ambiguous
                }
                Err(refusal) => {
                    source.log_refusal(position, refusal.reason(), &refusal.to_string());
                    true
                }
            };
            if !refused {
                continue;
            }
            resolved.refusals = resolved.refusals.saturating_add(1);
            // A refused grant never establishes an identity, so the refusal is
            // metered at the tier that has not proved one.
            if let Some(wait) = self.guard.credential_refusal(handle, Tier::Anonymous) {
                resolved.wait = Some(wait);
                break;
            }
        }
        resolved
    }

    /// Serve one connection to completion: the registration gate, the
    /// handshake, the run loop, and cleanup on disconnect.
    ///
    /// # Errors
    ///
    /// [`SessionError`] on a transport failure, a protocol violation, a
    /// snapshot failure, or a materializer error.
    pub async fn serve<T: Transport>(
        self: Arc<Self>,
        mut transport: T,
    ) -> Result<(), SessionError> {
        let _tally = OpenSessionTally::start(self.open_sessions.clone());
        let Some((handshake, nonce)) = self.registration_gate(&mut transport).await? else {
            return Ok(());
        };
        let Some(outcome) = self.run_handshake(&mut transport, handshake, nonce).await? else {
            return Ok(());
        };
        let span = outcome.span.clone();
        self.run_session(transport, outcome).instrument(span).await
    }

    /// The run loop and its teardown, inside the connection's logging context.
    async fn run_session<T: Transport>(
        self: Arc<Self>,
        mut transport: T,
        outcome: HandshakeOutcome<Id, Key>,
    ) -> Result<(), SessionError> {
        let HandshakeOutcome {
            connection_num,
            principal,
            resume,
            resume_read_budget,
            writer_row,
            bind_nonce,
            refused_grants,
            span: _,
            outbound_tx,
            mut outbound_rx,
            key_expiry,
            cursor_subjects,
        } = outcome;
        let session_id = principal.session_id();
        tracing::info!(?resume, "connection established");

        // The refusals the handshake collected are tallied here rather than as
        // they happened, because the caller may not be fully resolved until all
        // grants are checked. The connection is already registered (in
        // run_handshake, before the ack) so a crossing ban can close it.
        let refused = self
            .guard
            .refused_grants(Self::caller(&principal), refused_grants);
        let mut state = SessionState {
            credits: self.config.initial_credits,
            pending: VecDeque::new(),
            subs: HashMap::new(),
            paging: VecDeque::new(),
            reader_reservation: ReaderReservation::default(),
            missed: Vec::new(),
            computed_subs: HashMap::new(),
            outbound: outbound_tx,
            principal,
            pending_header: None,
            writer_row,
            session_id,
            bind_nonce,
            indeterminate: None,
            deferred: BTreeMap::new(),
            resume,
            resume_read_budget,
            cursor_subjects,
            key_expiry,
            closing: refused == Reaction::Close,
            enrol_challenge: None,
        };
        self.send_revocation_lists(&mut transport, &state).await;

        // Every exit breaks with its result rather than returning, so the teardown below always runs.
        let mut last_inbound = tokio::time::Instant::now();
        let ended: Result<(), SessionError> = loop {
            if state.closing {
                break Ok(());
            }
            // Between two frames, so the rows a snapshot missed precede every live patch still queued, which all commit later.
            if !state.missed.is_empty()
                && let Err(err) = self.replay_missed(&mut transport, &mut state).await
            {
                break Err(err);
            }
            // One task, two arms. The transport arm awaits a whole subscribe,
            // including its first page of rows, so the outbound arm cannot
            // interleave a live patch into that. A read still arriving in
            // pages is the one exception, deliberately: its later pages are
            // taken when the client acknowledges, so a live patch may land
            // between two pages. That is safe in one direction only and the
            // direction is the right one, because a page is read after every
            // frame already sent (R58 decision 9).
            // Moving either arm onto its own task breaks that silently.
            tokio::select! {
                incoming = transport.recv() => {
                    match self.handle_incoming(&mut transport, incoming, &mut state).await {
                        Ok(true) => last_inbound = tokio::time::Instant::now(),
                        Ok(false) => break Ok(()),
                        Err(err) => break Err(err),
                    }
                }
                outbound = outbound_rx.recv() => {
                    let Some(outbound) = outbound else { break Ok(()) };
                    match self.handle_outbound(&mut transport, outbound, &mut state).await {
                        Ok(true) => {}
                        Ok(false) => break Ok(()),
                        Err(err) => break Err(err),
                    }
                }
                () = next_key_expiry(&state.key_expiry, &self.config) => self.expire_keys(&mut state).await,
                // Only an inbound frame moves `last_inbound`, so this is the client's silence.
                () = tokio::time::sleep_until(last_inbound + self.config.idle_limit()) => break Ok(()),
            }
        };

        // Runs on every exit, an error included, so no ended session stays registered.
        self.unregister_connection(session_id, connection_num).await;
        // A session that was bound to a device writer leaves the writer's live
        // set, so a later retirement does not try to close it again (R75).
        if let Some(row) = state
            .writer_row
            .as_ref()
            .filter(|row| row.device_key.is_some())
        {
            let mut live = self.writer_sessions.lock().await;
            if let Some(set) = live.get_mut(&row.writer) {
                set.remove(&session_id);
            }
        }
        // The connection is the window for a caller with no identity, so its
        // tallies die here and nothing else expires them.
        self.guard.forget_connection(session_id);

        self.unsubscribe_all(state).await;
        tracing::info!("connection closed");
        ended
    }

    /// Handle one transport read, answering whether the session goes on.
    async fn handle_incoming<T: Transport>(
        &self,
        transport: &mut T,
        incoming: Result<Option<IncomingFrame>, T::Error>,
        state: &mut SessionState<Id, Key>,
    ) -> Result<bool, SessionError> {
        match incoming.map_err(transport_err)? {
            None => return Ok(false),
            Some(IncomingFrame::Control(msg)) => self.handle_control(transport, msg, state).await?,
            Some(IncomingFrame::Bulk(BulkMessage::MutationPatch(patch))) => {
                self.handle_mutation(transport, patch, state).await?;
            }
            Some(IncomingFrame::Bulk(_)) => {
                return Err(SessionError::Protocol(
                    "unexpected bulk frame from client".into(),
                ));
            }
        }
        Ok(true)
    }

    /// Deliver one item the dispatch side produced for this session, answering
    /// whether the session goes on.
    ///
    /// It runs on the same task as the transport arm, not one of its own, so
    /// the select cannot interleave a live patch into a subscribe and the
    /// resnapshot notice travels with its replacement as one ordered pair (R7).
    async fn handle_outbound<T: Transport>(
        &self,
        transport: &mut T,
        outbound: Outbound,
        state: &mut SessionState<Id, Key>,
    ) -> Result<bool, SessionError> {
        match outbound {
            Outbound::Live(patch) => {
                let budget = self
                    .guard
                    .read_limits(Tier::of(&state.principal))
                    .page_bytes;
                note_delivered(
                    state,
                    &patch.sub_id,
                    patch.patchset_zstd.len() as u64,
                    budget,
                );
                enqueue_and_flush(
                    transport,
                    &mut state.credits,
                    &mut state.pending,
                    Deliverable::Rows(BulkMessage::LivePatch(patch)),
                )
                .await
                .map_err(transport_err)?;
            }
            Outbound::Aggregate(update) => {
                transport
                    .send_control(ControlMessage::AggregateUpdate(update))
                    .await
                    .map_err(transport_err)?;
            }
            Outbound::Fatal(fatal) => {
                let _ = transport
                    .send_control(ControlMessage::FatalError(fatal))
                    .await;
                return Ok(false);
            }
            Outbound::Drop => return Ok(false),
            // Non-fatal control frame: send immediately, ignore a closed
            // transport (the session may have moved on).
            Outbound::Control(msg) => {
                let _ = transport.send_control(msg).await;
            }
            Outbound::Resnapshot { sub_id, reason } => {
                self.resnapshot_row(transport, state, &sub_id, &reason, None)
                    .await?;
            }
            Outbound::ReservedResnapshot {
                sub_id,
                owner,
                permit,
            } => {
                if state
                    .subs
                    .get(&sub_id)
                    .is_some_and(|row| (row.reg.consumer_id, row.reg.sub_id) == owner)
                {
                    self.resnapshot_row(
                        transport,
                        state,
                        &sub_id,
                        &FullResyncReason::AuthorizationChange,
                        Some(permit),
                    )
                    .await?;
                }
            }
            Outbound::Rebootstrap { sub_id, retired_id } => {
                self.rebootstrap_computed(transport, state, sub_id, retired_id)
                    .await?;
            }
            Outbound::Refuse { sub_id } => {
                self.refuse_subscription(transport, state, &sub_id).await?;
            }
        }
        Ok(true)
    }

    /// Drop every route and registration this connection held.
    async fn unsubscribe_all(&self, state: SessionState<Id, Key>) {
        for row in state.subs.into_values() {
            let (consumer_id, sub_id) = (row.reg.consumer_id, row.reg.sub_id);
            self.remove_route(consumer_id).await;
            self.materializer.lock().await.unregister(sub_id);
        }
        for subscription_id in state
            .computed_subs
            .into_values()
            .map(|computed| computed.id)
        {
            self.remove_computed_route(subscription_id).await;
            self.materializer.lock().await.unregister(subscription_id);
        }
    }

    /// The tables whose read answer depends on the caller's keys, or `None`
    /// when no authorization store reports them.
    fn key_tables(&self) -> Option<&[String]> {
        self.upkeep
            .as_deref()
            .map(crate::openfga::StoreUpkeep::key_tables)
    }

    /// Replace the share keys this session holds with the set a client sent (R95).
    ///
    /// The grants are checked and metered as a handshake's are, and crossing
    /// the refused-grant limit closes the session as it closes a handshake. A
    /// change costs one subscription allowance per subscription it reaches, and
    /// its answer is queued behind their resends.
    async fn replace_share_keys(&self, req: ReplaceShareKeys, state: &mut SessionState<Id, Key>) {
        let ReplaceShareKeys { request_id, keys } = req;
        let resolved = self
            .resolve_grants(state.session_id, &keys, GrantSource::Swap(&request_id))
            .await;
        let reaction = self
            .guard
            .refused_grants(Self::caller(&state.principal), resolved.refusals);
        if reaction == Reaction::Close {
            state.closing = true;
        }
        if let Some(wait) = resolved.wait {
            let _ = state.outbound.send(Outbound::Fatal(FatalError::new(
                FatalErrorReason::RateLimited {
                    retry_after_ms: retry_ms(wait),
                },
            )));
            return;
        }
        let next = state
            .principal
            .with_capabilities(resolved.principal.into_capabilities());
        if rendered_keys(next.capabilities()) != rendered_keys(state.principal.capabilities()) {
            let reached = self.reached_by_keys(state);
            let tier = Tier::of(&state.principal);
            let permit = if reached.0.is_empty() {
                None
            } else {
                let held = state
                    .reader_reservation
                    .upgrade()
                    .or_else(|| state.paging.iter().find_map(|read| read.permit.clone()));
                let permit = if let Some(held) = held {
                    held
                } else {
                    match self.guard.reader_permit(tier).await {
                        Ok(permit) => permit,
                        Err(wait) => {
                            let _ = state.outbound.send(Outbound::Control(
                                ControlMessage::RateLimited(RateLimited {
                                    related_to: Some(request_id),
                                    retry_after_ms: retry_ms(wait),
                                }),
                            ));
                            return;
                        }
                    }
                };
                state.reader_reservation = permit.remember();
                Some(permit)
            };
            let refused = reached
                .0
                .iter()
                .chain(&reached.1)
                .find_map(|_| self.guard.subscription(state.session_id, tier));
            if let Some(wait) = refused {
                let retry_after_ms = retry_ms(wait);
                tracing::warn!(%request_id, retry_after_ms, "key swap refused, rate limit reached");
                let _ = state
                    .outbound
                    .send(Outbound::Control(ControlMessage::RateLimited(
                        RateLimited {
                            related_to: Some(request_id),
                            retry_after_ms,
                        },
                    )));
                return;
            }
            self.swap_keys(state, next, reached, permit).await;
        }
        state.key_expiry = resolved.key_expiry;
        let _ = state
            .outbound
            .send(Outbound::Control(ControlMessage::ShareKeysReplaced(
                ShareKeysReplaced { request_id },
            )));
    }
    /// Drop every held key whose expiry has passed (R95).
    async fn expire_keys(&self, state: &mut SessionState<Id, Key>) {
        let now = self
            .config
            .key_expiry_now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (expired, live): (BTreeMap<String, u64>, BTreeMap<String, u64>) =
            core::mem::take(&mut state.key_expiry)
                .into_iter()
                .partition(|(_, at)| *at <= now);
        state.key_expiry = live;
        if expired.is_empty() {
            return;
        }
        tracing::info!(keys = expired.len(), "held share keys expired");
        let next = state.principal.with_capabilities(
            state
                .principal
                .capabilities()
                .iter()
                .filter(|held| !expired.contains_key(&held.key().to_string()))
                .cloned(),
        );
        let reached = self.reached_by_keys(state);
        self.swap_keys(state, next, reached, None).await;
    }

    /// The labels of the row and the computed subscriptions a change of the
    /// caller's share keys reaches.
    fn reached_by_keys(&self, state: &SessionState<Id, Key>) -> (Vec<String>, Vec<String>) {
        let key_tables = self.key_tables();
        let rows = state
            .subs
            .iter()
            .filter(|(_, row)| key_change_reaches(&row.reg, key_tables))
            .map(|(label, _)| label.clone())
            .collect();
        let computed = state
            .computed_subs
            .iter()
            .filter(|(_, computed)| computed.rebinds)
            .map(|(label, _)| label.clone())
            .collect();
        (rows, computed)
    }

    /// Make `next` the session's caller, queueing the resend of every
    /// subscription in `reached` behind everything already queued (R95).
    ///
    /// The dispatch gate is held throughout, so every patch filtered under the
    /// old keys is queued before the first resend and none after it.
    async fn swap_keys(
        &self,
        state: &mut SessionState<Id, Key>,
        next: Principal<Id, Key>,
        (rows, computed): (Vec<String>, Vec<String>),
        reader_permit: Option<ReaderPermit>,
    ) {
        let _gate = self.dispatch_gate.lock().await;
        state.principal = Arc::new(next);
        state.cursor_subjects = None;
        {
            let mut routes = self.routes.lock().await;
            for row in state.subs.values() {
                if let Some(route) = routes.get_mut(&row.reg.consumer_id) {
                    route.principal = Arc::clone(&state.principal);
                }
            }
        }
        for label in rows {
            let instruction = if self.register_again(state, &label).await {
                if let Some(permit) = &reader_permit {
                    let Some(row) = state.subs.get(&label) else {
                        continue;
                    };
                    Outbound::ReservedResnapshot {
                        owner: (row.reg.consumer_id, row.reg.sub_id),
                        sub_id: label,
                        permit: permit.clone(),
                    }
                } else {
                    Outbound::Resnapshot {
                        sub_id: label,
                        reason: FullResyncReason::AuthorizationChange,
                    }
                }
            } else {
                Outbound::Refuse { sub_id: label }
            };
            let _ = state.outbound.send(instruction);
        }
        for label in computed {
            if let Some(id) = state.computed_subs.get(&label).map(|sub| sub.id) {
                self.remove_computed_route(id).await;
                self.materializer.lock().await.unregister(id);
                let _ = state.outbound.send(Outbound::Rebootstrap {
                    sub_id: label,
                    retired_id: id,
                });
            }
        }
    }

    /// Register one row subscription again under the session's current caller
    /// when its seed holds the subject set, answering whether it can still be
    /// served.
    async fn register_again(&self, state: &mut SessionState<Id, Key>, label: &str) -> bool {
        let Some(row) = state.subs.get(label) else {
            return false;
        };
        if !row.reg.reads_subjects {
            return true;
        }
        let (old_consumer, old_sub) = (row.reg.consumer_id, row.reg.sub_id);
        let consumer_id = self.next_consumer_id();
        let registered = self
            .register_subscription(consumer_id, &row.sub, state)
            .await;
        self.remove_route(old_consumer).await;
        self.materializer.lock().await.unregister(old_sub);
        match registered.map(|registered| registered.into_row(consumer_id)) {
            Ok(Ok(mut reg)) => {
                if let Some(row) = state.subs.get_mut(label) {
                    // The query is unchanged, so its terms watch the same tables.
                    reg.member_tables = core::mem::take(&mut row.reg.member_tables);
                    reg.reads_subjects = true;
                    row.reg = reg;
                }
                true
            }
            Ok(Err(capture)) => {
                self.materializer
                    .lock()
                    .await
                    .unregister(capture.subscription_id);
                false
            }
            Err(err) => {
                tracing::warn!(sub_id = %label, error = %err, "a subscription could not be registered under the new share keys");
                false
            }
        }
    }

    /// Register a computed subscription again under the session's current
    /// caller and replace the answer the client holds (R95).
    async fn rebootstrap_computed<T: Transport>(
        &self,
        transport: &mut T,
        state: &mut SessionState<Id, Key>,
        sub_id: String,
        retired_id: SubscriptionId,
    ) -> Result<(), SessionError> {
        let std::collections::hash_map::Entry::Occupied(owner) = state.computed_subs.entry(sub_id)
        else {
            return Ok(());
        };
        if owner.get().id != retired_id {
            return Ok(());
        }
        let sub = owner.remove().sub;
        let consumer_id = self.next_consumer_id();
        let refused = match self.register_subscription(consumer_id, &sub, state).await {
            Ok(registered) => {
                let reads_subjects = registered.reads_subjects;
                match registered.into_row(consumer_id) {
                    Err(capture) => {
                        return self
                            .subscribe_computed(
                                transport,
                                sub,
                                state,
                                capture,
                                reads_subjects,
                                Some(FullResyncReason::AuthorizationChange),
                            )
                            .await;
                    }
                    Ok(reg) => {
                        self.materializer.lock().await.unregister(reg.sub_id);
                        "it registered as rows".to_owned()
                    }
                }
            }
            Err(err) => err.to_string(),
        };
        tracing::warn!(sub_id = %sub.sub_id, error = %refused, "an aggregate could not be registered under the new share keys");
        transport
            .send_control(ControlMessage::NonFatalError(NonFatalError {
                related_to: Some(sub.sub_id),
                detail: SUBSCRIPTION_REFUSED.to_owned(),
            }))
            .await
            .map_err(transport_err)
    }

    /// Answer one content ticket request: check visibility, call the signer,
    /// charge the write budget after a successful mint, and send the grant.
    ///
    /// Visibility runs first on the reader pool, behind the same reader-share
    /// permit that subscription and mutation reads hold (R39), so an anonymous
    /// caller cannot starve identified callers. Invisibility and a budget
    /// refusal carry the same byte-identical detail so a caller cannot learn
    /// that a file it cannot see exists. A signer fault carries a distinct
    /// detail because it discloses nothing about data and a retry is
    /// meaningful. The budget is charged after a successful mint, so a signer
    /// failure never consumes the caller's upload window.
    async fn handle_content_ticket<T: Transport>(
        &self,
        transport: &mut T,
        req: ContentTicketRequest,
        state: &SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        let request_id = req.request_id;
        let caller = crate::capability::rendered_caller(&state.principal);
        let budget_key = crate::capability::meter_key(&state.principal, state.session_id);

        // Reader permit: visibility checks out a reader-pool connection, so
        // the same gate that protects subscriptions and mutations applies here.
        let Some(_reader_permit) = self
            .ticket_reader_permit(transport, &request_id, state)
            .await?
        else {
            return Ok(());
        };

        // Visibility check: reader pool only, so RLS fires inside the
        // SECURITY INVOKER function body.
        let visible = self
            .target
            .file_visible_to_caller(req.file_id, &state.principal)
            .await;
        let visible = match visible {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(request_id, ?err, "content ticket visibility check failed");
                return transport
                    .send_control(ControlMessage::NonFatalError(NonFatalError {
                        related_to: Some(request_id),
                        detail: CONTENT_TICKET_SIGNER_ERROR.to_owned(),
                    }))
                    .await
                    .map_err(transport_err);
            }
        };
        if !visible {
            return transport
                .send_control(ControlMessage::NonFatalError(NonFatalError {
                    related_to: Some(request_id),
                    detail: CONTENT_TICKET_REFUSED.to_owned(),
                }))
                .await
                .map_err(transport_err);
        }

        // Mint before charging so a signer failure costs the caller nothing.
        let url = match self.signer.mint(&caller, req.file_id, req.verb).await {
            Ok(url) => url,
            Err(err) => {
                tracing::warn!(request_id, %err, "content ticket signing failed");
                return transport
                    .send_control(ControlMessage::NonFatalError(NonFatalError {
                        related_to: Some(request_id),
                        detail: CONTENT_TICKET_SIGNER_ERROR.to_owned(),
                    }))
                    .await
                    .map_err(transport_err);
            }
        };

        // Charge after a successful mint: reads cost no upload bandwidth, and
        // a write that was never authorized costs nothing.
        if let ContentVerb::Write { declared_len } = req.verb
            && !self
                .guard
                .bytes()
                .allow_content_bytes(&budget_key, declared_len)
        {
            return transport
                .send_control(ControlMessage::NonFatalError(NonFatalError {
                    related_to: Some(request_id),
                    detail: CONTENT_TICKET_REFUSED.to_owned(),
                }))
                .await
                .map_err(transport_err);
        }

        transport
            .send_control(ControlMessage::ContentTicketGrant(ContentTicketGrant {
                request_id,
                url,
            }))
            .await
            .map_err(transport_err)
    }

    /// Answer a device list request with the caller's devices.
    async fn handle_devices_request<T: Transport>(
        &self,
        transport: &mut T,
        req: DevicesRequest,
        state: &SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        let request_id = req.request_id;
        let answer = match self.enrolling(state) {
            Ok((enrolment, user)) => enrolment.devices(&user).await.map_err(|err| {
                tracing::warn!(error = %err, "the enrolment table refused a device list");
                EnrolRefusal::IssuerUnavailable
            }),
            Err(refusal) => Err(refusal),
        };
        let answer = match answer {
            Ok(devices) => ControlMessage::DevicesList(DevicesList {
                request_id,
                devices,
            }),
            Err(reason) => ControlMessage::EnrolRefused(EnrolRefused { request_id, reason }),
        };
        transport.send_control(answer).await.map_err(transport_err)
    }

    /// Revoke one of the caller's devices, answering before its connection closes.
    async fn handle_revoke_request<T: Transport>(
        &self,
        transport: &mut T,
        req: RevokeDeviceRequest,
        state: &SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        let request_id = req.request_id;
        let key = KeyId::from_bytes(req.key_id);
        let revoked = match self.enrolling(state) {
            Ok((enrolment, user)) => enrolment
                .revoke(Some(&user), key)
                .await
                .map(|revoked| (enrolment, revoked))
                .map_err(|err| match err {
                    RevokeError::NotFound => EnrolRefusal::InvalidRequest,
                    RevokeError::NotInstalled => EnrolRefusal::IssuerUnavailable,
                    RevokeError::Unavailable(source) => {
                        tracing::warn!(error = %source, "a device could not be revoked");
                        EnrolRefusal::IssuerUnavailable
                    }
                }),
            Err(refusal) => Err(refusal),
        };
        match revoked {
            Ok((enrolment, (_, session, lists))) => {
                transport
                    .send_control(ControlMessage::DeviceRevokedAck(DeviceRevokedAck {
                        request_id,
                    }))
                    .await
                    .map_err(transport_err)?;
                self.after_revocation(&enrolment, session, lists).await;
                Ok(())
            }
            Err(reason) => transport
                .send_control(ControlMessage::EnrolRefused(EnrolRefused {
                    request_id,
                    reason,
                }))
                .await
                .map_err(transport_err),
        }
    }

    /// Hand an identified session the current revocation lists after its
    /// handshake. A list that cannot be built is logged, and the session
    /// runs without it until the next change.
    async fn send_revocation_lists<T: Transport>(
        &self,
        transport: &mut T,
        state: &SessionState<Id, Key>,
    ) {
        let Ok((enrolment, _)) = self.enrolling(state) else {
            return;
        };
        match enrolment.lists().await {
            Ok(lists) => {
                if let Err(err) = transport
                    .send_control(ControlMessage::RevocationUpdate(RevocationUpdate { lists }))
                    .await
                {
                    tracing::debug!(error = %err, "the revocation lists were not sent");
                }
            }
            Err(err) => tracing::warn!(error = %err, "the revocation lists could not be built"),
        }
    }

    /// Close the revoked device's connection, push the new lists to every
    /// identified connection, and revoke the auth-store session.
    async fn after_revocation(
        &self,
        enrolment: &crate::device_cert::DeviceEnrolment<Id>,
        session: SessionId,
        lists: Vec<SignedList>,
    ) {
        self.close_session(session, FatalErrorReason::DeviceRevoked)
            .await;
        let update = ControlMessage::RevocationUpdate(RevocationUpdate { lists });
        for live in self.sessions.lock().await.values() {
            if live.user.is_some() {
                let _ = live.tx.send(Outbound::Control(update.clone()));
            }
        }
        enrolment.revoke_session(session).await;
    }

    /// Revoke the device key `key` whoever it belongs to, as the deployment's
    /// operator, publishing the list and closing its connection and revoking
    /// its session, repeating the close and revocation when the key is
    /// already revoked. Answers whether the revocation is new.
    ///
    /// # Errors
    ///
    /// [`RevokeError::NotFound`] for a key never enrolled,
    /// [`RevokeError::NotInstalled`] when no enrolment is installed, and
    /// [`RevokeError::Unavailable`] when the table or the issuer fails.
    pub async fn revoke_device(&self, key: KeyId) -> Result<bool, RevokeError> {
        let enrolment = self
            .device_enrolment
            .get()
            .ok_or(RevokeError::NotInstalled)?;
        let (fresh, session, lists) = enrolment.revoke(None, key).await?;
        self.after_revocation(enrolment, session, lists).await;
        Ok(fresh)
    }

    /// The installed enrolment and the account enrolling, or why this session cannot enrol.
    fn enrolling(
        &self,
        state: &SessionState<Id, Key>,
    ) -> Result<(Arc<crate::device_cert::DeviceEnrolment<Id>>, Id), EnrolRefusal> {
        let user = state
            .principal
            .identity()
            .ok_or(EnrolRefusal::Unidentified)?
            .user_id
            .clone();
        let enrolment = self
            .device_enrolment
            .get()
            .ok_or(EnrolRefusal::IssuerUnavailable)?;
        Ok((Arc::clone(enrolment), user))
    }

    /// The answer to an enrolment nonce request: the nonce or the refusal.
    fn enrol_challenge(
        &self,
        request_id: String,
        state: &mut SessionState<Id, Key>,
    ) -> ControlMessage {
        let answer = self
            .enrolling(state)
            .and_then(|(enrolment, _)| enrolment.challenge(&mut state.enrol_challenge));
        match answer {
            Ok((nonce, window)) => ControlMessage::EnrolChallenge(EnrolChallenge {
                request_id,
                nonce,
                expires_in_ms: u64::try_from(window.as_millis()).unwrap_or(u64::MAX),
            }),
            Err(reason) => ControlMessage::EnrolRefused(EnrolRefused { request_id, reason }),
        }
    }

    async fn handle_control<T: Transport>(
        &self,
        transport: &mut T,
        msg: ControlMessage,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        match msg {
            ControlMessage::Subscribe(sub) => self.handle_subscribe(transport, sub, state).await,
            ControlMessage::Unsubscribe(unsub) => {
                for (consumer_id, sub_id) in take_row_subscription(state, &unsub.sub_id) {
                    self.remove_route(consumer_id).await;
                    self.materializer.lock().await.unregister(sub_id);
                }
                if let Some(ComputedSub {
                    id: subscription_id,
                    ..
                }) = state.computed_subs.remove(&unsub.sub_id)
                {
                    self.remove_computed_route(subscription_id).await;
                    self.materializer.lock().await.unregister(subscription_id);
                }
                Ok(())
            }
            ControlMessage::Ping(ping) => transport
                .send_control(ControlMessage::Pong(Pong { nonce: ping.nonce }))
                .await
                .map_err(transport_err),
            ControlMessage::AckCredits(ack) => {
                state.credits = state.credits.saturating_add(ack.credits);
                flush(transport, &mut state.credits, &mut state.pending)
                    .await
                    .map_err(transport_err)?;
                // The acknowledgement is what paces a read still arriving in
                // pages: one page per acknowledgement, so the server holds one
                // page at a time and a client that stops reading stops the
                // producer (R58 decision 9).
                self.pump_page(transport, state).await
            }
            ControlMessage::Handshake(_) => {
                let _ = transport
                    .send_control(ControlMessage::FatalError(FatalError::new(
                        FatalErrorReason::ProtocolViolation {
                            detail: "duplicate handshake".into(),
                        },
                    )))
                    .await;
                Err(SessionError::Protocol("duplicate handshake".into()))
            }
            // A registration belongs to the gate that runs before identity
            // (R91). After the handshake it is a protocol violation.
            ControlMessage::RegisterBot(_) => {
                let _ = transport
                    .send_control(ControlMessage::FatalError(FatalError::new(
                        FatalErrorReason::ProtocolViolation {
                            detail: "registration after identity".into(),
                        },
                    )))
                    .await;
                Err(SessionError::Protocol("registration after identity".into()))
            }
            // Announce a mutation upload. The paired patch follows on the bulk
            // channel and completes the write path.
            ControlMessage::MutationHeader(header) => {
                state.pending_header = Some(header);
                Ok(())
            }
            ControlMessage::ContentTicketRequest(req) => {
                self.handle_content_ticket(transport, req, state).await
            }
            ControlMessage::EnrolChallengeRequest(req) => transport
                .send_control(self.enrol_challenge(req.request_id, state))
                .await
                .map_err(transport_err),
            ControlMessage::EnrolRequest(req) => {
                let request_id = req.request_id.clone();
                let answer = match self.enrolling(state) {
                    Ok((enrolment, user)) => {
                        enrolment
                            .enrol(&user, state.session_id, &mut state.enrol_challenge, req)
                            .await
                    }
                    Err(refusal) => {
                        state.enrol_challenge = None;
                        Err(refusal)
                    }
                };
                let answer = answer.map_or_else(
                    |reason| ControlMessage::EnrolRefused(EnrolRefused { request_id, reason }),
                    ControlMessage::EnrolGrant,
                );
                transport.send_control(answer).await.map_err(transport_err)
            }
            ControlMessage::DevicesRequest(req) => {
                self.handle_devices_request(transport, req, state).await
            }
            ControlMessage::RevokeDeviceRequest(req) => {
                self.handle_revoke_request(transport, req, state).await
            }
            ControlMessage::ReplaceShareKeys(req) => {
                self.replace_share_keys(req, state).await;
                Ok(())
            }
            ControlMessage::BindDevice(bind) => {
                tracing::debug!(request_id = %bind.request_id, "device bind requested");
                self.handle_bind_device(transport, bind, state).await
            }
            ControlMessage::RetireWriter(retire) => {
                self.handle_retire_writer(transport, retire, state).await
            }
            // Server-origin frames received from a client are ignored.
            _ => Ok(()),
        }
    }

    /// Verify a device key's signature over this connection's bind nonce and
    /// switch the connection to write as its writer, answering the outcome,
    /// or close the connection with `DeviceRevoked` when the key's enrolment
    /// is revoked.
    async fn handle_bind_device<T: Transport>(
        &self,
        transport: &mut T,
        bind: BindDevice,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        let outcome = match state.principal.identity() {
            Some(identity) => match self
                .bind_device(identity.user_id.clone(), &bind, state)
                .await?
            {
                BindVerdict::Writer(outcome) => outcome,
                // The device must learn of its revocation.
                BindVerdict::Revoked => {
                    tracing::debug!(request_id = %bind.request_id, "device bind refused as revoked, closing the connection");
                    let _ = transport
                        .send_control(ControlMessage::FatalError(FatalError::new(
                            FatalErrorReason::DeviceRevoked,
                        )))
                        .await;
                    return Err(SessionError::Protocol("a bind of a revoked key".into()));
                }
            },
            // An anonymous session enrols no device key.
            None => WriterOutcome::NotEnrolled,
        };
        tracing::debug!(request_id = %bind.request_id, ?outcome, "device bind answered");
        transport
            .send_control(ControlMessage::WriterAnswer(WriterAnswer {
                request_id: bind.request_id,
                outcome,
            }))
            .await
            .map_err(transport_err)
    }

    /// The bind's verification and its verdict. `BindVerdict::Revoked`
    /// stands when the key is the caller's own revoked enrolment.
    async fn bind_device(
        &self,
        user_id: Id,
        bind: &BindDevice,
        state: &mut SessionState<Id, Key>,
    ) -> Result<BindVerdict, SessionError> {
        let enrolment = self
            .device_enrolment
            .get()
            .ok_or_else(|| SessionError::Protocol("no device enrolment installed".into()))?;
        let Some(record) = enrolment
            .key_record(Some(&user_id), KeyId::from_bytes(bind.key_id))
            .await
            .map_err(|_| SessionError::Protocol("the enrolment store did not answer".into()))?
        else {
            return Ok(BindVerdict::Writer(WriterOutcome::NotEnrolled));
        };
        if record.revoked {
            return Ok(BindVerdict::Revoked);
        }
        // The nonce is the connection's, so a signature from another
        // connection's bind cannot stand here.
        let message = writer_bind_message(&state.bind_nonce);
        let Some(point) = spki_point(&record.public_key) else {
            return Ok(BindVerdict::Writer(WriterOutcome::NotEnrolled));
        };
        if UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &point)
            .verify(&message, &bind.signature)
            .is_err()
        {
            return Ok(BindVerdict::Writer(WriterOutcome::NotEnrolled));
        }
        let key: Vec<u8> = bind.key_id.to_vec();
        let row = match self
            .target
            .writer_by_key(&key)
            .await
            .map_err(|err| SessionError::WriteTarget(err.detail()))?
        {
            Some(row) if row.retired_at.is_some() => {
                return Ok(BindVerdict::Writer(WriterOutcome::Retired));
            }
            Some(row) => row,
            None => {
                self.target
                    .insert_device_writer(Some(user_id), &key)
                    .await
                    .map_err(|err| SessionError::WriteTarget(err.detail()))?;
                self.target
                    .writer_by_key(&key)
                    .await
                    .map_err(|err| SessionError::WriteTarget(err.detail()))?
                    .ok_or_else(|| {
                        SessionError::Protocol("the device writer row did not stand".into())
                    })?
            }
        };
        if row.retired_at.is_some() {
            return Ok(BindVerdict::Writer(WriterOutcome::Retired));
        }
        // A bind after a number switches the connection to the device writer.
        state.writer_row = Some(row.clone());
        state.indeterminate = None;
        self.writer_sessions
            .lock()
            .await
            .entry(row.writer)
            .or_default()
            .insert(state.session_id);
        Ok(BindVerdict::Writer(WriterOutcome::Bound {
            frontier: u64::try_from(row.frontier).unwrap_or(0),
        }))
    }

    /// Retire the writer the request names, closing the sessions that write
    /// as it, and answer the outcome.
    async fn handle_retire_writer<T: Transport>(
        &self,
        transport: &mut T,
        retire: RetireWriter,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        let outcome = match state.principal.identity() {
            Some(identity) => {
                self.retire_writer(
                    Some(identity.user_id.clone()),
                    state.session_id,
                    &retire.writer,
                )
                .await?
            }
            // An anonymous run retires only the number writer its own handle
            // holds, looked up by that handle.
            None => {
                self.retire_writer(None, state.session_id, &retire.writer)
                    .await?
            }
        };
        transport
            .send_control(ControlMessage::WriterAnswer(WriterAnswer {
                request_id: retire.request_id,
                outcome,
            }))
            .await
            .map_err(transport_err)
    }

    /// Mark the named writer retired and close the sessions bound to it.
    async fn retire_writer(
        &self,
        user_id: Option<Id>,
        session: SessionId,
        writer: &WriterRef,
    ) -> Result<WriterOutcome, SessionError> {
        let bind_session = user_id.is_none().then(|| *session.as_uuid());
        let row = match writer {
            WriterRef::Number(number) => {
                let writer = i64::try_from(*number).unwrap_or(i64::MAX);
                match self
                    .target
                    .writer_by_number(writer, user_id.as_ref(), bind_session.as_ref())
                    .await
                    .map_err(|err| SessionError::WriteTarget(err.detail()))?
                {
                    Some(row) => row,
                    None => return Ok(WriterOutcome::Unknown),
                }
            }
            WriterRef::Device(key_id) => {
                let Some(user_id) = user_id else {
                    // An anonymous caller holds no device writer to retire.
                    return Ok(WriterOutcome::Unknown);
                };
                let key: Vec<u8> = key_id.to_vec();
                match self
                    .target
                    .writer_by_key(&key)
                    .await
                    .map_err(|err| SessionError::WriteTarget(err.detail()))?
                {
                    // Only this account's writer retires, never confirming
                    // another account's key exists.
                    Some(row) if same_account(row.user_id.as_ref(), Some(&user_id)) => row,
                    Some(_) => return Ok(WriterOutcome::Unknown),
                    // A device key enrolled to this account that never bound
                    // retires with its row created (R75).
                    None => match self.retire_unbound_device_key(user_id, key_id).await? {
                        Some(row) => row,
                        None => return Ok(WriterOutcome::Unknown),
                    },
                }
            }
        };
        let retired = self
            .target
            .mark_writer_retired(row.writer, row.device_key.as_deref())
            .await
            .map_err(|err| SessionError::WriteTarget(err.detail()))?;
        if !retired {
            return Ok(WriterOutcome::Retired);
        }
        // The writer's live sessions learn of the retirement as a fatal.
        let sessions = self
            .writer_sessions
            .lock()
            .await
            .remove(&row.writer)
            .unwrap_or_default();
        for session in sessions {
            let _ = self
                .close_session(session, FatalErrorReason::WriterRetired)
                .await;
        }
        Ok(WriterOutcome::Retired)
    }

    /// A device key enrolled to this account that never bound, retired with
    /// its row created. `None` when the key is no live enrolment of the
    /// account, so the retirement is refused as unknown.
    ///
    /// # Errors
    ///
    /// [`SessionError::WriteTarget`] when the writer tables fail,
    /// [`SessionError::Protocol`] when the enrolment store does not answer.
    async fn retire_unbound_device_key(
        &self,
        user_id: Id,
        key: &[u8; 32],
    ) -> Result<Option<WriterRow<Id>>, SessionError> {
        let Some(enrolment) = self.device_enrolment.get() else {
            return Ok(None);
        };
        let Some(record) = enrolment
            .key_record(Some(&user_id), KeyId::from_bytes(*key))
            .await
            .map_err(|_| SessionError::Protocol("the enrolment store did not answer".into()))?
        else {
            return Ok(None);
        };
        if record.revoked {
            return Ok(None);
        }
        let bytes: Vec<u8> = key.to_vec();
        self.target
            .insert_retired_device_writer(Some(user_id), &bytes)
            .await
            .map_err(|err| SessionError::WriteTarget(err.detail()))?;
        self.target
            .writer_by_key(&bytes)
            .await
            .map_err(|err| SessionError::WriteTarget(err.detail()))
    }

    /// Settle a range the courier carried from the author's device (R75).
    ///
    /// The author's signature verifies against the author's live enrolment
    /// over the range's chain and every entry's provenance original, the
    /// entries continue the author's settled chain from the writer's
    /// frontier, and each entry settles at the frontier plus one, in order,
    /// under the author's identity, so an entry another path settled is
    /// answered from the record and never applied twice. A carried entry
    /// settles its provenance original the way the direct upload does.
    ///
    /// # Errors
    ///
    /// [`SessionError::Protocol`] when no enrolment is installed, the store
    /// does not answer, or the writer row does not stand.
    /// [`SessionError::WriteTarget`] when the writer tables or the apply
    /// database fail.
    ///
    /// # Panics
    ///
    /// When one identity cannot settle one run, a guarantee `accept` upholds.
    #[expect(
        clippy::too_many_lines,
        reason = "the author's signature verifies the whole range and each entry settles in order under its identity, so the range settles as one unit"
    )]
    pub async fn courier_deliver(
        &self,
        author: KeyId,
        entries: &[CourierEntry],
        signature: &[u8],
    ) -> Result<CourierDelivery, SessionError> {
        let enrolment = self
            .device_enrolment
            .get()
            .ok_or_else(|| SessionError::Protocol("no device enrolment installed".into()))?;
        let Some(record) = enrolment
            .key_record(None, author)
            .await
            .map_err(|_| SessionError::Protocol("the enrolment store did not answer".into()))?
        else {
            return Ok(CourierDelivery::Refused(CourierRefusal::NotEnrolled));
        };
        if record.revoked || !record.certificate_live {
            return Ok(CourierDelivery::Refused(CourierRefusal::NotEnrolled));
        }
        let key: Vec<u8> = author.as_bytes().to_vec();
        let writer_row = match self
            .target
            .writer_by_key(&key)
            .await
            .map_err(|err| SessionError::WriteTarget(err.detail()))?
        {
            Some(row) if row.retired_at.is_some() => {
                return Ok(CourierDelivery::Refused(CourierRefusal::WriterRetired));
            }
            Some(row) => row,
            // A live enrolment that never bound takes its row at frontier 0.
            None => {
                self.target
                    .insert_device_writer(Some(record.user.clone()), &key)
                    .await
                    .map_err(|err| SessionError::WriteTarget(err.detail()))?;
                self.target
                    .writer_by_key(&key)
                    .await
                    .map_err(|err| SessionError::WriteTarget(err.detail()))?
                    .ok_or_else(|| {
                        SessionError::Protocol("the device writer row did not stand".into())
                    })?
            }
        };
        // The entries continue the author's settled chain.
        let frontier = u64::try_from(writer_row.frontier).unwrap_or(0);
        let head = writer_row.head.as_deref().map_or(GENESIS, |head| {
            <[u8; 32]>::try_from(head).unwrap_or(GENESIS)
        });
        let mut previous = head;
        let mut hashes = Vec::with_capacity(entries.len());
        let mut expected = frontier.saturating_add(1);
        for entry in entries {
            if entry.seq != expected {
                return Ok(CourierDelivery::Refused(CourierRefusal::SequenceGap {
                    expected,
                    got: entry.seq,
                }));
            }
            let hash = chain::entry_hash(&previous, entry.seq, &entry.changeset);
            previous = hash;
            expected = entry.seq.saturating_add(1);
            hashes.push(hash);
        }
        // The author vouches the range's chain up to its last entry, or its
        // own head when the range carries none, and every entry's provenance.
        let (vouch_seq, vouch_head) = match entries.last() {
            Some(last) => (last.seq, previous),
            None => (frontier, head),
        };
        let message = chain::courier_range_message(
            author.as_bytes(),
            vouch_seq,
            &vouch_head,
            entries.iter().map(|entry| (entry.seq, entry.provenance)),
        );
        let Some(point) = spki_point(&record.public_key) else {
            return Ok(CourierDelivery::Refused(CourierRefusal::NotEnrolled));
        };
        if UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &point)
            .verify(&message, signature)
            .is_err()
        {
            return Ok(CourierDelivery::Refused(CourierRefusal::NotEnrolled));
        }
        // The author's identity every entry applies under.
        let session = SessionId::from_uuid(Uuid::new_v4());
        let session_uuid = *session.as_uuid();
        let mut author_principal = Principal::unidentified(session);
        author_principal
            .accept(Subject::Identity(VerifiedSession {
                context: AuthContext::new(record.user),
                session_id: session,
                bot_list: None,
            }))
            .expect("one identity settles one run");
        let author: Arc<Principal<Id, Key>> = Arc::new(author_principal);
        let mut outcomes: Vec<SettledOutcome> = Vec::with_capacity(entries.len());
        let mut previous = head;
        for (entry, hash) in entries.iter().zip(hashes.iter()) {
            let outcome = self
                .courier_entry(
                    &author,
                    session_uuid,
                    writer_row.writer,
                    entry,
                    *hash,
                    previous,
                )
                .await?;
            previous = *hash;
            // A refusal stops the range.
            let stops = matches!(outcome, SettledOutcome::Rejected(_));
            outcomes.push(outcome);
            if stops {
                break;
            }
        }
        Ok(CourierDelivery::Entries(outcomes))
    }

    /// Settle one courier entry at the frontier as [`SettlePath::Courier`].
    ///
    /// # Errors
    ///
    /// [`SessionError::WriteTarget`] when the apply database or the writer
    /// tables fail.
    /// [`SessionError::Protocol`] when the changeset will not compress, or
    /// the provenance sequence is past the original's frontier.
    async fn courier_entry(
        &self,
        author: &Arc<Principal<Id, Key>>,
        session_id: uuid::Uuid,
        writer: i64,
        entry: &CourierEntry,
        entry_hash: [u8; 32],
        previous_hash: [u8; 32],
    ) -> Result<SettledOutcome, SessionError> {
        let changeset = entry.changeset.as_slice();
        let mut settle = SettleSpec {
            writer,
            seq: entry.seq,
            entry_hash,
            previous_hash,
            path: SettlePath::Courier,
            original: None,
        };
        if let Some(outcome) = self
            .courier_original(author, session_id, entry, &mut settle)
            .await?
        {
            return Ok(outcome);
        }
        let payload = compress(changeset).map_err(|err| {
            SessionError::Protocol(format!("the changeset will not compress, {err}"))
        })?;
        let plan = match self.materializer.lock().await.plan_write(&payload) {
            Ok(plan) => plan,
            Err(err) => {
                return self
                    .courier_settle_refusal(author, &settle, reject_reason(&err))
                    .await;
            }
        };
        match self.every_op_authorized(&plan, author).await {
            WriteVerdict::Allowed => {}
            WriteVerdict::Denied => {
                let _ = self.guard.rejected_write(Self::caller(author));
                return self
                    .courier_settle_refusal(author, &settle, MutationRejectReason::Unauthorized)
                    .await;
            }
            // Settles nothing, so the range re-offers from this entry.
            WriteVerdict::Undetermined => {
                return Ok(SettledOutcome::Rejected(
                    MutationRejectReason::Indeterminate,
                ));
            }
        }
        let outcome = self
            .commit_with_retry(author, &plan, &payload, &settle)
            .await;
        match outcome {
            Ok(WriteOutcome::Applied) => Ok(SettledOutcome::Applied),
            Ok(WriteOutcome::Conflict {
                table,
                version_column,
                pk_columns,
                pk_values,
                ..
            }) => Ok(SettledOutcome::Conflict {
                table,
                version_column,
                pk_columns,
                pk_values,
            }),
            Ok(WriteOutcome::Settled(settlement)) => {
                self.recorded_outcome(author, &settle, &settlement)
            }
            Err(WriteError::Unauthorized) => {
                self.courier_settle_refusal(author, &settle, MutationRejectReason::Unauthorized)
                    .await
            }
            Err(WriteError::Materializer(err)) => {
                self.courier_settle_refusal(author, &settle, reject_reason(&err))
                    .await
            }
            Err(WriteError::Backend(detail)) => {
                self.courier_settle_refusal(author, &settle, MutationRejectReason::Other { detail })
                    .await
            }
            // Settles nothing, so the range re-offers from this entry.
            Err(WriteError::Frontier | WriteError::Transient(_)) => Ok(SettledOutcome::Rejected(
                MutationRejectReason::Indeterminate,
            )),
        }
    }

    /// Settle a courier copy of a recorded original or bind its next sequence.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer tables fail or provenance skips the original frontier.
    async fn courier_original(
        &self,
        author: &Arc<Principal<Id, Key>>,
        session_id: uuid::Uuid,
        entry: &CourierEntry,
        settle: &mut SettleSpec,
    ) -> Result<Option<SettledOutcome>, SessionError> {
        let Some(provenance) = entry.provenance else {
            return Ok(None);
        };
        match self
            .provenance_original(&provenance, &entry.changeset, author, session_id)
            .await?
        {
            Some((writer, frontier, _, _)) if provenance.seq <= frontier => {
                let stored = self
                    .target
                    .settled_row(writer, provenance.seq)
                    .await
                    .map_err(|err| SessionError::WriteTarget(err.detail()))?;
                let outcome = match stored {
                    // A pruned record stands applied.
                    None => SettledOutcome::Applied,
                    Some(row) => {
                        self.recorded_outcome(author, settle, &Settlement { row, forked: false })?
                    }
                };
                let settlement = self
                    .target
                    .settle_refusal(settle, &outcome)
                    .await
                    .map_err(|err| SessionError::WriteTarget(err.detail()))?;
                self.recorded_outcome(author, settle, &settlement).map(Some)
            }
            Some((writer, frontier, hash, previous)) if provenance.seq == frontier + 1 => {
                settle.original = Some((writer, provenance.seq, hash, previous));
                Ok(None)
            }
            Some((_, frontier, _, _)) => Err(SessionError::Protocol(format!(
                "a provenance sequence {} past the original frontier {frontier}",
                provenance.seq
            ))),
            None => Ok(None),
        }
    }

    /// Settle a courier refusal under the entry, so a re-delivery answers
    /// from the record.
    ///
    /// # Errors
    ///
    /// [`SessionError::WriteTarget`] when the writer tables fail.
    async fn courier_settle_refusal(
        &self,
        author: &Principal<Id, Key>,
        settle: &SettleSpec,
        reason: MutationRejectReason,
    ) -> Result<SettledOutcome, SessionError> {
        let settlement = self
            .target
            .settle_refusal(settle, &SettledOutcome::Rejected(reason))
            .await
            .map_err(|err| SessionError::WriteTarget(err.detail()))?;
        self.recorded_outcome(author, settle, &settlement)
    }

    /// One sweep pass (R75 decision 5).
    ///
    /// Prunes the settled rows of every device writer whose enrolment is
    /// revoked or has gone absent, and reports how many writers it pruned.
    /// An expired certificate does not prune: the key renews on the same key
    /// and its settled rows keep the replay and fork evidence its still-bound
    /// sessions and its renewal consult. The writer row itself stands, its
    /// frontier and head intact, so a re-enrolled key resumes the chain where
    /// it left it.
    ///
    /// Fails closed on a store error, a writer whose enrolment record could
    /// not be read keeps its rows, and returns zero when no enrolment is
    /// installed.
    ///
    /// # Errors
    ///
    /// [`SessionError::WriteTarget`] when the writer tables fail.
    /// [`SessionError::Protocol`] when the enrolment store does not answer.
    pub async fn sweep_writer_rows(&self) -> Result<usize, SessionError> {
        let Some(enrolment) = self.device_enrolment.get() else {
            return Ok(0);
        };
        let writers = self
            .target
            .device_writers()
            .await
            .map_err(|err| SessionError::WriteTarget(err.detail()))?;
        let mut pruned = 0;
        for (writer, key) in writers {
            // The key is the device writer's id, absent only for a row the
            // table should not hold.
            let Some(key) = key else {
                continue;
            };
            let Ok(bytes) = <[u8; 32]>::try_from(key.as_slice()) else {
                continue;
            };
            let record = enrolment
                .key_record(None, KeyId::from_bytes(bytes))
                .await
                .map_err(|_| SessionError::Protocol("the enrolment store did not answer".into()))?;
            let dead = record.is_none_or(|record| record.revoked);
            if dead {
                self.target
                    .prune_writer(writer)
                    .await
                    .map_err(|err| SessionError::WriteTarget(err.detail()))?;
                pruned += 1;
            }
        }
        Ok(pruned)
    }

    /// Ask the write question about every op in `plan`, stopping at the first
    /// answer that is not an allow.
    ///
    /// The question carries the row versions its verb is judged on, so a
    /// replacement is asked about both rather than about one image standing in
    /// for two. Judging a replacement on the resulting row alone asks whether
    /// the **new** owner is the caller, which grants a caller who holds nothing
    /// and writes itself in.
    pub(crate) async fn every_op_authorized(
        &self,
        plan: &crate::materializer::WritePlan,
        caller: &Arc<Principal<Id, Key>>,
    ) -> WriteVerdict {
        for op in &plan.ops {
            let answer = match &op.write {
                PlannedWrite::Insert { new } => {
                    let new = ValuesRow::new(op.table_id, new);
                    self.auth
                        .may_write(RowWrite::Insert { new: &new }, caller)
                        .await
                }
                PlannedWrite::Update { old, new } => {
                    let old = ValuesRow::new(op.table_id, old);
                    let new = ValuesRow::new(op.table_id, new);
                    self.auth
                        .may_write(
                            RowWrite::Update {
                                old: &old,
                                new: &new,
                            },
                            caller,
                        )
                        .await
                }
                PlannedWrite::Delete { old } => {
                    let old = ValuesRow::new(op.table_id, old);
                    self.auth
                        .may_write(RowWrite::Delete { old: &old }, caller)
                        .await
                }
            };
            match answer {
                Ok(verdict) if verdict.allowed() => {}
                Ok(_) => return WriteVerdict::Denied,
                Err(_) => return WriteVerdict::Undetermined,
            }
        }
        WriteVerdict::Allowed
    }

    /// Pair a `MutationPatch` with its header and settle it on the writer's
    /// applied frontier (R75). A new write at the frontier plus one applies
    /// and settles its sequence, a redelivery at or below it answers from
    /// the settled record, and a sequence past the frontier that nothing
    /// unsettled on this connection explains closes the link.
    #[expect(
        clippy::too_many_lines,
        reason = "one branch per frontier state, the redelivery, the gap, and the oversized refusal"
    )]
    async fn handle_mutation<T: Transport>(
        &self,
        transport: &mut T,
        patch: MutationPatch,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        let client_seq = patch.client_seq;
        let Some(header) = state.pending_header.take() else {
            return Err(SessionError::Protocol(
                "mutation patch arrived without a preceding header".into(),
            ));
        };
        if !self.admit_mutation(transport, &header, &patch).await? {
            return Ok(());
        }
        // A write before a device writer binds arrives first, and no sequence
        // can stand under a writer that does not exist yet.
        if state.writer_row.is_none() {
            let _ = transport
                .send_control(ControlMessage::FatalError(FatalError::new(
                    FatalErrorReason::ProtocolViolation {
                        detail: "a write before the device writer bound".into(),
                    },
                )))
                .await;
            return Err(SessionError::Protocol(
                "a write before the device writer bound".into(),
            ));
        }
        // A brief outage retries through, as a commit does, before the write answers indeterminate.
        match self.refresh_writer_row_with_retry(state, client_seq).await {
            Err(WriteError::Transient(_) | WriteError::Frontier) => {
                state.indeterminate = Some(client_seq);
                return self.reject_indeterminate(transport, client_seq).await;
            }
            Err(err) => return Err(SessionError::WriteTarget(err.detail())),
            Ok(()) => {}
        }
        let Some(writer_row) = &state.writer_row else {
            return Err(SessionError::Protocol(
                "the writer row did not stand".into(),
            ));
        };
        let writer = writer_row.writer;
        let frontier = u64::try_from(writer_row.frontier).unwrap_or(0);
        let bytes = match crate::materializer::decompress(&patch.patchset_zstd) {
            Ok(bytes) => bytes,
            Err(err) => {
                // The envelope cannot be read, so the entry cannot be hashed
                // and nothing may settle under its sequence. The link ends
                // and the client resends the entry it still holds.
                let _ = transport
                    .send_control(ControlMessage::FatalError(FatalError::new(
                        FatalErrorReason::ProtocolViolation {
                            detail: format!("mutation envelope: {err}"),
                        },
                    )))
                    .await;
                return Err(SessionError::Protocol(
                    "a mutation envelope does not decompress".into(),
                ));
            }
        };
        if client_seq <= frontier {
            return self
                .redelivered(transport, writer, client_seq, &bytes, state)
                .await;
        }
        if client_seq > frontier + 1 {
            // A write past the frontier the writer's own unsettled write explains
            // answers it, the client sends new writes while a deferred one stands.
            if state
                .indeterminate
                .is_some_and(|unsettled| client_seq > unsettled)
            {
                return self.reject_indeterminate(transport, client_seq).await;
            }
            // A write past the frontier this connection's own deferred write
            // explains waits behind it, sharing the deadline the deferral named.
            let deadline = state
                .deferred
                .range(frontier + 1..client_seq)
                .map(|(_, retry_after_ms)| *retry_after_ms)
                .min();
            if let Some(retry_after_ms) = deadline {
                state.deferred.insert(client_seq, retry_after_ms);
                return self
                    .defer_mutation(transport, client_seq, Duration::from_millis(retry_after_ms))
                    .await;
            }
            let _ = transport
                .send_control(ControlMessage::FatalError(FatalError::new(
                    FatalErrorReason::SequenceGap {
                        expected: frontier + 1,
                        got: client_seq,
                    },
                )))
                .await;
            // The fatal is the final answer, so the deliberate close ends the
            // session cleanly rather than as a protocol error.
            state.closing = true;
            return Ok(());
        }
        // A patch the window could never hold is refused and settles its
        // sequence, so the write stands refused and the frontier takes it.
        if let Some(limit) =
            self.guard.bytes().mutation_limit().filter(|limit| {
                u64::try_from(patch.patchset_zstd.len()).unwrap_or(u64::MAX) > *limit
            })
        {
            let previous = writer_row.head.as_deref().map_or(GENESIS, |head| {
                <[u8; 32]>::try_from(head).unwrap_or(GENESIS)
            });
            let settle = SettleSpec {
                writer,
                seq: client_seq,
                entry_hash: chain::entry_hash(&previous, client_seq, &bytes),
                previous_hash: previous,
                path: SettlePath::Direct,
                original: None,
            };
            return self
                .settle_and_refuse(
                    transport,
                    &settle,
                    MutationRejectReason::Other {
                        detail: format!(
                            "mutation of {} bytes exceeds the {limit} byte window",
                            patch.patchset_zstd.len()
                        ),
                    },
                    state,
                )
                .await;
        }
        let answered = self
            .new_write(transport, &header, &patch, client_seq, &bytes, state)
            .await;
        // The write already answered, so a failed re-read is logged and the next write reads again.
        match self.refresh_writer_row(state).await {
            Err(err @ (WriteError::Transient(_) | WriteError::Frontier)) => {
                tracing::warn!(
                    seq = client_seq,
                    error = %err.detail(),
                    "the writer row could not be re-read after a write"
                );
            }
            Err(err) => return Err(SessionError::WriteTarget(err.detail())),
            Ok(()) => {}
        }
        answered
    }

    /// Re-read the connection's writer row while the database fails transiently and the write retry budget lasts.
    async fn refresh_writer_row_with_retry(
        &self,
        state: &mut SessionState<Id, Key>,
        seq: u64,
    ) -> Result<(), WriteError> {
        let policy =
            RetryPolicy::new().with_max_total_backoff(Some(self.config.write_retry_budget));
        let mut episode = policy.start();
        loop {
            let outcome = self.refresh_writer_row(state).await;
            let Err(WriteError::Transient(detail)) = &outcome else {
                return outcome;
            };
            let Some(wait) = episode.next_wait() else {
                tracing::warn!(seq, error = %detail, "a write could not read its writer row at the database");
                return outcome;
            };
            tracing::warn!(seq, error = %detail, wait_ms = retry_ms(wait), "a write could not read its writer row, reading it again");
            tokio::time::sleep(wait).await;
        }
    }

    /// Re-read the connection's writer row, so the next write takes its sequence and chain hash from where the frontier stands.
    async fn refresh_writer_row(
        &self,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), WriteError> {
        let Some(row) = state.writer_row.clone() else {
            return Ok(());
        };
        let bind_session = row.user_id.is_none().then(|| *state.session_id.as_uuid());
        let fresh = match row.device_key.as_deref() {
            Some(key) => self.target.writer_by_key(key).await,
            None => {
                self.target
                    .writer_by_number(row.writer, row.user_id.as_ref(), bind_session.as_ref())
                    .await
            }
        }?;
        if let Some(fresh) = fresh {
            state.writer_row = Some(fresh);
        }
        Ok(())
    }

    /// Answer a redelivery at or below the writer's frontier from the settled
    /// record: the stored outcome when the entry stands as it was settled,
    /// a fork when it does not.
    async fn redelivered<T: Transport>(
        &self,
        transport: &mut T,
        writer: i64,
        seq: u64,
        bytes: &[u8],
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        // A pruned record stands settled, so the client retires its copy.
        let Some(row) = self
            .target
            .settled_row(writer, seq)
            .await
            .map_err(|err| SessionError::WriteTarget(err.detail()))?
        else {
            return self.ack(transport, seq).await;
        };
        let previous = <[u8; 32]>::try_from(row.previous_hash.as_slice()).map_err(|_| {
            SessionError::WriteTarget("a retained entry's predecessor hash is malformed".to_owned())
        })?;
        let hash = chain::entry_hash(&previous, seq, bytes);
        let stored = <[u8; 32]>::try_from(row.entry_hash.as_slice()).map_err(|_| {
            SessionError::WriteTarget("a settled entry hash is not 32 bytes".to_owned())
        })?;
        if hash != stored {
            self.guard.record(
                AuthEvent::new(
                    state.session_id,
                    state
                        .principal
                        .identity()
                        .map(|identity| identity.user_id.clone()),
                    AuthOp::WriteForked,
                )
                .about_write(
                    writer,
                    i64::try_from(seq).unwrap_or(i64::MAX),
                    row.path,
                    SettlePath::Direct,
                ),
            );
            return self
                .reject(transport, seq, MutationRejectReason::Forked)
                .await;
        }
        if row.path != SettlePath::Direct {
            // A cross-path delivery stands on both paths' audit.
            self.guard.record(
                AuthEvent::new(
                    state.session_id,
                    state
                        .principal
                        .identity()
                        .map(|identity| identity.user_id.clone()),
                    AuthOp::WriteRedelivered,
                )
                .about_write(
                    writer,
                    i64::try_from(seq).unwrap_or(i64::MAX),
                    row.path,
                    SettlePath::Direct,
                ),
            );
        }
        self.answer_settled(transport, seq, &row, state).await
    }

    /// Send the frame a settled record stored, a conflict reading its row fresh.
    async fn answer_settled<T: Transport>(
        &self,
        transport: &mut T,
        seq: u64,
        row: &SettledRow,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        let outcome = SettledOutcome::from_json(&row.outcome)
            .map_err(|err| SessionError::WriteTarget(err.to_string()))?;
        self.answer_outcome(transport, seq, &outcome, state).await
    }

    /// Send the frame for a stored outcome, an `Unauthorized` refusal counting
    /// its abuse signal the way a fresh denial does.
    async fn answer_outcome<T: Transport>(
        &self,
        transport: &mut T,
        seq: u64,
        outcome: &SettledOutcome,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        match outcome {
            SettledOutcome::Applied => self.ack(transport, seq).await,
            SettledOutcome::Rejected(reason) => {
                if *reason == MutationRejectReason::Unauthorized {
                    return self.reject_unauthorized(transport, seq, state).await;
                }
                self.reject(transport, seq, reason.clone()).await
            }
            SettledOutcome::Conflict {
                table,
                version_column,
                pk_columns,
                pk_values,
            } => {
                let server_row = self
                    .target
                    .settled_conflict_row(
                        &state.principal,
                        table,
                        version_column,
                        pk_columns,
                        pk_values,
                    )
                    .await
                    .map_err(|err| SessionError::WriteTarget(err.detail()))?
                    .map(|row| ConflictRow {
                        updated_at: row.version,
                        row_json: row.row_json,
                    });
                transport
                    .send_control(ControlMessage::MutationConflict(MutationConflict {
                        client_seq: seq,
                        table: table.clone(),
                        server_row,
                    }))
                    .await
                    .map_err(transport_err)
            }
        }
    }

    /// Apply a new write at the frontier, settling its sequence with the apply
    /// and, when the provenance original stands unsettled, settling it alongside.
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per state of the writer frontier and the provenance original"
    )]
    async fn new_write<T: Transport>(
        &self,
        transport: &mut T,
        header: &MutationHeader,
        patch: &MutationPatch,
        seq: u64,
        bytes: &[u8],
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        let writer_row = state
            .writer_row
            .as_ref()
            .expect("a new write stands on the bound writer");
        let writer = writer_row.writer;
        let previous = writer_row.head.as_deref().map_or(GENESIS, |head| {
            <[u8; 32]>::try_from(head).unwrap_or(GENESIS)
        });
        let entry_hash = chain::entry_hash(&previous, seq, bytes);
        let mut settle = SettleSpec {
            writer,
            seq,
            entry_hash,
            previous_hash: previous,
            path: SettlePath::Direct,
            original: None,
        };
        // A provenance entry the original already settled settles this copy
        // with the stored outcome, so the logical write applies once.
        if let Some(provenance) = header.provenance {
            match self
                .provenance_original(
                    &provenance,
                    bytes,
                    &state.principal,
                    *state.session_id.as_uuid(),
                )
                .await?
            {
                Some((orig_writer, orig_frontier, _orig_hash, _orig_previous))
                    if provenance.seq <= orig_frontier =>
                {
                    let stored = self
                        .target
                        .settled_row(orig_writer, provenance.seq)
                        .await
                        .map_err(|err| SessionError::WriteTarget(err.detail()))?;
                    let outcome = match stored {
                        // A pruned record stands applied.
                        None => SettledOutcome::Applied,
                        Some(row) => {
                            if row.path != SettlePath::Direct {
                                self.guard.record(
                                    AuthEvent::new(
                                        state.session_id,
                                        state
                                            .principal
                                            .identity()
                                            .map(|identity| identity.user_id.clone()),
                                        AuthOp::WriteRedelivered,
                                    )
                                    .about_write(
                                        writer,
                                        i64::try_from(seq).unwrap_or(i64::MAX),
                                        row.path,
                                        SettlePath::Direct,
                                    ),
                                );
                            }
                            SettledOutcome::from_json(&row.outcome)
                                .map_err(|err| SessionError::WriteTarget(err.to_string()))?
                        }
                    };
                    let settlement = self
                        .target
                        .settle_refusal(&settle, &outcome)
                        .await
                        .map_err(|err| SessionError::WriteTarget(err.detail()))?;
                    let outcome = self.recorded_outcome(&state.principal, &settle, &settlement)?;
                    return self.answer_outcome(transport, seq, &outcome, state).await;
                }
                Some((orig_writer, orig_frontier, orig_hash, orig_previous))
                    if provenance.seq == orig_frontier + 1 =>
                {
                    settle.original = Some((orig_writer, provenance.seq, orig_hash, orig_previous));
                }
                Some((_, orig_frontier, _, _)) => {
                    let _ = transport
                        .send_control(ControlMessage::FatalError(FatalError::new(
                            FatalErrorReason::SequenceGap {
                                expected: orig_frontier + 1,
                                got: provenance.seq,
                            },
                        )))
                        .await;
                    return Err(SessionError::Protocol(format!(
                        "a provenance sequence {} past the original frontier {orig_frontier}",
                        provenance.seq
                    )));
                }
                // The original is not a writer of this account, so the entry applies plainly.
                None => {}
            }
        }
        let plan = match self
            .materializer
            .lock()
            .await
            .plan_write(&patch.patchset_zstd)
        {
            Ok(plan) => plan,
            Err(err) => {
                return self
                    .settle_and_refuse(transport, &settle, reject_reason(&err), state)
                    .await;
            }
        };
        match self.every_op_authorized(&plan, &state.principal).await {
            WriteVerdict::Allowed => {}
            // A genuine denial settles, so a redelivery re-answers it.
            WriteVerdict::Denied => {
                return self
                    .settle_and_refuse(
                        transport,
                        &settle,
                        MutationRejectReason::Unauthorized,
                        state,
                    )
                    .await;
            }
            // The service could not be reached, so nothing settles and the
            // client must retry rather than discard.
            WriteVerdict::Undetermined => {
                state.indeterminate = Some(seq);
                return self.reject_indeterminate(transport, seq).await;
            }
        }
        // The apply is the mutation's one reader-pool checkout, so a share
        // permit spans it (R39).
        let outcome = {
            let Some(_reader_permit) = self.mutation_permit(transport, patch, state).await? else {
                return Ok(());
            };
            self.commit_with_retry(&state.principal, &plan, &patch.patchset_zstd, &settle)
                .await
        };
        self.answer_write(transport, outcome, seq, &settle, state)
            .await
    }

    /// The owned original's writer, frontier, entry hash and predecessor.
    async fn provenance_original(
        &self,
        provenance: &Provenance,
        bytes: &[u8],
        caller: &Arc<Principal<Id, Key>>,
        session_id: uuid::Uuid,
    ) -> Result<Option<(i64, u64, [u8; 32], [u8; 32])>, SessionError> {
        let user_id = caller.identity().map(|identity| identity.user_id.clone());
        let bind_session = user_id.is_none().then_some(session_id);
        let row = match provenance.writer {
            WriterRef::Number(number) => {
                let writer = i64::try_from(number).unwrap_or(i64::MAX);
                match self
                    .target
                    .writer_by_number(writer, user_id.as_ref(), bind_session.as_ref())
                    .await
                    .map_err(|err| SessionError::WriteTarget(err.detail()))?
                {
                    Some(row) => row,
                    None => return Ok(None),
                }
            }
            WriterRef::Device(key_id) => {
                let key: Vec<u8> = key_id.to_vec();
                match self
                    .target
                    .writer_by_key(&key)
                    .await
                    .map_err(|err| SessionError::WriteTarget(err.detail()))?
                {
                    // Only this account's writers settle through their
                    // provenance; a key held elsewhere applies plain and is
                    // never confirmed.
                    Some(row) if same_account(row.user_id.as_ref(), user_id.as_ref()) => row,
                    Some(_) => return Ok(None),
                    // A device key enrolled to this account that never bound
                    // takes its row at frontier 0 (R75).
                    None => {
                        let Some(user_id) = user_id else {
                            return Ok(None);
                        };
                        let Some(enrolment) = self.device_enrolment.get() else {
                            return Ok(None);
                        };
                        let Some(record) = enrolment
                            .key_record(Some(&user_id), KeyId::from_bytes(key_id))
                            .await
                            .map_err(|_| {
                                SessionError::Protocol("the enrolment store did not answer".into())
                            })?
                        else {
                            return Ok(None);
                        };
                        if record.revoked {
                            return Ok(None);
                        }
                        self.target
                            .insert_device_writer(Some(user_id), &key)
                            .await
                            .map_err(|err| SessionError::WriteTarget(err.detail()))?;
                        match self
                            .target
                            .writer_by_key(&key)
                            .await
                            .map_err(|err| SessionError::WriteTarget(err.detail()))?
                        {
                            Some(row) => row,
                            None => return Ok(None),
                        }
                    }
                }
            }
        };
        let frontier = u64::try_from(row.frontier).unwrap_or(0);
        let previous = row.head.as_deref().map_or(GENESIS, |head| {
            <[u8; 32]>::try_from(head).unwrap_or(GENESIS)
        });
        let entry_hash = chain::entry_hash(&previous, provenance.seq, bytes);
        Ok(Some((row.writer, frontier, entry_hash, previous)))
    }

    fn recorded_outcome(
        &self,
        caller: &Principal<Id, Key>,
        settle: &SettleSpec,
        settlement: &Settlement,
    ) -> Result<SettledOutcome, SessionError> {
        let row = &settlement.row;
        let operation = if settlement.forked {
            Some(AuthOp::WriteForked)
        } else {
            (row.path != settle.path).then_some(AuthOp::WriteRedelivered)
        };
        if let Some(operation) = operation {
            self.guard.record(
                AuthEvent::new(
                    caller.session_id(),
                    caller.identity().map(|identity| identity.user_id.clone()),
                    operation,
                )
                .about_write(
                    settle.writer,
                    i64::try_from(settle.seq).unwrap_or(i64::MAX),
                    row.path,
                    settle.path,
                ),
            );
        }
        if settlement.forked {
            return Ok(SettledOutcome::Rejected(MutationRejectReason::Forked));
        }
        SettledOutcome::from_json(&row.outcome)
            .map_err(|err| SessionError::WriteTarget(err.to_string()))
    }

    /// Answer the write target's outcome: confirm, conflict, re-answer from
    /// the record, or refuse with the record settled.
    async fn answer_write<T: Transport>(
        &self,
        transport: &mut T,
        outcome: Result<WriteOutcome, WriteError>,
        seq: u64,
        settle: &SettleSpec,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        match outcome {
            Ok(WriteOutcome::Applied) => {
                state.indeterminate = None;
                self.ack(transport, seq).await
            }
            Ok(WriteOutcome::Conflict {
                table, server_row, ..
            }) => {
                state.indeterminate = None;
                transport
                    .send_control(ControlMessage::MutationConflict(MutationConflict {
                        client_seq: seq,
                        table,
                        server_row,
                    }))
                    .await
                    .map_err(transport_err)
            }
            Ok(WriteOutcome::Settled(settlement)) => {
                state.indeterminate = None;
                let outcome = self.recorded_outcome(&state.principal, settle, &settlement)?;
                self.answer_outcome(transport, seq, &outcome, state).await
            }
            Err(WriteError::Unauthorized) => {
                self.settle_and_refuse(transport, settle, MutationRejectReason::Unauthorized, state)
                    .await
            }
            Err(WriteError::Materializer(err)) => {
                self.settle_and_refuse(transport, settle, reject_reason(&err), state)
                    .await
            }
            Err(WriteError::Backend(detail)) => {
                self.settle_and_refuse(
                    transport,
                    settle,
                    MutationRejectReason::Other { detail },
                    state,
                )
                .await
            }
            Err(WriteError::Frontier) => {
                // The frontier kept moving under the write, so it cannot settle
                // until a concurrent copy resolves; the client must retry.
                state.indeterminate = Some(seq);
                self.reject_indeterminate(transport, seq).await
            }
            Err(WriteError::Transient(detail)) => {
                tracing::warn!(seq, error = %detail, "a write could not reach the database within the retry budget");
                state.indeterminate = Some(seq);
                self.reject_indeterminate(transport, seq).await
            }
        }
    }

    /// Settle a final refusal under the entry, so a redelivery re-answers it,
    /// and send the reject the client rolls back on.
    async fn settle_and_refuse<T: Transport>(
        &self,
        transport: &mut T,
        settle: &SettleSpec,
        reason: MutationRejectReason,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        let settlement = self
            .target
            .settle_refusal(settle, &SettledOutcome::Rejected(reason))
            .await
            .map_err(|err| SessionError::WriteTarget(err.detail()))?;
        let outcome = self.recorded_outcome(&state.principal, settle, &settlement)?;
        state.indeterminate = None;
        match outcome {
            SettledOutcome::Rejected(reason) => self.reject(transport, settle.seq, reason).await,
            outcome => {
                self.answer_outcome(transport, settle.seq, &outcome, state)
                    .await
            }
        }
    }

    /// Commit one mutation under `caller`, applying it again while the
    /// database fails transiently or the frontier re-races it and the write
    /// retry budget lasts.
    pub(crate) async fn commit_with_retry(
        &self,
        caller: &Principal<Id, Key>,
        plan: &crate::materializer::WritePlan,
        payload_zstd: &[u8],
        settle: &SettleSpec,
    ) -> Result<WriteOutcome, WriteError> {
        let policy =
            RetryPolicy::new().with_max_total_backoff(Some(self.config.write_retry_budget));
        let mut episode = policy.start();
        loop {
            let outcome = self.target.commit(caller, plan, payload_zstd, settle).await;
            let retryable = match &outcome {
                Err(WriteError::Transient(detail)) => Some(detail.clone()),
                Err(WriteError::Frontier) => None,
                _ => return outcome,
            };
            let Some(wait) = episode.next_wait() else {
                return outcome;
            };
            match retryable {
                Some(detail) => {
                    tracing::warn!(seq = settle.seq, error = %detail, wait_ms = retry_ms(wait), "a write could not reach the database, applying it again");
                }
                None => {
                    tracing::warn!(
                        seq = settle.seq,
                        wait_ms = retry_ms(wait),
                        "the frontier moved under a write, racing it again"
                    );
                }
            }
            tokio::time::sleep(wait).await;
        }
    }

    /// Refuse one write the policy rejected, and report it as an abuse signal.
    ///
    /// Naming a row and being told no is the phase's definition of a signal.
    /// This is the one signal no rate limit sits above, so its threshold does
    /// all its own work.
    async fn reject_unauthorized<T: Transport>(
        &self,
        transport: &mut T,
        client_seq: u64,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        let reaction = self.guard.rejected_write(Self::caller(&state.principal));
        if reaction == Reaction::Close {
            state.closing = true;
        }
        self.reject(transport, client_seq, MutationRejectReason::Unauthorized)
            .await
    }

    /// Refuse one write the database or the authorization service could not
    /// answer. The client MUST retry rather than discard its pending record:
    /// the server could not determine whether the write is permitted or apply
    /// it, so discarding it would turn a transient outage into permanent loss.
    async fn reject_indeterminate<T: Transport>(
        &self,
        transport: &mut T,
        client_seq: u64,
    ) -> Result<(), SessionError> {
        self.reject(transport, client_seq, MutationRejectReason::Indeterminate)
            .await
    }

    async fn reject<T: Transport>(
        &self,
        transport: &mut T,
        client_seq: u64,
        reason: MutationRejectReason,
    ) -> Result<(), SessionError> {
        transport
            .send_control(ControlMessage::MutationReject(MutationReject {
                client_seq,
                reason,
            }))
            .await
            .map_err(transport_err)
    }

    /// Confirm a durably applied sequence, so the client retires the pending
    /// record it would otherwise replay on the next resume.
    async fn ack<T: Transport>(
        &self,
        transport: &mut T,
        client_seq: u64,
    ) -> Result<(), SessionError> {
        transport
            .send_control(ControlMessage::MutationApplied(MutationApplied {
                client_seq,
            }))
            .await
            .map_err(transport_err)
    }

    /// Build the term seed one described filter needs, or `None` when it
    /// names no term.
    ///
    /// Each term says which of the caller's values its own SQL reads.
    /// A term written against the identity is seeded from the subscriber and
    /// a term written against the subject set from the subjects, because
    /// seeding one from the other would admit rows the registered query does
    /// not return, or refuse rows it does.
    ///
    /// Refuses rather than narrows. A value that cannot be built at the
    /// compared column's kind turns the registration away, since a seed short
    /// one subject admits fewer rows than the query the caller sent returns
    /// and no later membership change repairs it.
    async fn seed_for_terms(
        &self,
        terms: &[TermDescription],
        state: &SessionState<Id, Key>,
    ) -> Result<Option<TermSeed>, SubscribeRefusal> {
        let seed = match terms {
            [] => None,
            all => {
                let reads_identity = all
                    .iter()
                    .any(|term| caller_of(term) == TermCaller::Identity);
                let reads_subjects = all
                    .iter()
                    .any(|term| caller_of(term) == TermCaller::Subjects);
                // One kind per side, checked only among the terms that read
                // that side: the engine builds one subscriber and one subject
                // set per registration, and a filter may legitimately compare
                // the identity on one column's kind and the set on another.
                let subscriber = if reads_identity {
                    let identity = state
                        .principal
                        .identity()
                        .ok_or(SubscribeRefusal::Anonymous)?;
                    let kind = one_kind(all, TermCaller::Identity)?;
                    Some(
                        typed_subscriber(&identity.user_id.to_string(), kind)
                            .ok_or(SubscribeRefusal::Mistyped)?,
                    )
                } else {
                    None
                };
                let subjects = if reads_subjects {
                    let kind = one_kind(all, TermCaller::Subjects)?;
                    caller_subjects(
                        state.principal.identity(),
                        state.principal.capabilities(),
                        kind,
                    )?
                } else {
                    Vec::new()
                };
                let mut term_values = Vec::new();
                for term in all {
                    // A caller comparison seeds itself from the value it
                    // admits: there is no membership table to read.
                    let TermDescription::Membership(membership) = term else {
                        continue;
                    };
                    let member_keys: Vec<String> = membership
                        .pairs
                        .iter()
                        .map(|pair| pair.member_key.clone())
                        .collect();
                    let read = self
                        .snapshot_source
                        .term_seed(
                            &membership.seed_sql,
                            &membership.member_table,
                            &membership.member_subject,
                            &member_keys,
                            &state.principal,
                        )
                        .await
                        .map_err(|err| SubscribeRefusal::Seed(err.to_string()))?
                        .ok_or(SubscribeRefusal::Unseedable)?;
                    match read.published {
                        Some(true) => {}
                        Some(false) => {
                            return Err(SubscribeRefusal::Unpublished(
                                membership.member_table.clone(),
                            ));
                        }
                        None => return Err(SubscribeRefusal::NoPublication),
                    }
                    // Registration refuses a null cell inside a stated row,
                    // and a null subject with it, so a row carrying either is
                    // dropped whole rather than half-stated.
                    let rows: Vec<(PgValue<Postgres>, Vec<PgValue<Postgres>>)> = read
                        .rows
                        .into_iter()
                        .filter(|(subject, values)| {
                            !core::iter::once(subject)
                                .chain(values)
                                .any(|value| matches!(value, PgValue::Missing | PgValue::Null))
                        })
                        .collect();
                    let columns: Vec<String> = membership
                        .pairs
                        .iter()
                        .map(|pair| pair.column.clone())
                        .collect();
                    term_values.push((columns, rows));
                }
                Some(TermSeed {
                    subscriber,
                    subjects,
                    term_values,
                })
            }
        };
        Ok(seed)
    }

    /// Translate and register one subscription, seeding a membership term.
    ///
    /// A filter naming no term registers as before. A term is seeded per R27:
    /// every subject the caller holds typed at `member_subject`'s own catalog
    /// kind and the values read from the membership table as the caller,
    /// each value row under the subject granting it. The materializer
    /// lock is held across the seed read and the register (decision 11), so
    /// no dispatch lands between the seed's snapshot and the engine watching,
    /// which would silently lose that membership change for good. The
    /// lock-then-connection order cannot deadlock: no other path holds this
    /// lock and a pooled connection at once, verified against
    /// `dispatch_event` and `handle_mutation`.
    async fn register_subscription(
        &self,
        consumer_id: u64,
        sub: &Subscribe,
        state: &SessionState<Id, Key>,
    ) -> Result<Registered, SubscribeRefusal> {
        let mut materializer = self.materializer.lock().await;
        let pg_sql = materializer.translate_subscription_sql(&sub.spec.query)?;
        // The rule's caller-reading term only describes when the caller is stated.
        let subscriber = state
            .principal
            .identity()
            .map(|identity| PgValue::String(identity.user_id.to_string()));
        let subjects: Vec<PgValue<Postgres>> = state
            .principal
            .capabilities()
            .iter()
            .map(|subject| PgValue::String(subject.key().to_string()))
            .collect();
        // Describing asks the plain compiler, which refuses shapes the
        // re-execution wrapper goes on to accept (a `MAX` aggregate, say), so
        // a refusal here is not one: registration below is the authority and
        // re-raises anything genuinely refused, term problems included, since
        // subql describes and registers through one compile path.
        let terms = materializer
            .describe_terms(consumer_id, &pg_sql, &sub.spec.binds, subscriber, subjects)
            .unwrap_or_default();
        let seed = self.seed_for_terms(&terms, state).await?;
        let member_tables = Self::member_tables_of(&terms);
        let reads_subjects = terms
            .iter()
            .any(|term| caller_of(term) == TermCaller::Subjects);
        // Engine-driven reads run on the dispatch path, so they spend the
        // shared re-execution bound: a slow read delays everyone's stream.
        let viewer = self.viewer_read_setup(state);
        let registration = materializer.register_translated(
            consumer_id,
            &pg_sql,
            &sub.spec.binds,
            seed,
            self.guard.reexec_budget(),
            viewer,
        )?;
        Ok(Registered {
            registration,
            pg_sql,
            member_tables,
            reads_subjects,
        })
    }

    /// The read setup a per-consumer registration would run under: the shared
    /// re-execution budget plus this caller's own binding, or `None` for a
    /// caller that binds nothing at all. An aggregate over a
    /// row-level-security table cannot share one fold, and offering this is
    /// what lets registration retry it with per-consumer reads that answer as
    /// this viewer (R85); with nobody to read as, the refusal stands.
    ///
    /// A share key is somebody to read as, so only a caller holding neither an
    /// identity nor a subject is refused.
    fn viewer_read_setup(
        &self,
        state: &SessionState<Id, Key>,
    ) -> Option<crate::reexec::ConnettoReadSetup> {
        let binding =
            crate::capability::CallerBinding::of(&state.principal, self.target.user_setting());
        // Both settings are bound either way, an unheld half taking the absent
        // marker, so what decides the offer is what the caller holds rather
        // than how many statements the binding renders.
        binding.binds_a_caller().then(|| {
            crate::reexec::ConnettoReadSetup::of(ReadBudget::new(
                self.guard.reexec_budget().timeout,
            ))
            .with_statements(binding.setup_statements())
        })
    }

    /// The membership tables a registration's terms read, paired with the member
    /// subject column, for the session's term-move routing.
    /// The membership tables a filter's terms watch, one entry per table and
    /// column, carrying every caller kind the terms over it read.
    ///
    /// Collapsed rather than one entry per term, because the mirror is keyed
    /// by table and opened once. Two terms over one table under different
    /// caller kinds would otherwise open the first and silently skip the
    /// second, leaving that kind's membership moves undelivered.
    fn member_tables_of(terms: &[TermDescription]) -> std::sync::Arc<[MemberTable]> {
        let mut tables: Vec<MemberTable> = Vec::new();
        for term in terms {
            let TermDescription::Membership(membership) = term else {
                continue;
            };
            let held = tables.iter().position(|held| {
                held.table == membership.member_table && held.subject == membership.member_subject
            });
            let at = held.unwrap_or_else(|| {
                tables.push(MemberTable {
                    table: membership.member_table.clone(),
                    subject: membership.member_subject.clone(),
                    identity: false,
                    subjects: false,
                });
                tables.len() - 1
            });
            let entry = &mut tables[at];
            match membership.caller {
                TermCaller::Identity => entry.identity = true,
                TermCaller::Subjects => entry.subjects = true,
            }
        }
        tables.into()
    }

    async fn handle_subscribe<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        let tier = Tier::of(&state.principal);
        // The reader-share permit (R39) comes first and the allowance second,
        // so a subscribe the share defers has spent nothing and its retry is
        // not refused by count, while a probe that fails to resolve still pays
        // (R36 counts probing, and a free failure would hand it an unlimited
        // budget). The permit is held across registration, which is a
        // materializer-lock translate and touches no database, and a computed
        // subscription drops it, since its reads spend the shared re-execution bound.
        let reader_permit = match self.guard.reader_permit(tier).await {
            Ok(permit) => permit,
            Err(wait) => {
                let retry_after_ms = retry_ms(wait);
                tracing::warn!(
                    sub_id = %sub.sub_id,
                    retry_after_ms,
                    "subscription deferred, the unreserved reader share is full"
                );
                transport
                    .send_control(ControlMessage::RateLimited(RateLimited {
                        related_to: Some(sub.sub_id),
                        retry_after_ms,
                    }))
                    .await
                    .map_err(transport_err)?;
                return Ok(());
            }
        };
        if let Some(wait) = self.guard.subscription(state.session_id, tier) {
            let retry_after_ms = retry_ms(wait);
            tracing::warn!(
                sub_id = %sub.sub_id,
                retry_after_ms,
                "subscription refused, rate limit reached"
            );
            transport
                .send_control(ControlMessage::RateLimited(RateLimited {
                    related_to: Some(sub.sub_id),
                    retry_after_ms,
                }))
                .await
                .map_err(transport_err)?;
            return Ok(());
        }
        let consumer_id = self.next_consumer_id();
        let registered = match self.register_subscription(consumer_id, &sub, state).await {
            Ok(registered) => registered,
            Err(err) => {
                tracing::warn!(sub_id = %sub.sub_id, error = %err, "subscription registration refused");
                // Naming something that does not resolve is one of the four
                // abuse signals. The snapshot failure below is not: there the
                // table exists and the read failed, which says nothing about
                // what the caller named.
                let reaction = self
                    .guard
                    .unresolvable_subscription(Self::caller(&state.principal));
                if reaction == Reaction::Close {
                    state.closing = true;
                }
                transport
                    .send_control(ControlMessage::NonFatalError(NonFatalError {
                        related_to: Some(sub.sub_id),
                        detail: SUBSCRIPTION_REFUSED.to_owned(),
                    }))
                    .await
                    .map_err(transport_err)?;
                return Ok(());
            }
        };
        let reads_subjects = registered.reads_subjects;
        match registered.into_row(consumer_id) {
            Ok(reg) => {
                self.serve_term_row(transport, sub, state, tier, reg, reader_permit)
                    .await
            }
            Err(capture) => {
                // Aggregates bootstrap through the re-execution connector and hold no share permit (R39).
                drop(reader_permit);
                self.subscribe_computed(transport, sub, state, capture, reads_subjects, None)
                    .await
            }
        }
    }

    /// Serve one registered row subscription under the R39 reader permit the
    /// caller already holds, which spans the whole row delivery (the snapshot
    /// read or the catchup replay's visibility questions, which check out
    /// reader connections one at a time, so an unidentified caller counts once
    /// for the operation however many checkouts it makes): the R27 allowance
    /// pre-charge for the membership subscription a term needs, the snapshot
    /// or catchup, and the membership open behind it.
    async fn serve_term_row<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState<Id, Key>,
        tier: Tier,
        reg: RowRegistration,
        reader_permit: ReaderPermit,
    ) -> Result<(), SessionError> {
        let sub_label = sub.sub_id.clone();
        let (consumer_id, sub_id) = (reg.consumer_id, reg.sub_id);
        // R27 decisions 4 and 7: the membership subscription this term needs
        // is counted against the same allowance before anything is served, so
        // a caller at its ceiling is refused as a unit rather than served
        // half.
        for member in reg.member_tables.iter() {
            if state.subs.contains_key(&membership_label(&member.table)) {
                continue;
            }
            if let Some(wait) = self.guard.subscription(state.session_id, tier) {
                let retry_after_ms = retry_ms(wait);
                self.materializer.lock().await.unregister(sub_id);
                transport
                    .send_control(ControlMessage::RateLimited(RateLimited {
                        related_to: Some(sub_label),
                        retry_after_ms,
                    }))
                    .await
                    .map_err(transport_err)?;
                return Ok(());
            }
        }
        let members = std::sync::Arc::clone(&reg.member_tables);
        let membership_permit = reader_permit.clone();
        match self
            .subscribe_row(transport, sub, state, reg, tier, Some(reader_permit))
            .await
        {
            // A snapshot failure is scoped to this one subscription: the
            // registration is rolled back and the session (with every sibling
            // subscription) stays alive. Transport and oplog failures stay
            // fatal.
            Err(SessionError::Snapshot(detail) | SessionError::ReadRefused(detail)) => {
                tracing::warn!(sub_id = %sub_label, error = %detail, "snapshot failed");
                state.subs.remove(&sub_label);
                self.remove_route(consumer_id).await;
                self.materializer.lock().await.unregister(sub_id);
                transport
                    .send_control(ControlMessage::NonFatalError(NonFatalError {
                        related_to: Some(sub_label),
                        detail: SUBSCRIPTION_REFUSED.to_owned(),
                    }))
                    .await
                    .map_err(transport_err)?;
                Ok(())
            }
            Ok(()) => {
                // R27 decision 7: the server opens the membership
                // subscription the term needs, after the term's own frames so
                // the announce precedes the hidden subscription's snapshot.
                for member in members.iter() {
                    match self
                        .open_membership_subscription(
                            transport,
                            state,
                            tier,
                            member,
                            membership_permit.clone(),
                        )
                        .await
                    {
                        Ok(()) => {}
                        // Without its membership rows the term's local answer is wrong, so the two are refused as a unit.
                        Err(SessionError::Snapshot(detail) | SessionError::ReadRefused(detail)) => {
                            tracing::warn!(sub_id = %sub_label, error = %detail, "membership read failed, refusing the term");
                            return self.refuse_subscription(transport, state, &sub_label).await;
                        }
                        Err(other) => return Err(other),
                    }
                }
                Ok(())
            }
            other => other,
        }
    }

    /// Deliver a row subscription, by snapshot or by oplog catchup.
    ///
    /// A fresh session snapshots. A resuming session whose cursor is still
    /// inside the retained window catches up from the oplog instead of
    /// re-snapshotting. One outside the window, or past where its timeline
    /// ended, snapshots afresh, and the resync notice goes out with the new
    /// data rather than here, so a failing read reads like any other refusal
    /// and costs the client nothing.
    async fn subscribe_row<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState<Id, Key>,
        reg: RowRegistration,
        tier: Tier,
        permit: Option<ReaderPermit>,
    ) -> Result<(), SessionError> {
        let resync = match state.resume.clone() {
            Resume::Fresh => None,
            Resume::BeyondHistory => Some(FullResyncReason::CursorBeyondHistory),
            // A catch-up never shows or hides a row that did not change, so keys
            // that changed since the cursor need the whole set again (R95).
            Resume::At(..)
                if key_change_reaches(&reg, self.key_tables())
                    && state.cursor_subjects.as_ref().is_none_or(|subjects| {
                        *subjects != rendered_keys(state.principal.capabilities())
                    }) =>
            {
                Some(FullResyncReason::AuthorizationChange)
            }
            Resume::At(at, fence) => {
                let min = read_log::<O, _, _>(&mut state.resume_read_budget, || {
                    self.oplog.min_position()
                })
                .await?;
                let current = read_log::<O, _, _>(&mut state.resume_read_budget, || {
                    self.oplog.current_position()
                })
                .await?;
                match catchup_decision(at, min, current) {
                    CatchupDecision::Catchup => {
                        return self
                            .catch_up_row(transport, sub, state, &reg, at, fence)
                            .await;
                    }
                    CatchupDecision::FullResync => Some(FullResyncReason::CursorOutsideRetention),
                }
            }
        };
        self.snapshot_row(
            transport,
            state,
            ReadStart {
                sub,
                reg,
                tier,
                permit,
                restarted: false,
            },
            resync,
        )
        .await
    }

    /// Open the membership subscription a term needs, on the client's behalf
    /// (R27 decisions 3, 4, 7 and 12): the caller's own membership rows and
    /// nothing wider, announced ahead of its snapshot, hidden from the
    /// changed-tables signal by the client, and torn down with the last term
    /// subscription that needs it. Idempotent per session through the
    /// deterministic label, which also covers a reconnect registering the
    /// same term again.
    ///
    /// It reads under `permit`, the term's own reader-share slot, because the
    /// two reads are one operation and a second slot could be refused while the
    /// term's still paging read holds the first.
    async fn open_membership_subscription<T: Transport>(
        &self,
        transport: &mut T,
        state: &mut SessionState<Id, Key>,
        tier: Tier,
        member: &MemberTable,
        permit: ReaderPermit,
    ) -> Result<(), SessionError> {
        let label = membership_label(&member.table);
        if state.subs.contains_key(&label) {
            return Ok(());
        }
        // A term reading the identity has nothing to mirror for a caller with
        // none, and `register_subscription` refuses it for the same reason.
        if member.identity && state.principal.identity().is_none() {
            return Err(SessionError::Snapshot(
                "a membership subscription over an identity term needs an identified caller"
                    .to_owned(),
            ));
        }
        // The caller's own rows only (decision 12): a membership table
        // typically carries no policy of its own, so an unfiltered read would
        // snapshot every tenant's membership rows to every client. The caller
        // rides as the deployment's own caller function (R63 decision 2), so
        // subql compiles one self-seeding term whose predicate text is shared
        // by every subscriber, instead of one inlined-literal predicate per
        // identity. A term subscription only exists because the application's
        // query named this function, so the mapping is present whenever this
        // runs, and its absence is a server-side defect.
        let (identity_function, subjects_function) = {
            let materializer = self.materializer.lock().await;
            (
                materializer.caller_function().map(str::to_owned),
                materializer.subject_set_function().map(str::to_owned),
            )
        };
        let table = connetto_core::quote_ident(&member.table);
        let predicate = mirror_predicate(
            member,
            identity_function.as_deref(),
            subjects_function.as_deref(),
            Key::SEPARATOR,
        )
        .map_err(|gap| {
            SessionError::Snapshot(match gap {
                MirrorGap::Identity => {
                    "a membership subscription needs the deployment's caller mapping".to_owned()
                }
                MirrorGap::Subjects => "a membership subscription over a subject-set term needs \
                     the deployment's subject mapping"
                    .to_owned(),
            })
        })?;
        let query = format!("SELECT * FROM {table} WHERE {predicate}");
        let hidden = Subscribe {
            sub_id: label.clone(),
            spec: SubscriptionSpec::new(query),
        };
        transport
            .send_control(ControlMessage::MembershipOpened(MembershipOpened {
                sub_id: label.clone(),
                member_table: member.table.clone(),
            }))
            .await
            .map_err(transport_err)?;
        let consumer_id = self.next_consumer_id();
        let registered = match self
            .register_subscription(consumer_id, &hidden, state)
            .await
        {
            Ok(registered) => registered,
            // The server's own rendering over its own catalog, so a refusal is a server-side defect.
            Err(err) => return Err(SessionError::Snapshot(err.to_string())),
        };
        let Ok(mut reg) = registered.into_row(consumer_id) else {
            return Err(SessionError::Snapshot(
                "a membership subscription registered as something other than rows".to_owned(),
            ));
        };
        reg.member_tables = std::sync::Arc::from(Vec::new());
        reg.reads_subjects |= member.subjects;
        self.subscribe_row(transport, hidden, state, reg, tier, Some(permit))
            .await
    }

    /// Install the live route and record the subscription, so `dispatch_event`
    /// starts delivering to this consumer.
    ///
    /// Both row paths call this before reading anything. Until the route
    /// exists every patch produced for the consumer is discarded, and the
    /// snapshot read plus its bulk transfer is long enough to lose commits.
    ///
    /// The route also records the table the subscription reads, taken from the
    /// translated SQL rather than from the client's text, because that is what
    /// a moved grant is matched against (R7).
    async fn attach_row_route(
        &self,
        sub: &Subscribe,
        state: &mut SessionState<Id, Key>,
        reg: &RowRegistration,
        fence: Option<Arc<ReadFence>>,
    ) {
        self.add_route(
            reg.consumer_id,
            Route {
                session_key: state.session_id.as_u64_key(),
                sub_id: reg.sub_id,
                label: sub.sub_id.clone(),
                tx: state.outbound.clone(),
                principal: Arc::clone(&state.principal),
                table: crate::snapshot::table_from_select(&reg.pg_sql).ok(),
                pg_sql: reg.pg_sql.as_str().into(),
                binds: sub.spec.binds.clone().into(),
                member_tables: reg.member_tables.clone(),
                fence,
            },
        )
        .await;
        // A resnapshot re-records the same subscription, so the delivery
        // counters carry over rather than resetting: what a standing request
        // has cost over its life does not restart because it was replaced.
        let carried = state
            .subs
            .get(&sub.sub_id)
            .map(|row| (row.first_delivery, row.delivered, row.warned));
        let (first_delivery, delivered, warned) = carried.unwrap_or((None, 0, false));
        state.subs.insert(
            sub.sub_id.clone(),
            RowSub {
                reg: reg.clone(),
                sub: sub.clone(),
                first_delivery,
                delivered,
                warned,
            },
        );
    }

    /// Replace what one subscription holds, because a grant reaching its table
    /// moved (R7) or a table it reads was emptied (R48).
    ///
    /// The read comes first and the notice second, which `snapshot_row`
    /// guarantees, so a failed read leaves the client holding what it had and
    /// nothing is discarded on a promise. That is also why a failure is retried
    /// rather than reported: the rows are still there, wrongly, until the
    /// replacement lands. The backoff is the one the ingest loop uses when the
    /// authorization service is unreachable, because a read failing here is the
    /// same class of outage.
    async fn resnapshot_row<T: Transport>(
        &self,
        transport: &mut T,
        state: &mut SessionState<Id, Key>,
        sub_label: &str,
        reason: &FullResyncReason,
        permit: Option<ReaderPermit>,
    ) -> Result<(), SessionError> {
        // The notice goes straight out while row frames wait for credit, so a
        // queued frame of the old answer would land after the clear.
        state
            .pending
            .retain(|queued| queued.sub_id() != Some(sub_label));
        state.paging.retain(|read| read.label != sub_label);
        let mut attempt: u32 = 0;
        loop {
            // Read afresh each time: an unsubscribe may have landed between
            // attempts, and then there is nothing left to replace.
            let Some(row) = state.subs.get(sub_label) else {
                return Ok(());
            };
            let (sub, reg) = (row.sub.clone(), row.reg.clone());
            match self
                .snapshot_row(
                    transport,
                    state,
                    ReadStart {
                        sub,
                        reg,
                        tier: Tier::of(&state.principal),
                        permit: permit.clone(),
                        restarted: false,
                    },
                    Some(reason.clone()),
                )
                .await
            {
                Ok(()) => return Ok(()),
                Err(SessionError::Snapshot(detail)) => {
                    attempt = attempt.saturating_add(1);
                    let backoff = self.auth_retry.backoff(attempt);
                    tracing::warn!(
                        sub_id = %sub_label,
                        attempt,
                        error = %detail,
                        "replacing a subscription failed, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                }
                // A refusal is not an outage, so retrying it would replace
                // nothing for ever. The subscription ends instead, and the
                // rows it held are covered by nothing, which R29's retention
                // pass evicts on the client.
                Err(SessionError::ReadRefused(detail)) => {
                    tracing::warn!(
                        sub_id = %sub_label,
                        error = %detail,
                        "replacing a subscription was refused, ending it"
                    );
                    return self.refuse_subscription(transport, state, sub_label).await;
                }
                Err(other) => return Err(other),
            }
        }
    }

    /// Snapshot a row subscription: route first, then the estimate, then the
    /// first page, then the resync notice, begin, rows, and either the end or
    /// a continuation that later pages arrive on.
    ///
    /// The rows and the end share one queue, so the end cannot overtake the
    /// rows it completes however far behind the client has fallen. Only the
    /// rows spend a credit.
    ///
    /// Live delivery runs throughout, so a change committed while the read is
    /// in flight reaches the client as a patch of its own. Such a patch may
    /// repeat a row a page already carried, which is harmless: patches arrive
    /// in commit order, so the last one applied for a row is that row's
    /// current value. A paged read takes that one step further, since a later
    /// page is read after every frame already sent and so can never carry a
    /// value older than one the client has applied (R58 decision 9).
    /// Filtering the overlap by LSN was considered and rejected, see
    /// `04-subscriptions.md`.
    ///
    /// No frame goes out until the first page succeeds. A `SnapshotBegin` or a
    /// `FullResyncRequired` ahead of a failing read would mark the refusal as
    /// one that passed registration, and a refusal must not vary by cause.
    /// The resync notice is also what makes the client discard the rows it
    /// holds, so it must not go out before the replacement data exists.
    async fn snapshot_row<T: Transport>(
        &self,
        transport: &mut T,
        state: &mut SessionState<Id, Key>,
        start: ReadStart,
        resync: Option<FullResyncReason>,
    ) -> Result<(), SessionError> {
        let ReadStart {
            sub,
            reg,
            tier,
            permit,
            restarted,
        } = start;
        self.attach_row_route(&sub, state, &reg, None).await;
        // Any read still arriving in pages for this label is abandoned: this
        // call is its replacement.
        state.paging.retain(|read| read.label != sub.sub_id);
        state.missed.retain(|replay| replay.label != sub.sub_id);
        let limits = self.guard.read_limits(tier);
        let estimate = self
            .snapshot_source
            .estimate(&reg.pg_sql, &sub.spec.binds, &state.principal)
            .await
            .map_err(|err| {
                refuse_read(&sub.sub_id, &SubscribeRefusal::Estimate(err.to_string()))
            })?;
        // The cheap refusal the estimate pays for: a table whose typical row
        // is already above the ceiling has no servable page, and nothing has
        // been read to find out (R58 decision 10).
        if u64::from(estimate.width) > limits.row_ceiling {
            return Err(refuse_read(
                &sub.sub_id,
                &SubscribeRefusal::TableTooWide {
                    width: estimate.width,
                    ceiling: limits.row_ceiling,
                },
            ));
        }
        let max_rows = page_rows(limits.page_bytes, estimate.width);
        let page = self
            .snapshot_source
            .snapshot_page(
                &reg.pg_sql,
                &sub.spec.binds,
                &state.principal,
                &PageSpec {
                    after: None,
                    max_rows,
                    timeout: limits.timeout,
                },
            )
            .await
            .map_err(|err| {
                if err.read_failure() == ReadFailure::Timeout {
                    SessionError::ReadRefused(err.to_string())
                } else {
                    SessionError::Snapshot(err.to_string())
                }
            })?;
        admit_page(&sub.sub_id, &page, max_rows, estimate.width, limits)?;
        let (cursor, replay) = self.first_page_end(&page.cursor, &sub.sub_id, reg.consumer_id);
        if let Some(reason) = resync {
            transport
                .send_control(ControlMessage::FullResyncRequired(FullResyncRequired {
                    sub_id: sub.sub_id.clone(),
                    reason,
                }))
                .await
                .map_err(transport_err)?;
        }
        transport
            .send_control(ControlMessage::SnapshotBegin(SnapshotBegin {
                sub_id: sub.sub_id.clone(),
                priority: sub.spec.priority,
            }))
            .await
            .map_err(transport_err)?;
        let delivered = self
            .send_page(transport, state, &sub.sub_id, page.patchset)
            .await?;
        state.missed.extend(replay);
        // More to come. The producer waits in `state.paging` and the next
        // page is taken when the client acknowledges this one, because the
        // only path that can read that acknowledgement is the one a
        // waiting read would block (R33).
        if let Some(after) = page.next {
            state.paging.push_back(PagedRead {
                label: sub.sub_id.clone(),
                sub,
                reg,
                after,
                max_rows,
                limits,
                average_width: estimate.width,
                cursor,
                delivered,
                tier,
                restarted,
                permit,
            });
            Ok(())
        } else {
            self.complete_snapshot(transport, state, sub.sub_id, cursor, delivered)
                .await
        }
    }

    /// Send each fenced snapshot the rows of the transactions its fence missed that the log already holds, in commit order, as live patches under the snapshot's own cursor.
    ///
    /// Those were dispatched before the route existed, so the live path never sent them, and the snapshot does not hold them either (the state table in `plans/design-commit-positions.md`). A client that drops before they arrive resumes from that cursor and is sent them again. A missed truncate cannot be sent as a patch and a read taken now would miss it again, so the subscription is refused.
    async fn replay_missed<T: Transport>(
        &self,
        transport: &mut T,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        for replay in std::mem::take(&mut state.missed) {
            let unseen = replay.fence.unseen();
            let records = read_log::<O, _, _>(&mut state.resume_read_budget, || {
                self.oplog.entries_of(&unseen)
            })
            .await?;
            let watchers = [Arc::clone(&state.principal)];
            let mut verdicts = Transitions::new();
            let mut payloads = Vec::new();
            let mut truncated = false;
            for record in records {
                if replay.fence.seen(record.position()) != Seen::Missed {
                    continue;
                }
                let matched = {
                    self.materializer
                        .lock()
                        .await
                        .replay_match(record.event(), replay.consumer_id)?
                };
                let Some(departing) = matched else {
                    continue;
                };
                if record.event().kind() == EventKind::Truncate {
                    truncated = true;
                    break;
                }
                if let Some(payload) = self
                    .replay_payload(transport, &record, departing, &watchers, &mut verdicts)
                    .await?
                {
                    payloads.push(payload);
                }
            }
            if truncated {
                tracing::warn!(sub_id = %replay.label, "a truncate the snapshot missed is not yet visible, refusing the subscription");
                self.refuse_subscription(transport, state, &replay.label)
                    .await?;
                continue;
            }
            for payload in payloads {
                let live = LivePatch::new(replay.label.clone(), replay.cursor.clone(), payload);
                enqueue_and_flush(
                    transport,
                    &mut state.credits,
                    &mut state.pending,
                    Deliverable::Rows(BulkMessage::LivePatch(live)),
                )
                .await
                .map_err(transport_err)?;
            }
        }
        Ok(())
    }

    /// The cursor a read's `SnapshotEnd` carries, from its first page's, and the replay its fence owes.
    fn first_page_end(
        &self,
        page_cursor: &Cursor,
        label: &str,
        consumer_id: u64,
    ) -> (Cursor, Option<MissedReplay>) {
        let Some((read, fence)) = split_snapshot_cursor(page_cursor.as_bytes()) else {
            return (Cursor::new(Vec::new()), None);
        };
        let cursor = Cursor::new(self.stamp_fenced(read, fence.as_ref()));
        let replay = fence.map(|fence| MissedReplay {
            label: label.to_owned(),
            consumer_id,
            fence,
            cursor: cursor.clone(),
        });
        (cursor, replay)
    }

    /// A snapshot's cursor for the wire: `read` stamped with the timeline last read, then `fence`.
    fn stamp_fenced(&self, read: PgCommitPosition, fence: Option<&ReadFence>) -> Vec<u8> {
        let mut bytes = self.stamp(read);
        if let Some(fence) = fence {
            fence.encode_into(&mut bytes);
        }
        bytes
    }

    /// Deliver one page's rows, returning what the frame carried.
    ///
    /// Compression happens here rather than in the source, so the source
    /// answers in rows and the wire's own encoding stays on this side.
    async fn send_page<T: Transport>(
        &self,
        transport: &mut T,
        state: &mut SessionState<Id, Key>,
        label: &str,
        patchset: Vec<u8>,
    ) -> Result<u64, SessionError> {
        let payload = compress(&patchset)?;
        let bytes = payload.len() as u64;
        enqueue_and_flush(
            transport,
            &mut state.credits,
            &mut state.pending,
            Deliverable::Rows(BulkMessage::SnapshotPatch(SnapshotPatch::new(
                label.to_owned(),
                payload,
            ))),
        )
        .await
        .map_err(transport_err)?;
        Ok(bytes)
    }

    /// Close a delivery: queue its `SnapshotEnd` and record what it carried as
    /// the reference the growth warning is measured against.
    ///
    /// The end is queued rather than sent, so it cannot overtake the rows it
    /// completes when the credit window is shut. It costs no credit: it waits
    /// its turn, it is not rationed. Sending it here instead would tell the
    /// client to record a resume position for rows still in `pending` (R33).
    async fn complete_snapshot<T: Transport>(
        &self,
        transport: &mut T,
        state: &mut SessionState<Id, Key>,
        label: String,
        cursor: Cursor,
        delivered: u64,
    ) -> Result<(), SessionError> {
        if let Some(row) = state.subs.get_mut(&label) {
            row.delivered = row.delivered.saturating_add(delivered);
            if row.first_delivery.is_none() {
                row.first_delivery = Some(delivered);
            }
        }
        enqueue_and_flush(
            transport,
            &mut state.credits,
            &mut state.pending,
            Deliverable::SnapshotComplete(SnapshotEnd {
                sub_id: label,
                cursor,
            }),
        )
        .await
        .map_err(transport_err)
    }

    /// Take the next page of the read that has waited longest, if the client
    /// has room for it.
    ///
    /// One page per call, called when an acknowledgement arrives, so the
    /// credit window paces the backend reads as well as the wire and the
    /// server holds one page at a time (R58 decision 9). Nothing is read while
    /// a frame is still queued, so a client that has fallen behind stops the
    /// producer rather than filling the queue behind it.
    async fn pump_page<T: Transport>(
        &self,
        transport: &mut T,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        if state.credits == 0 || !state.pending.is_empty() {
            return Ok(());
        }
        let Some(read) = state.paging.pop_front() else {
            return Ok(());
        };
        // An unsubscribe may have landed since the last page, and then there
        // is nothing left to deliver to.
        if !state.subs.contains_key(&read.label) {
            return Ok(());
        }
        let PagedRead {
            label,
            sub,
            reg,
            after,
            max_rows,
            limits,
            average_width,
            cursor,
            delivered,
            restarted,
            tier,
            permit,
        } = read;
        let outcome = self
            .snapshot_source
            .snapshot_page(
                &reg.pg_sql,
                &sub.spec.binds,
                &state.principal,
                &PageSpec {
                    after: Some(after),
                    max_rows,
                    timeout: limits.timeout,
                },
            )
            .await;
        let page = match outcome {
            Ok(page) => page,
            Err(err) => {
                return self
                    .restart_or_refuse(
                        transport,
                        state,
                        ReadStart {
                            sub,
                            reg,
                            tier,
                            permit,
                            restarted,
                        },
                        &err.to_string(),
                    )
                    .await;
            }
        };
        // A page above the ceiling is not a transient failure and a restart
        // would meet the same row, so this one ends the subscription.
        if admit_page(&label, &page, max_rows, average_width, limits).is_err() {
            return self.refuse_subscription(transport, state, &label).await;
        }
        // Size the next page from what this one measured rather than from the
        // prediction, which cannot see the true size of a value stored out of
        // line (R58).
        let measured = match page.rows {
            0 => average_width,
            rows => u32::try_from(page.bytes / u64::from(rows)).unwrap_or(u32::MAX),
        };
        let max_rows = page_rows(limits.page_bytes, measured);
        let carried = delivered.saturating_add(
            self.send_page(transport, state, &label, page.patchset)
                .await?,
        );
        match page.next {
            Some(after) => {
                state.paging.push_back(PagedRead {
                    label,
                    sub,
                    reg,
                    after,
                    max_rows,
                    limits,
                    average_width: measured,
                    cursor,
                    delivered: carried,
                    restarted,
                    tier,
                    permit,
                });
                Ok(())
            }
            None => {
                self.complete_snapshot(transport, state, label, cursor, carried)
                    .await
            }
        }
    }

    /// A page after the first failed. Read the whole subscription again once,
    /// and refuse it if that fails too (R58 decision 11).
    ///
    /// The replacement's own first page is read before the notice goes out, so
    /// nothing is discarded on a promise. A refusal leaves the pages already
    /// applied on the client covered by no subscription, which R29's retention
    /// pass evicts, so no partial set survives.
    async fn restart_or_refuse<T: Transport>(
        &self,
        transport: &mut T,
        state: &mut SessionState<Id, Key>,
        start: ReadStart,
        detail: &str,
    ) -> Result<(), SessionError> {
        let label = start.sub.sub_id.clone();
        if start.restarted {
            let _ = refuse_read(&label, &SubscribeRefusal::Interrupted(detail.to_owned()));
            return self.refuse_subscription(transport, state, &label).await;
        }
        tracing::warn!(
            sub_id = %label,
            error = %detail,
            "a page failed part way through a read, replacing the subscription"
        );
        let start = ReadStart {
            restarted: true,
            ..start
        };
        match self
            .snapshot_row(
                transport,
                state,
                start,
                Some(FullResyncReason::SnapshotInterrupted),
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(SessionError::Snapshot(detail) | SessionError::ReadRefused(detail)) => {
                let _ = refuse_read(&label, &SubscribeRefusal::Interrupted(detail));
                self.refuse_subscription(transport, state, &label).await
            }
            Err(other) => Err(other),
        }
    }

    /// Give up on one subscription: tear the registration down and answer with
    /// the one fixed phrase (R38).
    async fn refuse_subscription<T: Transport>(
        &self,
        transport: &mut T,
        state: &mut SessionState<Id, Key>,
        label: &str,
    ) -> Result<(), SessionError> {
        for (consumer_id, sub_id) in take_row_subscription(state, label) {
            self.remove_route(consumer_id).await;
            self.materializer.lock().await.unregister(sub_id);
        }
        transport
            .send_control(ControlMessage::NonFatalError(NonFatalError {
                related_to: Some(label.to_owned()),
                detail: SUBSCRIPTION_REFUSED.to_owned(),
            }))
            .await
            .map_err(transport_err)
    }

    /// Catch a resuming row subscription up from the oplog.
    ///
    /// Registers the route first, so live events for positions past the watermark
    /// queue behind the catchup (the run loop is blocked here until this
    /// returns, so nothing is delivered meanwhile), then replays each retained
    /// entry the subscription matches as a `LivePatch` carrying that entry's
    /// cursor, in the live-path format. Entries past the pre-catchup watermark
    /// are skipped because the live path will deliver them, so replay and live
    /// hold locally. The two-check form runs per client, so a row this caller may
    /// no longer see replays as the plain delete that takes it back, and a
    /// deleted row this caller could never see replays as nothing at all (R6).
    async fn catch_up_row<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState<Id, Key>,
        reg: &RowRegistration,
        from: PgCommitPosition,
        fence: Option<Arc<ReadFence>>,
    ) -> Result<(), SessionError> {
        self.attach_row_route(&sub, state, reg, fence.clone()).await;

        // Watermark just after the route exists. An entry at or below it was
        // appended before this consumer could receive live delivery, so
        // replaying it cannot duplicate a live patch.
        let ceiling = read_log::<O, _, _>(&mut state.resume_read_budget, || {
            self.oplog.current_position()
        })
        .await?;
        let entries = self.catchup_entries(state, from, fence.as_deref()).await?;
        // Retention only moves forward, so a log that still reaches the cursor now reached it when the entries were read.
        let min = read_log::<O, _, _>(&mut state.resume_read_budget, || self.oplog.min_position())
            .await?;
        if matches!(
            catchup_decision(from, min, ceiling),
            CatchupDecision::FullResync
        ) {
            return self
                .resnapshot_row(
                    transport,
                    state,
                    &sub.sub_id,
                    &FullResyncReason::CursorOutsideRetention,
                    None,
                )
                .await;
        }
        // One watcher, this session's caller, so the buffers hold one verdict
        // each and are reused across the whole replay.
        let watchers = [Arc::clone(&state.principal)];
        let mut verdicts = Transitions::new();
        for record in entries {
            if ceiling.is_none_or(|ceiling| record.position() > ceiling) {
                continue;
            }
            let matched = {
                self.materializer
                    .lock()
                    .await
                    .replay_match(record.event(), reg.consumer_id)?
            };
            let Some(departing) = matched else {
                continue;
            };
            // The `Some` above is what says this subscription reads the truncated
            // table. A truncate replays as a patchset with no operations, so
            // applying it would leave the emptied table populated exactly as the
            // live path used to (R48). Everything after it arrives again in the
            // replacement snapshot, so the rest of this replay is abandoned
            // rather than sent and then undone.
            if record.event().kind() == EventKind::Truncate {
                let reason = FullResyncReason::TableTruncated {
                    table: self.event_table(record.event()),
                };
                return self
                    .resnapshot_row(transport, state, &sub.sub_id, &reason, None)
                    .await;
            }
            let Some(payload) = self
                .replay_payload(transport, &record, departing, &watchers, &mut verdicts)
                .await?
            else {
                continue;
            };
            let cursor = self.stamp(record.position());
            let advanced = {
                self.materializer.lock().await.advance_cursor(
                    state.session_id.as_u64_key(),
                    reg.sub_id,
                    &cursor,
                )
            };
            match advanced {
                Ok(()) => {}
                // A live change dispatched since the route went up already moved the cursor past this entry, and its patch queues behind the replay.
                Err(MaterializerError::Cursor(AdvanceCursorError::NonMonotonic { .. })) => {
                    tracing::debug!(sub_id = %sub.sub_id, position = ?record.position(), "a live change already moved the cursor past this replayed entry");
                }
                Err(err) => return Err(err.into()),
            }
            let live = LivePatch::new(sub.sub_id.clone(), Cursor::new(cursor), payload);
            enqueue_and_flush(
                transport,
                &mut state.credits,
                &mut state.pending,
                Deliverable::Rows(BulkMessage::LivePatch(live)),
            )
            .await
            .map_err(transport_err)?;
        }
        enqueue_and_flush(
            transport,
            &mut state.credits,
            &mut state.pending,
            Deliverable::SnapshotComplete(SnapshotEnd {
                sub_id: sub.sub_id,
                cursor: Cursor::new(self.stamp(ceiling.unwrap_or(from))),
            }),
        )
        .await
        .map_err(transport_err)
    }

    /// The log's records a cursor at `from` resumes with, in commit order.
    ///
    /// A fenced cursor was issued by a snapshot, which misses the transactions it did not see below its read and holds some above it.
    async fn catchup_entries(
        &self,
        state: &mut SessionState<Id, Key>,
        from: PgCommitPosition,
        fence: Option<&ReadFence>,
    ) -> Result<Vec<ChangeRecord>, SessionError> {
        let mut entries = match fence {
            Some(fence) => {
                let unseen = fence.unseen();
                read_log::<O, _, _>(&mut state.resume_read_budget, || {
                    self.oplog.entries_of(&unseen)
                })
                .await?
                .into_iter()
                .filter(|record| {
                    record.position() <= from && fence.seen(record.position()) == Seen::Missed
                })
                .collect()
            }
            None => Vec::new(),
        };
        let since = read_log::<O, _, _>(&mut state.resume_read_budget, || {
            self.oplog.entries_since(from)
        })
        .await?;
        entries.extend(since.into_iter().filter(|record| {
            fence.is_none_or(|fence| fence.seen(record.position()) != Seen::Held)
        }));
        Ok(entries)
    }

    /// What one replayed record delivers to this caller, or [`None`] when it
    /// delivers nothing (R6, the two-check form on the catchup path).
    ///
    /// Asked before anything is built, so a record this caller may not see
    /// costs the visibility question and nothing else. A delivered record goes
    /// out as the patch logged with it, or as R44's marked departure notice
    /// when `departing` says the row left this subscription's window.
    ///
    /// # Errors
    ///
    /// [`SessionError::ChangeStreamUnusable`] when the stream cannot report the
    /// previous version at all, and [`SessionError::Materializer`] when the
    /// departure notice or the withdrawal cannot be folded.
    async fn replay_payload<T: Transport>(
        &self,
        transport: &mut T,
        record: &ChangeRecord,
        departing: bool,
        watchers: &[Arc<Principal<Id, Key>>],
        verdicts: &mut Transitions,
    ) -> Result<Option<Vec<u8>>, SessionError> {
        let event = record.event();
        // A truncate never reaches here: `catch_up_row` turns one into a
        // replacement before asking anything about it (R48).
        debug_assert_ne!(event.kind(), EventKind::Truncate);
        // Retry the authorization question on error instead of silently skipping
        // the record: a skip followed by delivering later records would advance
        // the cursor past this one, making it permanently unreplayable from the
        // oplog.
        let mut auth_attempt: u32 = 0;
        let mut paused = false;
        loop {
            match transitions(&self.auth, event, self.catalog.as_ref(), watchers, verdicts).await {
                Ok(()) => {
                    if paused {
                        let _ = transport
                            .send_control(ControlMessage::DeliveryResumed)
                            .await;
                    }
                    break;
                }
                // Not transient, so retrying it would replay one record for ever.
                // The live path refuses on the same condition and for the same
                // reason.
                Err(
                    err @ (TransitionError::IncompletePreviousImage
                    | TransitionError::UnknownTable
                    | TransitionError::NotARowEvent),
                ) => return Err(self.transition_refusal(event, err)),
                Err(TransitionError::Policy(err)) => {
                    auth_attempt = auth_attempt.saturating_add(1);
                    if !paused {
                        let _ = transport
                            .send_control(ControlMessage::DeliveryPaused {
                                cause: PauseCause::AuthServiceUnreachable,
                            })
                            .await;
                        paused = true;
                    }
                    let backoff = self.auth_retry.backoff(auth_attempt);
                    tracing::warn!(
                        attempt = auth_attempt,
                        backoff_ms = backoff.as_millis(),
                        error = %err,
                        "auth service unreachable during catchup replay, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                }
            }
        }
        self.ask_second_opinion(event, watchers, verdicts.get())
            .await;
        // R44's departure notice takes the same three-way answer as the live
        // path: still visible and out of the window keeps the marked notice, out
        // of reach becomes the plain delete, and never in reach becomes silence
        // (R6 decision 6).
        match verdicts.get().first().copied().unwrap_or_default() {
            Transition::Nothing => Ok(None),
            Transition::Deliver if departing => {
                let notice = { self.materializer.lock().await.departure_notice(event)? };
                Ok(Some(notice.unwrap_or_else(|| record.payload().to_vec())))
            }
            Transition::Deliver => Ok(Some(record.payload().to_vec())),
            // A replayed delete's own patch already is the withdrawal, as on the
            // live path, so only an update pays a second fold.
            Transition::Withdraw if event.kind() == EventKind::Delete => {
                Ok(Some(record.payload().to_vec()))
            }
            Transition::Withdraw => {
                let withdrawal = { self.materializer.lock().await.withdrawal_patch(event)? };
                let withdrawal = withdrawal.ok_or_else(|| {
                    MaterializerError::Emit(
                        "a replayed row has to be taken back from a caller and the event folded \
                         to no operation to take it back with"
                            .to_owned(),
                    )
                })?;
                Ok(Some(withdrawal))
            }
        }
    }

    /// Produce a computed subscription's first answer, deliver it, and route
    /// future changes.
    ///
    /// A fold's seed runs in the subscribing caller's own path through the
    /// session's connector, so it spends that caller's tier budget: a slow
    /// seed delays the caller who asked for it and nobody else (R81 decision
    /// 2). A read tier bootstraps through the engine's own connector under
    /// the shared re-execution bound, because that path holds the
    /// materializer lock.
    ///
    /// `resync` goes out once the answer exists and ahead of it, so a client
    /// replacing an answer drops the old one only for a new one.
    async fn subscribe_computed<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState<Id, Key>,
        capture: ComputedCapture,
        reads_subjects: bool,
        resync: Option<FullResyncReason>,
    ) -> Result<(), SessionError> {
        let subscription_id = capture.subscription_id;
        let changes = match self.first_answer(&capture, state).await {
            Ok(changes) => changes,
            Err(err) => {
                return self
                    .refuse_computed_subscribe(transport, sub.sub_id, subscription_id, &err)
                    .await;
            }
        };

        self.add_computed_route(
            subscription_id,
            AggRoute {
                label: sub.sub_id.clone(),
                tx: state.outbound.clone(),
            },
        )
        .await;
        if let Some(reason) = resync {
            transport
                .send_control(ControlMessage::FullResyncRequired(FullResyncRequired {
                    sub_id: sub.sub_id.clone(),
                    reason,
                }))
                .await
                .map_err(transport_err)?;
        }
        for change in changes {
            transport
                .send_control(ControlMessage::AggregateUpdate(AggregateUpdate {
                    sub_id: sub.sub_id.clone(),
                    group_key: change.group_key,
                    group_values_json: change.group_values_json,
                    result_json: change.result_json,
                    is_full_result: change.is_full_result,
                }))
                .await
                .map_err(transport_err)?;
        }
        let rebinds = capture.per_viewer || reads_subjects;
        state.computed_subs.insert(
            sub.sub_id.clone(),
            ComputedSub {
                id: subscription_id,
                sub,
                rebinds,
            },
        );
        Ok(())
    }

    /// Produce a computed subscription's first answer: a fold's seed or a
    /// scalar extreme's read through the session's connector under the
    /// caller's own tier (R81 decision 2), or the engine-driven bootstrap
    /// for the read tiers (with the demotion follow-up read when a fold's
    /// seed outgrew the budget).
    async fn first_answer(
        &self,
        capture: &ComputedCapture,
        state: &SessionState<Id, Key>,
    ) -> Result<Vec<ComputedChange>, String> {
        let subscription_id = capture.subscription_id;
        let caller_setup = || {
            crate::reexec::ConnettoReadSetup::of(ReadBudget::new(
                self.guard.read_limits(Tier::of(&state.principal)).timeout,
            ))
        };
        let bootstrap = match &capture.seed {
            SeedPlan::Snapshot => {
                return self
                    .bootstrap_computed(subscription_id, capture.consumer_id)
                    .await;
            }
            SeedPlan::Scalar { query, kind } => {
                for _ in 0..Self::SCALAR_READ_ATTEMPTS {
                    let (value, fence) = self
                        .connector
                        .execute_scalar(&query.as_read_query(), *kind, &caller_setup())
                        .await
                        .map_err(|err| err.to_string())?;
                    let installed = {
                        self.materializer
                            .lock()
                            .await
                            .install_scalar(subscription_id, value, fence)
                            .map_err(|err| err.to_string())?
                    };
                    if let Some(change) = installed {
                        return Ok(vec![change]);
                    }
                }
                return Err("changes the scalar reads missed kept removing their answer".to_owned());
            }
            SeedPlan::Fold { bootstrap } => bootstrap,
        };
        let setup = caller_setup();
        // The engine buffers changes dispatched while this read is in flight
        // and judges them against the read's fence, so registering before
        // reading neither loses a change nor counts one twice.
        let (rows, fence) = if bootstrap.group_columns == 0 {
            // One row of component columns under one snapshot.
            self.connector
                .execute_scalar_row(&bootstrap.query.as_read_query(), &bootstrap.kinds, &setup)
                .await
                .map(|(row, fence)| (vec![row], fence))
                .map_err(|err| err.to_string())?
        } else {
            // One row per group. One generous page: a grouped seed is bounded
            // by the engine's group budget, and a result past one page would
            // demote past it regardless, so the refusal arrives at
            // registration rather than as a torn seed.
            let page = self
                .connector
                .read_page(
                    &bootstrap.query.as_read_query(),
                    GROUPED_SEED_PAGE_BYTES,
                    &setup,
                )
                .await
                .map_err(|err| err.to_string())?;
            if page.value.more {
                return Err("the grouped seed exceeded one page".to_owned());
            }
            (page.value.rows, page.fence)
        };
        let seeded = {
            self.materializer
                .lock()
                .await
                .install_fold_seed(subscription_id, rows, fence)
                .map_err(|err| err.to_string())?
        };
        if seeded.needs_snapshot {
            // The seed itself demoted the subscription (its groups already
            // exceed the budget), so the first answer is the whole re-read
            // the transition asked for.
            return self
                .bootstrap_computed(subscription_id, capture.consumer_id)
                .await;
        }
        Ok(seeded.changes)
    }

    /// The engine-driven bootstrap, its error rendered for the refusal path.
    async fn bootstrap_computed(
        &self,
        subscription_id: SubscriptionId,
        consumer_id: u64,
    ) -> Result<Vec<ComputedChange>, String> {
        self.materializer
            .lock()
            .await
            .bootstrap_computed(subscription_id, consumer_id)
            .await
            .map_err(|err| err.to_string())
    }

    /// Roll back a computed registration whose first answer could not be
    /// produced, telling the caller only what every refusal tells it.
    async fn refuse_computed_subscribe<T: Transport, E: core::fmt::Display>(
        &self,
        transport: &mut T,
        sub_label: String,
        subscription_id: SubscriptionId,
        cause: &E,
    ) -> Result<(), SessionError> {
        tracing::warn!(sub_id = %sub_label, error = %cause, "computed bootstrap failed");
        self.materializer.lock().await.unregister(subscription_id);
        transport
            .send_control(ControlMessage::NonFatalError(NonFatalError {
                related_to: Some(sub_label),
                detail: SUBSCRIPTION_REFUSED.to_owned(),
            }))
            .await
            .map_err(transport_err)?;
        Ok(())
    }
}

/// Queue `msg` then drain what the credit window allows, preserving FIFO order.
async fn enqueue_and_flush<T: Transport>(
    transport: &mut T,
    credits: &mut u32,
    pending: &mut VecDeque<Deliverable>,
    msg: Deliverable,
) -> Result<(), T::Error> {
    pending.push_back(msg);
    flush(transport, credits, pending).await
}

/// Drain the outbound queue in order, stopping at the first bulk frame the
/// credit window cannot pay for.
///
/// A free item behind a bulk frame the window cannot afford stays queued, and
/// that is the point: it is queued precisely because it describes data the
/// client has not received.
async fn flush<T: Transport>(
    transport: &mut T,
    credits: &mut u32,
    pending: &mut VecDeque<Deliverable>,
) -> Result<(), T::Error> {
    loop {
        if *credits == 0 && pending.front().is_some_and(Deliverable::costs_credit) {
            return Ok(());
        }
        let Some(next) = pending.pop_front() else {
            return Ok(());
        };
        match next {
            Deliverable::Rows(msg) => {
                transport.send_bulk(msg).await?;
                *credits -= 1;
            }
            Deliverable::SnapshotComplete(end) => {
                transport
                    .send_control(ControlMessage::SnapshotEnd(end))
                    .await?;
            }
        }
    }
}

#[cfg(test)]
mod rebootstrap_tests;

#[cfg(test)]
mod tests {
    use connetto_core::SessionId;
    use connetto_core::auth::{
        AuthContext, CapabilitySubject, Principal, Subject, VerifiedSession,
    };
    use subql::backend::{ScalarFamily, Value as PgValue};

    use super::{
        GrantHolder, MemberTable, MirrorGap, Resume, SubscribeRefusal, attempt_limit_reached,
        caller_subjects, concerns, mirror_predicate, page_rows,
    };
    use crate::timeline::{Position, TimelineHistory};
    use connetto_core::Cursor;
    use subql::{PgCommitPosition, PgLsn, PgXid};

    fn judged(cursor: &[u8], history: &TimelineHistory) -> Resume {
        Resume::of(Some(&Cursor::new(cursor.to_vec())), history)
    }

    /// The cluster the histories here belong to.
    const CLUSTER: u64 = 42;

    /// A row at commit `lsn`.
    fn row(lsn: u64) -> PgCommitPosition {
        PgCommitPosition::new(PgLsn(lsn), PgXid(1), 1)
    }

    fn at(timeline: u32, lsn: u64) -> Vec<u8> {
        Position {
            system: CLUSTER,
            timeline,
            at: row(lsn),
        }
        .to_cursor_bytes()
    }

    /// Timeline 3, whose history ended timeline 1 at 0x100 and timeline 2 at 0x200.
    fn twice_promoted() -> TimelineHistory {
        TimelineHistory::parse(CLUSTER, 3, "1\t0/100\tr\n2\t0/200\tr\n").expect("parse")
    }

    #[test]
    fn a_cursor_resumes_only_while_the_history_holds_its_position() {
        let history = twice_promoted();
        assert_eq!(
            judged(&at(3, 0x900), &history),
            Resume::At(row(0x900), None)
        );
        assert_eq!(
            judged(&at(2, 0x1FF), &history),
            Resume::At(row(0x1FF), None)
        );
        assert_eq!(
            judged(&at(2, 0x200), &history),
            Resume::BeyondHistory,
            "a commit starting at the switchpoint is on the new timeline's side"
        );
        assert_eq!(judged(&at(1, 0x101), &history), Resume::BeyondHistory);
        assert_eq!(
            judged(&at(4, 0x10), &history),
            Resume::BeyondHistory,
            "a timeline this history never had, an old primary brought back"
        );
    }

    /// A dump restored into another cluster starts again at timeline 1, so only the identifier tells its cursors apart.
    #[test]
    fn a_cursor_from_another_cluster_resyncs() {
        let restored = TimelineHistory::first(CLUSTER + 1);
        assert_eq!(judged(&at(1, 0x10), &restored), Resume::BeyondHistory);
        assert_eq!(
            judged(&at(1, 0x10), &TimelineHistory::first(CLUSTER)),
            Resume::At(row(0x10), None)
        );
    }

    #[test]
    fn no_position_is_a_fresh_start_whatever_the_history() {
        let history = twice_promoted();
        assert_eq!(Resume::of(None, &history), Resume::Fresh);
        assert_eq!(judged(&[], &history), Resume::Fresh);
        assert_eq!(judged(&at(1, 0), &history), Resume::Fresh);
    }

    /// A client holding rows presents a cursor, so one the server cannot read
    /// must resync with the notice that clears them, not a plain snapshot.
    #[test]
    fn a_cursor_the_server_cannot_read_resyncs_with_a_clear() {
        let history = twice_promoted();
        assert_eq!(
            judged(&0x150_u64.to_be_bytes(), &history),
            Resume::BeyondHistory,
            "the layout without a timeline"
        );
        let timeline_only = [&3_u32.to_be_bytes()[..], &0x150_u64.to_be_bytes()].concat();
        assert_eq!(
            judged(&timeline_only, &history),
            Resume::BeyondHistory,
            "the layout without a cluster"
        );
        assert_eq!(judged(&[1, 2, 3], &history), Resume::BeyondHistory);
    }

    /// A membership table watched under the given caller kinds.
    fn watched(identity: bool, subjects: bool) -> MemberTable {
        MemberTable {
            table: "team_members".to_owned(),
            subject: "member".to_owned(),
            identity,
            subjects,
        }
    }

    /// One mirror serves a table two terms watch under different caller
    /// kinds, because the mirror is keyed by table and opened once. Dropping
    /// either reach would leave that kind's membership moves undelivered
    /// with nothing reported.
    #[test]
    fn a_table_watched_under_both_caller_kinds_mirrors_under_both() {
        let predicate =
            mirror_predicate(&watched(true, true), Some("caller"), Some("subjects"), ',')
                .expect("both mappings are bound");
        let (identity, set) = predicate.split_once(" OR ").expect("both reaches, joined");
        assert_eq!(identity, "\"member\" = caller()");
        assert!(
            set.contains("subjects()") && set.contains("instr("),
            "the set reach is the guarded search, got {set}"
        );
    }

    /// A term reading a set the deployment binds no function for is a
    /// server-side defect, and it is named rather than mirrored as an
    /// identity comparison that would admit the wrong rows.
    #[test]
    fn a_set_term_without_its_mapping_names_the_gap() {
        assert_eq!(
            mirror_predicate(&watched(false, true), Some("caller"), None, ','),
            Err(MirrorGap::Subjects)
        );
        assert_eq!(
            mirror_predicate(&watched(true, false), None, Some("subjects"), ','),
            Err(MirrorGap::Identity)
        );
    }

    /// The identity half of a caller, as a handshake resolves it.
    fn identity(user: &str) -> AuthContext<String> {
        AuthContext::new(user.to_owned())
    }

    /// A caller is a set, so every key it holds is seeded beside the
    /// identity. A membership row naming a key admits rows in the database,
    /// and a seed that named the identity alone would admit fewer.
    #[test]
    fn a_caller_is_its_identity_and_every_key_it_holds() {
        let keys = [
            CapabilitySubject::<String>::new("key:a"),
            CapabilitySubject::<String>::new("key:b"),
        ];
        let subjects = caller_subjects(Some(&identity("alice")), &keys, ScalarFamily::String)
            .expect("a text subject column takes any of them");
        assert_eq!(
            subjects,
            vec![
                PgValue::String("alice".to_owned()),
                PgValue::String("key:a".to_owned()),
                PgValue::String("key:b".to_owned()),
            ]
        );
    }

    /// A key the subject column cannot hold refuses the registration. Dropping
    /// it would register a subscription admitting fewer rows than the query
    /// the caller sent returns, and no later membership change repairs that.
    #[test]
    fn a_key_the_subject_column_cannot_hold_refuses_rather_than_being_dropped() {
        let keys = [CapabilitySubject::<String>::new("key:a")];
        let refusal = caller_subjects(
            Some(&identity("0193c8e5-1111-7abc-8def-000000000000")),
            &keys,
            ScalarFamily::Uuid,
        )
        .expect_err("the identity reads as a uuid and the key cannot");
        assert!(matches!(refusal, SubscribeRefusal::Mistyped), "{refusal}");
    }

    /// A page's rows come from a byte budget divided by the width Postgres
    /// predicts, so a table of wide rows pages smaller under the same budget.
    #[test]
    fn a_page_is_sized_from_the_budget_and_the_width() {
        assert_eq!(page_rows(8192, 64), 128);
        assert!(
            page_rows(8192, 4096) < page_rows(8192, 64),
            "wide rows page smaller under one budget"
        );
    }

    /// A page cannot be smaller than one row, which is why a ceiling on one row
    /// exists beside the budget, and an unpredicted width caps on rows alone.
    #[test]
    fn a_page_always_carries_at_least_one_row() {
        assert_eq!(page_rows(8192, 100_000), 1);
        assert_eq!(page_rows(8192, 0), 8192);
    }

    /// A caller holding keys, an identity, or both, as a handshake leaves it.
    fn caller(user: Option<&str>, keys: &[&str]) -> Principal {
        let handle = SessionId::from_token_hash(user.unwrap_or("anonymous"));
        let mut principal = Principal::unidentified(handle);
        if let Some(user) = user {
            principal
                .accept(Subject::Identity(VerifiedSession {
                    context: AuthContext::new(user),
                    session_id: handle,
                    bot_list: None,
                }))
                .expect("one identity");
        }
        for key in keys {
            principal
                .accept(Subject::Capability(CapabilitySubject::new(*key)))
                .expect("a capability always folds in");
        }
        principal
    }

    /// **The narrowing's second half.** A move naming one key reaches the
    /// session holding that key, and no other.
    ///
    /// The negative halves are the load-bearing ones. A caller holding a
    /// different key, and a caller holding none, both already pass the wide
    /// behaviour, so only their exclusion proves the narrowing.
    #[test]
    fn a_keyed_move_concerns_the_bearer_alone() {
        let holder = GrantHolder::Subject("key:a".to_owned());
        assert!(
            concerns(&caller(None, &["key:a"]), &holder),
            "the session holding the key lost or gained the access, so it has \
             to replace what it holds"
        );
        assert!(
            !concerns(&caller(None, &["key:b"]), &holder),
            "another bearer's access did not change, and a replacement there \
             re-reads a set that is unaltered"
        );
        assert!(
            !concerns(&caller(Some("alice"), &[]), &holder),
            "a caller holding no key is granted by no key"
        );
    }

    /// A move naming a person still reaches that person alone.
    #[test]
    fn a_person_move_concerns_that_person_alone() {
        let holder = GrantHolder::Person("alice".to_owned());
        assert!(concerns(&caller(Some("alice"), &[]), &holder));
        assert!(
            !concerns(&caller(Some("bob"), &[]), &holder),
            "one person's grant says nothing about another's"
        );
        assert!(
            !concerns(&caller(None, &["key:a"]), &holder),
            "a key is not a person, so an identity move leaves it alone"
        );
    }

    /// A wildcard carrying nothing still reaches every subscriber, which is
    /// what keeps the unnarrowable case safe.
    #[test]
    fn an_everybody_move_concerns_every_caller() {
        let holder = GrantHolder::Everybody;
        assert!(concerns(&caller(Some("alice"), &[]), &holder));
        assert!(concerns(&caller(None, &["key:a"]), &holder));
        assert!(concerns(&caller(None, &[]), &holder));
    }

    /// The failed connect that opened the episode is itself one of the
    /// attempts, so a capped policy stops on the nth failure and an uncapped
    /// one never does.
    #[test]
    fn a_capped_policy_stops_on_the_nth_failure() {
        assert!(!attempt_limit_reached(None, u32::MAX));
        assert!(attempt_limit_reached(Some(1), 1));
        assert!(!attempt_limit_reached(Some(3), 2));
        assert!(attempt_limit_reached(Some(3), 3));
    }

    /// A refused registration's tally key dies with its connection, on every
    /// exit the gate takes.
    #[tokio::test]
    async fn a_refused_registration_retires_its_gate_tally_key() {
        use super::{Materializer, RequestGuard, RuntimeWritableCatalog};
        use crate::abuse::Signal;
        use crate::defaults::ConnettoDefaults;
        use crate::{ManagerBuilder, PgReadConnector, PgSnapshotSource, pg_write_target};
        use connetto_core::loopback;
        use connetto_core::messages::{ControlMessage, RegisterBot};
        use connetto_core::test_support::TestGrantChecker;
        use connetto_core::traits::{IncomingFrame, Transport};
        use connetto_test_harness::RosterAuth;
        use diesel_async::AsyncPgConnection;
        use diesel_async::pooled_connection::AsyncDieselConnectionManager;
        use diesel_async::pooled_connection::bb8::Pool;

        use std::sync::Arc;
        const DDL: &str = "CREATE TABLE orders (id INT PRIMARY KEY, label TEXT);";
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(
            "postgres://nobody@127.0.0.1:9/none".to_owned(),
        );
        let pool = Pool::builder()
            .max_size(1)
            .build(manager)
            .await
            .expect("the pool builds even though it connects nowhere");
        let guard = Arc::new(RequestGuard::default());
        let manager = ManagerBuilder::new(
            Materializer::builder(DDL)
                .with_write_catalog(RuntimeWritableCatalog::default())
                .with_read_connector(PgReadConnector::with_session_setup(pool.clone()))
                .build()
                .expect("build the materializer"),
            PgSnapshotSource::from_ddl(pool.clone(), DDL).expect("the snapshot source"),
            RosterAuth::granting_nobody(),
            Arc::new(TestGrantChecker),
            PgReadConnector::with_session_setup(pool.clone()),
            pg_write_target::<ConnettoDefaults>(pool, DDL).expect("build the write target"),
        )
        .with_guard(guard.clone())
        .build();

        let (server_end, mut client) = loopback();
        let serving = Arc::clone(&manager);
        let serving_task = tokio::spawn(async move {
            let _ = serving.serve(server_end).await;
        });
        assert!(
            matches!(
                client.recv().await.expect("recv the opening frame"),
                Some(IncomingFrame::Control(ControlMessage::Challenge(_)))
            ),
            "the connection opens with a challenge"
        );
        client
            .send_control(ControlMessage::RegisterBot(RegisterBot {
                code: "no-such-code".to_owned(),
                name: "bot-a".to_owned(),
                public_key: [0; 32],
                list: vec![],
                signature: vec![],
            }))
            .await
            .expect("send the registration");
        let control = match client.recv().await.expect("recv the answer") {
            Some(IncomingFrame::Control(control)) => control,
            frame => panic!("expected the refusal frame, the connection ended: {frame:?}"),
        };
        assert!(
            matches!(control, ControlMessage::RegistrationRefused),
            "an unknown code is refused"
        );
        assert_eq!(
            guard.tracked_connections(Signal::RefusedGrant),
            1,
            "the gate's key is tracked while the connection is open"
        );
        client.close().await.expect("the peer hangs up");
        serving_task.await.expect("serve ends with the peer");
        assert_eq!(
            guard.tracked_connections(Signal::RefusedGrant),
            0,
            "the gate's key dies with the connection"
        );
    }
}
