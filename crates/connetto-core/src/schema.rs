//! Schema identity shared between client and server.
//!
//! Two values identify a schema. The [`Major`] is the application schema
//! major its source declares, the number a handshake is routed and refused
//! by and the number a replica and its device-private tier record. The
//! [`SchemaVersion`] is a content hash of the whole build artifact, which
//! catches the same major built from a different schema.
//!
//! A [`SchemaVersion`] always holds a real content hash. The absence of a
//! declared version is modeled out of band, as `Option<SchemaVersion>` on the
//! config and ack boundaries, never as an empty hash. There is deliberately no
//! `Default`: a fabricated empty hash is not a hash, and an in-band sentinel is
//! exactly what let a stale-check bug slip through. Staleness is checked only
//! when both sides declare a version (both `Some`).
//!
//! The one build artifact a schema produces is the [`SchemaBundle`]: the two
//! Postgres source documents, the translated replica DDL they produce under
//! connetto's fixed translation options, the policy table pairs, the policy
//! views, and an optional translated local tier. Its `version()` hashes the
//! whole bundle, so a client and its server that translate the same sources
//! with the same pg2sqlite agree bit-for-bit, and a different pg2sqlite
//! revision, which emits a different replica DDL for the same sources, reads
//! as an outdated build. Its `major()` is read from the schema source, so it
//! cannot drift from the document it describes.
//!
//! [`HandshakeAck`]: crate::messages::HandshakeAck

use core::fmt;
use core::num::NonZeroU32;

use serde::{Deserialize, Serialize};

/// The replica's local name for `current_setting('app.user_id')`, which the
/// identity arm of every deployment policy compares against.
pub const CALLER_FUNCTION: &str = "current_app_user";

/// The replica's local name for `current_setting('app.subjects')`, which the
/// membership arm of a policy searches.
///
/// A caller holding no key answers NULL, and the translated search is NULL
/// with it, so that arm admits nothing rather than everything.
pub const SUBJECTS_FUNCTION: &str = "current_app_subjects";
/// The session setting connetto binds on every caller's connection with the
/// bot's effective list, its `table:verb` entries joined by
/// [`BOT_LIST_SEPARATOR`], which the generated cap policy of every synced
/// table compares.
pub const BOT_LIST_SETTING: &str = "app.bot_list";

/// The replica's local name for `current_setting('app.bot_list')`, which the
/// generated cap policy of every synced table searches.
///
/// A connection carrying no list answers `NULL`-like nothing to the search,
/// so it fails closed and sees or writes nothing, which is why every
/// person's connection carries [`BOT_LIST_WILDCARD`] instead.
pub const BOT_LIST_FUNCTION: &str = "current_bot_list";

/// The separator a bot list packs its `table:verb` entries with.
pub const BOT_LIST_SEPARATOR: char = ',';

/// The comment a schema source declares its major with, alone on its line
/// and followed by the number, as in `-- connetto:major 3`.
pub const MAJOR_DIRECTIVE: &str = "-- connetto:major";

/// An application schema major, the number every incompatible schema change
/// increments. Majors start at 1.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Major(NonZeroU32);

impl Major {
    /// The major `value`, or `None` for 0, which no schema declares.
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        match NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// The number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    /// The major `source` declares through [`MAJOR_DIRECTIVE`].
    ///
    /// # Errors
    ///
    /// [`MajorError::Missing`] when no line carries the directive,
    /// [`MajorError::Repeated`] when more than one does, and
    /// [`MajorError::Invalid`] when its value is not a number from 1 up.
    pub fn declared_in(source: &str) -> Result<Self, MajorError> {
        let mut values = source
            .lines()
            .filter_map(|line| line.trim().strip_prefix(MAJOR_DIRECTIVE));
        let value = values.next().ok_or(MajorError::Missing)?;
        if values.next().is_some() {
            return Err(MajorError::Repeated);
        }
        let value = value.trim();
        value
            .parse::<u32>()
            .ok()
            .and_then(Self::new)
            .ok_or_else(|| MajorError::Invalid(value.to_owned()))
    }
}

impl fmt::Display for Major {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for Major {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Major({})", self.0)
    }
}

/// Why a schema source does not declare a usable major.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MajorError {
    /// No line carries [`MAJOR_DIRECTIVE`].
    #[error("the schema source declares no major, add a `{MAJOR_DIRECTIVE} N` line")]
    Missing,
    /// More than one line carries it.
    #[error("the schema source declares its major more than once")]
    Repeated,
    /// The value is not a number from 1 up.
    #[error("the schema source declares major {0:?}, which is not a number from 1 up")]
    Invalid(String),
}

/// The list entry every person's connection carries, which every generated
/// cap policy admits, so a person is held to its own rules alone.
pub const BOT_LIST_WILDCARD: &str = "*";

/// The name the translated DDL calls for a client-authored UUID primary key,
/// which the application registers on every replica connection it opens.
pub const UUID_FUNCTION: &str = "uuidv4";

/// The table the RLS translation's monitoring triggers write violations to.
pub const AUDIT_TABLE: &str = "rls_audit";

/// The SQLite function connetto registers on every replica connection and
/// holds true only while applying its own writes, so the translation's
/// fail-closed guards admit server data and refuse the application's direct
/// writes to the backing tables.
pub const WRITE_EXEMPTION_FUNCTION: &str = "connetto_write_exempt";

/// The domain tag every bundle hash starts with, so a bundle hash can never
/// collide with a [`schema_hash`] of the same bytes.
const BUNDLE_DOMAIN_TAG: &str = "connetto-schema-bundle-v1\0";

/// The one build artifact a schema produces, held identically by the server
/// (derived at boot from its Postgres sources) and by an application build
/// (translated at build time from the same sources).
///
/// It holds the two Postgres source documents, the translated replica DDL
/// they produce, the policy table pairs the translation split, the policy
/// views the translation emitted, and an optional translated local tier.
/// The local tier is a separate database, attached under its own schema on a
/// replica, so it is not part of the synced shape the version covers and
/// changing it does not change the version.
///
/// The version is always the hash of these contents, computed by
/// [`version`](SchemaBundle::version), and there is no other way to obtain
/// the version of a bundle. A bundle cannot be given a version, so the DDL an
/// application applies and the version it presents cannot drift apart. The
/// [`major`](SchemaBundle::major) is read from the schema source the same
/// way, so it sits inside the version too.
#[derive(Clone)]
pub struct SchemaBundle {
    schema_source: String,
    policies_source: String,
    replica_ddl: String,
    policy_tables: Vec<(String, String)>,
    policy_views: Vec<String>,
    local_tier_ddl: Option<String>,
    major: Major,
    tier_history: TierHistory,
}

/// The generated structural step of one local-tier boundary, from the major
/// it starts at to the next (R31).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TierBoundary {
    from: Major,
    sql: String,
}

impl TierBoundary {
    /// The step from `from` to the next major, as the SQL the build generated.
    #[must_use]
    pub fn new(from: Major, sql: impl Into<String>) -> Self {
        Self {
            from,
            sql: sql.into(),
        }
    }

    /// The major the step starts at.
    #[must_use]
    pub const fn from(&self) -> Major {
        self.from
    }

    /// The generated SQL, run against the tier alone.
    #[must_use]
    pub fn sql(&self) -> &str {
        &self.sql
    }
}

/// What a build knows about its local tier's past (R31): the oldest major it
/// exported, the first major whose export had a tier, and the generated step
/// of every boundary from the oldest up to the build's own major.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TierHistory {
    oldest: Major,
    first_with_tier: Option<Major>,
    boundaries: Vec<TierBoundary>,
}

impl TierHistory {
    /// A history starting at `oldest`, whose first tier appeared at
    /// `first_with_tier`, with `boundaries` in ascending order.
    #[must_use]
    pub const fn new(
        oldest: Major,
        first_with_tier: Option<Major>,
        boundaries: Vec<TierBoundary>,
    ) -> Self {
        Self {
            oldest,
            first_with_tier,
            boundaries,
        }
    }

    /// The oldest major a tier can be migrated from.
    #[must_use]
    pub const fn oldest(&self) -> Major {
        self.oldest
    }

    /// The first major whose build had a tier, `None` while none has.
    #[must_use]
    pub const fn first_with_tier(&self) -> Option<Major> {
        self.first_with_tier
    }

    /// The generated steps, oldest boundary first.
    #[must_use]
    pub fn boundaries(&self) -> &[TierBoundary] {
        &self.boundaries
    }

    /// Check that the boundaries run one by one from the oldest major to
    /// `build`, and that the first tier is no later than `build`.
    fn check_reaches(&self, build: Major) -> Result<(), TierHistoryError> {
        let mut next = self.oldest.get();
        for boundary in &self.boundaries {
            if boundary.from.get() != next {
                return Err(TierHistoryError::Gap {
                    expected: next,
                    found: boundary.from,
                });
            }
            next += 1;
        }
        if next != build.get() {
            return Err(TierHistoryError::Short {
                reached: next,
                build,
            });
        }
        match self.first_with_tier {
            Some(first) if first < self.oldest || first > build => {
                Err(TierHistoryError::FirstTierOutside { first, build })
            }
            _ => Ok(()),
        }
    }
}

/// Why a tier history does not fit the bundle it was given to.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TierHistoryError {
    /// A boundary is missing between two others.
    #[error("the tier history jumps to major {found}, expected a boundary from {expected}")]
    Gap {
        /// The major the next boundary had to start at.
        expected: u32,
        /// The major it started at.
        found: Major,
    },
    /// The boundaries stop short of the build's major, or run past it.
    #[error("the tier history reaches major {reached}, the build is major {build}")]
    Short {
        /// The major the last boundary reaches.
        reached: u32,
        /// The build's major.
        build: Major,
    },
    /// The first major with a tier lies outside the history.
    #[error(
        "the tier history says the tier first appeared at major {first}, outside the history up to {build}"
    )]
    FirstTierOutside {
        /// The first major with a tier.
        first: Major,
        /// The build's major.
        build: Major,
    },
}

impl SchemaBundle {
    /// Build a bundle from its contents, in the one place the contents are
    /// authoritative, the build step that translated them or a test.
    ///
    /// `policy_tables` are the `(logical, physical)` pairs the translation
    /// split, `policy_views` every view it emitted, and `local_tier_ddl` the
    /// translated local tier, when the build has one. Order of the pairs and
    /// views does not matter, the hash sorts them.
    ///
    /// # Errors
    ///
    /// The [`MajorError`] when `schema_source` does not declare its major
    /// through [`MAJOR_DIRECTIVE`].
    pub fn new<S, P, D, T, TL, TP, V, VN, L>(
        schema_source: S,
        policies_source: P,
        replica_ddl: D,
        policy_tables: T,
        policy_views: V,
        local_tier_ddl: Option<L>,
    ) -> Result<Self, MajorError>
    where
        S: Into<String>,
        P: Into<String>,
        D: Into<String>,
        T: IntoIterator<Item = (TL, TP)>,
        TL: Into<String>,
        TP: Into<String>,
        V: IntoIterator<Item = VN>,
        VN: Into<String>,
        L: Into<String>,
    {
        let schema_source = schema_source.into();
        let major = Major::declared_in(&schema_source)?;
        let local_tier_ddl: Option<String> = local_tier_ddl.map(Into::into);
        Ok(Self {
            schema_source,
            policies_source: policies_source.into(),
            replica_ddl: replica_ddl.into(),
            policy_tables: policy_tables
                .into_iter()
                .map(|(logical, physical)| (logical.into(), physical.into()))
                .collect(),
            policy_views: policy_views.into_iter().map(Into::into).collect(),
            tier_history: TierHistory::new(
                major,
                local_tier_ddl.is_some().then_some(major),
                Vec::new(),
            ),
            local_tier_ddl,
            major,
        })
    }

    /// The application schema major the schema source declares.
    #[must_use]
    pub const fn major(&self) -> Major {
        self.major
    }

    /// Return a copy of this bundle with its translated local tier, for the
    /// build step that translates the synced tier and the local tier as two
    /// separate reference universes. The version is unaffected, since the
    /// local tier is not part of the synced shape it covers. A bundle given a
    /// tier and no history records its own major as the first with a tier.
    #[must_use]
    pub fn with_local_tier(mut self, local_tier_ddl: impl Into<String>) -> Self {
        self.local_tier_ddl = Some(local_tier_ddl.into());
        if self.tier_history.first_with_tier.is_none() {
            self.tier_history.first_with_tier = Some(self.major);
        }
        self
    }

    /// Return a copy of this bundle carrying the local tier's history, the
    /// generated structural step of every boundary from the oldest exported
    /// major up to this bundle's (R31).
    ///
    /// # Errors
    ///
    /// [`TierHistoryError`] when the boundaries are not consecutive from the
    /// history's oldest major to this bundle's, or when the history names a
    /// first major with a tier that this bundle, which has a tier, cannot
    /// have reached.
    pub fn with_tier_history(mut self, history: TierHistory) -> Result<Self, TierHistoryError> {
        history.check_reaches(self.major)?;
        self.tier_history = history;
        Ok(self)
    }

    /// The local tier's history this build carries.
    #[must_use]
    pub const fn tier_history(&self) -> &TierHistory {
        &self.tier_history
    }

    /// The Postgres schema source document, as this bundle holds it.
    #[must_use]
    pub fn schema_source(&self) -> &str {
        &self.schema_source
    }

    /// The Postgres policy source document, as this bundle holds it.
    #[must_use]
    pub fn policies_source(&self) -> &str {
        &self.policies_source
    }

    /// The translated replica DDL, the SQLite document a client applies when
    /// it opens a fresh replica.
    #[must_use]
    pub fn replica_ddl(&self) -> &str {
        &self.replica_ddl
    }

    /// The `(logical, physical)` pairs the translation split, the map a
    /// client rewrites its wire names through at its sync boundaries.
    #[must_use]
    pub fn policy_tables(&self) -> &[(String, String)] {
        &self.policy_tables
    }

    /// Every view the translation emitted, which the replica's own catalogue
    /// is checked against at open.
    #[must_use]
    pub fn policy_views(&self) -> &[String] {
        &self.policy_views
    }

    /// The translated local tier, when the build has one. It is not part of
    /// the synced shape the version covers.
    #[must_use]
    pub fn local_tier_ddl(&self) -> Option<&str> {
        self.local_tier_ddl.as_deref()
    }

    /// The schema version this bundle presents at handshake.
    ///
    /// SHA-256 over the domain tag, then each field length-prefixed with its
    /// byte length as a big-endian `u64` and followed by its bytes, in a
    /// fixed order:
    ///
    /// 1. the schema source, with CRLF normalized to LF,
    /// 2. the policies source, normalized the same way,
    /// 3. the replica DDL, normalized the same way,
    /// 4. the policy pairs, lowercased and sorted, each as logical then
    ///    physical, joined with NULs,
    /// 5. the policy views, lowercased and sorted, joined with NULs,
    /// 6. [`CALLER_FUNCTION`],
    /// 7. [`SUBJECTS_FUNCTION`].
    ///
    /// The length prefixes are what keep the encoding unambiguous under
    /// concatenation, so one field gaining the text another lost cannot keep
    /// the hash put. Line endings are normalized so a CRLF vs LF checkout
    /// difference does not force a spurious reload. Nothing else is, so any
    /// real edit changes the hash. The pair and view names are lowercased the
    /// same way the client's policy map holds them, so a document rewritten
    /// in case alone reads as the same schema.
    #[must_use]
    pub fn version(&self) -> SchemaVersion {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(BUNDLE_DOMAIN_TAG.as_bytes());
        let pairs = pairs_field(&self.policy_tables);
        let views = views_field(&self.policy_views);
        for field in [
            self.schema_source.replace("\r\n", "\n").as_str(),
            self.policies_source.replace("\r\n", "\n").as_str(),
            self.replica_ddl.replace("\r\n", "\n").as_str(),
            pairs.as_str(),
            views.as_str(),
            CALLER_FUNCTION,
            SUBJECTS_FUNCTION,
        ] {
            field_into(&mut hasher, field);
        }
        SchemaVersion::from_hash(hasher.finalize().to_vec())
    }
}

impl fmt::Debug for SchemaBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchemaBundle")
            .field("major", &self.major)
            .field("version", &self.version())
            .field("policy_tables", &self.policy_tables)
            .field("policy_views", &self.policy_views)
            .finish_non_exhaustive()
    }
}

/// Hash one length-prefixed field into `hasher`, its byte length as a
/// big-endian `u64` and then its bytes.
fn field_into(hasher: &mut sha2::Sha256, field: &str) {
    use sha2::Digest;
    let len: u64 = field
        .len()
        .try_into()
        .expect("a schema document longer than u64::MAX bytes does not fit in any address space");
    hasher.update(len.to_be_bytes());
    hasher.update(field.as_bytes());
}

/// The policy pairs as one hash field, lowercased, sorted, logical then
/// physical per pair, and NUL-joined.
fn pairs_field(pairs: &[(String, String)]) -> String {
    let mut lowered: Vec<(String, String)> = pairs
        .iter()
        .map(|(logical, physical)| (logical.to_lowercase(), physical.to_lowercase()))
        .collect();
    lowered.sort_unstable();
    lowered
        .iter()
        .flat_map(|(logical, physical)| [logical.as_str(), physical.as_str()])
        .collect::<Vec<_>>()
        .join("\u{0}")
}

/// The policy views as one hash field, lowercased, sorted and NUL-joined.
fn views_field(views: &[String]) -> String {
    let mut lowered: Vec<String> = views.iter().map(|view| view.to_lowercase()).collect();
    lowered.sort_unstable();
    lowered.join("\u{0}")
}

/// Content hash identifying a schema, the authoritative equality signal shared
/// between client and server. Two schemas are interchangeable iff their hashes
/// match. It renders as a short hex prefix for humans, since the hash itself is
/// the identity. Absence of a version is `Option::None` at the boundaries, not
/// a value of this type.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SchemaVersion(#[serde(with = "serde_bytes")] Vec<u8>);

impl SchemaVersion {
    /// Build a schema version from a precomputed content hash.
    pub fn from_hash(hash: impl Into<Vec<u8>>) -> Self {
        Self(hash.into())
    }

    /// The content hash bytes.
    #[inline]
    pub fn hash(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for SchemaVersion {
    /// A short hex prefix, enough to identify a build in a log or error.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("none");
        }
        for byte in self.0.iter().take(6) {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SchemaVersion({self})")
    }
}

/// Deterministic content hash of a schema source document, shared by the server
/// (over its Postgres DDL) and an app build (over the same source), so two
/// builds of one schema agree bit-for-bit. Line endings are normalized so a
/// CRLF vs LF checkout difference does not force a spurious reload. Nothing else
/// is normalized, so any real edit changes the hash.
#[must_use]
pub fn schema_hash(source: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let normalized = source.replace("\r\n", "\n");
    Sha256::digest(normalized.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_major_is_read_from_its_directive_line() {
        let source = "CREATE TABLE a (id INT);\n  -- connetto:major 3  \nCREATE TABLE b (id INT);";
        assert_eq!(Major::declared_in(source).map(Major::get), Ok(3));
    }

    #[test]
    fn a_source_without_the_directive_declares_no_major() {
        assert_eq!(
            Major::declared_in("CREATE TABLE a (id INT); -- a comment"),
            Err(MajorError::Missing)
        );
    }

    fn major(value: u32) -> Major {
        Major::new(value).expect("a test major is from 1 up")
    }

    fn at_major(value: u32) -> SchemaBundle {
        SchemaBundle::new(
            format!("{MAJOR_DIRECTIVE} {value}"),
            "",
            "",
            NO_TABLES.iter().copied(),
            NO_VIEWS.iter().copied(),
            Some("CREATE TABLE notes (id INTEGER PRIMARY KEY)"),
        )
        .expect("the source declares its major")
    }

    #[test]
    fn a_tier_history_must_run_one_boundary_at_a_time_up_to_the_build() {
        let boundary = |from| TierBoundary::new(major(from), "");
        let whole = TierHistory::new(major(1), Some(major(1)), vec![boundary(1), boundary(2)]);
        assert!(at_major(3).with_tier_history(whole).is_ok());

        let gap = TierHistory::new(major(1), Some(major(1)), vec![boundary(1), boundary(3)]);
        assert_eq!(
            at_major(4).with_tier_history(gap).err(),
            Some(TierHistoryError::Gap {
                expected: 2,
                found: major(3)
            })
        );

        let short = TierHistory::new(major(1), Some(major(1)), vec![boundary(1)]);
        assert_eq!(
            at_major(3).with_tier_history(short).err(),
            Some(TierHistoryError::Short {
                reached: 2,
                build: major(3)
            })
        );

        let late = TierHistory::new(major(1), Some(major(4)), vec![boundary(1), boundary(2)]);
        assert_eq!(
            at_major(3).with_tier_history(late).err(),
            Some(TierHistoryError::FirstTierOutside {
                first: major(4),
                build: major(3)
            })
        );
    }

    #[test]
    fn a_bundle_with_a_tier_and_no_history_starts_its_history_at_its_own_major() {
        let history = at_major(5).tier_history().clone();
        assert_eq!(
            history,
            TierHistory::new(major(5), Some(major(5)), Vec::new())
        );
    }

    #[test]
    fn the_directive_may_appear_once() {
        assert_eq!(
            Major::declared_in("-- connetto:major 1\n-- connetto:major 1"),
            Err(MajorError::Repeated)
        );
    }

    #[test]
    fn zero_and_non_numbers_are_refused() {
        for value in ["0", "-1", "two", ""] {
            assert_eq!(
                Major::declared_in(&format!("-- connetto:major {value}")),
                Err(MajorError::Invalid(value.to_owned())),
                "{value:?}"
            );
        }
    }

    /// `source` with the major directive every bundle requires, major 1.
    fn majored(source: &str) -> String {
        format!("{MAJOR_DIRECTIVE} 1\n{source}")
    }

    /// One bundle of known contents, the reference every case below varies.
    fn reference() -> SchemaBundle {
        SchemaBundle::new(
            majored("CREATE TABLE orders (id INT);"),
            "CREATE POLICY orders_p ON orders USING (true);",
            "CREATE TABLE orders_rls (id INTEGER); CREATE VIEW orders AS SELECT * FROM orders_rls;",
            [("orders", "orders_rls")],
            ["orders", "orders_rls_violations"],
            None::<&str>,
        )
        .expect("the source declares major 1")
    }

    #[test]
    fn every_field_of_the_bundle_changes_the_version() {
        let base = reference().version();
        let varied = [
            SchemaBundle::new(majored("CREATE TABLE orders (id INT, extra INT);"), "CREATE POLICY orders_p ON orders USING (true);",
            "CREATE TABLE orders_rls (id INTEGER); CREATE VIEW orders AS SELECT * FROM orders_rls;",
            [("orders", "orders_rls")],
            ["orders", "orders_rls_violations"],
            None::<&str>,).expect("the source declares major 1")
            .version(),
            SchemaBundle::new(majored("CREATE TABLE orders (id INT);"), "CREATE POLICY orders_p ON orders USING (id > 0);",
            "CREATE TABLE orders_rls (id INTEGER); CREATE VIEW orders AS SELECT * FROM orders_rls;",
            [("orders", "orders_rls")],
            ["orders", "orders_rls_violations"],
            None::<&str>,).expect("the source declares major 1")
            .version(),
            SchemaBundle::new(majored("CREATE TABLE orders (id INT);"), "CREATE POLICY orders_p ON orders USING (true);",
            "CREATE TABLE orders_rls (id INTEGER NOT NULL); CREATE VIEW orders AS SELECT * FROM orders_rls;",
            [("orders", "orders_rls")],
            ["orders", "orders_rls_violations"],
            None::<&str>,).expect("the source declares major 1")
            .version(),
            SchemaBundle::new(majored("CREATE TABLE orders (id INT);"), "CREATE POLICY orders_p ON orders USING (true);",
            "CREATE TABLE orders_rls (id INTEGER); CREATE VIEW orders AS SELECT * FROM orders_rls;",
            [("orders", "orders_split")],
            ["orders", "orders_rls_violations"],
            None::<&str>,).expect("the source declares major 1")
            .version(),
            SchemaBundle::new(majored("CREATE TABLE orders (id INT);"), "CREATE POLICY orders_p ON orders USING (true);",
            "CREATE TABLE orders_rls (id INTEGER); CREATE VIEW orders AS SELECT * FROM orders_rls;",
            [("orders", "orders_rls")],
            ["orders"],
            None::<&str>,).expect("the source declares major 1")
            .version(),
        ];
        assert_ne!(base, varied[0], "the schema source is part of the version");
        assert_ne!(
            base, varied[1],
            "the policies source is part of the version"
        );
        assert_ne!(base, varied[2], "the replica DDL is part of the version");
        assert_ne!(base, varied[3], "the policy pairs are part of the version");
        assert_ne!(base, varied[4], "the policy views are part of the version");
    }

    #[test]
    fn the_local_tier_does_not_change_the_version() {
        let without = reference();
        let with = without
            .clone()
            .with_local_tier("CREATE TABLE notes (id INTEGER);");
        assert_eq!(
            without.version(),
            with.version(),
            "the local tier is a separate database and is not part of the synced shape"
        );
    }

    #[test]
    fn pair_and_view_order_does_not_change_the_version() {
        let base = SchemaBundle::new(
            majored("CREATE TABLE orders (id INT);"),
            "CREATE POLICY orders_p ON orders USING (true);",
            "CREATE TABLE orders_rls (id INTEGER);",
            [("orders", "orders_rls"), ("notes", "notes_rls")],
            ["notes", "orders", "orders_rls_violations"],
            None::<&str>,
        )
        .expect("the source declares major 1")
        .version();
        let reordered = SchemaBundle::new(
            majored("CREATE TABLE orders (id INT);"),
            "CREATE POLICY orders_p ON orders USING (true);",
            "CREATE TABLE orders_rls (id INTEGER);",
            [("notes", "notes_rls"), ("orders", "orders_rls")],
            ["orders_rls_violations", "orders", "notes"],
            None::<&str>,
        )
        .expect("the source declares major 1");
        assert_eq!(base, reordered.version(), "the hash sorts both lists");
    }

    #[test]
    fn pair_names_are_case_insensitive() {
        let base = reference().version();
        let recased = SchemaBundle::new(
            majored("CREATE TABLE orders (id INT);"),
            "CREATE POLICY orders_p ON orders USING (true);",
            "CREATE TABLE orders_rls (id INTEGER); CREATE VIEW orders AS SELECT * FROM orders_rls;",
            [("ORDERS", "ORDERS_RLS")],
            ["ORDERS", "ORDERS_RLS_VIOLATIONS"],
            None::<&str>,
        )
        .expect("the source declares major 1");
        assert_eq!(
            base,
            recased.version(),
            "Postgres folds unquoted identifier case"
        );
    }

    const NO_TABLES: &[(&str, &str)] = &[];
    const NO_VIEWS: &[&str] = &[];

    #[test]
    fn two_field_splits_of_one_concatenation_differ() {
        // One byte string, split between two fields at different points. A
        // scheme that hashed the concatenation would read the two bundles as
        // equal. The length prefixes make the split part of the identity.
        let left = SchemaBundle::new(
            majored("AB"),
            "",
            "DDL",
            NO_TABLES.iter().copied(),
            NO_VIEWS.iter().copied(),
            None::<&str>,
        )
        .expect("the source declares major 1")
        .version();
        let right = SchemaBundle::new(
            majored("A"),
            "B",
            "DDL",
            NO_TABLES.iter().copied(),
            NO_VIEWS.iter().copied(),
            None::<&str>,
        )
        .expect("the source declares major 1")
        .version();
        assert_ne!(left, right, "the split at the field boundary is hashed");

        let left = SchemaBundle::new(
            majored("A\nB"),
            "C",
            "DDL",
            NO_TABLES.iter().copied(),
            NO_VIEWS.iter().copied(),
            None::<&str>,
        )
        .expect("the source declares major 1")
        .version();
        let right = SchemaBundle::new(
            majored("A"),
            "B\nC",
            "DDL",
            NO_TABLES.iter().copied(),
            NO_VIEWS.iter().copied(),
            None::<&str>,
        )
        .expect("the source declares major 1")
        .version();
        assert_ne!(left, right, "so is a split across a newline");
    }

    /// SHA-256 of the domain tag plus each field, big-endian `u64`
    /// length-prefixed, computed here without the crate's own field helpers
    /// so the test pins the encoding rather than restating it.
    fn manual_digest(fields: &[&str]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"connetto-schema-bundle-v1\0");
        for field in fields {
            let len = u64::try_from(field.len()).expect("the test fields fit a u64 length prefix");
            hasher.update(len.to_be_bytes());
            hasher.update(field.as_bytes());
        }
        hasher.finalize().to_vec()
    }

    #[test]
    fn the_version_is_the_documented_digest() {
        let bundle = reference();
        let expected = manual_digest(&[
            &majored("CREATE TABLE orders (id INT);"),
            "CREATE POLICY orders_p ON orders USING (true);",
            "CREATE TABLE orders_rls (id INTEGER); CREATE VIEW orders AS SELECT * FROM orders_rls;",
            "orders\u{0}orders_rls",
            "orders\u{0}orders_rls_violations",
            CALLER_FUNCTION,
            SUBJECTS_FUNCTION,
        ]);
        assert_eq!(bundle.version().hash(), &expected[..]);
    }

    #[test]
    fn crlf_and_lf_sources_hash_equal() {
        let lf = SchemaBundle::new(
            majored("A\nB\nC"),
            "D\nE",
            "F\nG",
            NO_TABLES.iter().copied(),
            NO_VIEWS.iter().copied(),
            None::<&str>,
        )
        .expect("the source declares major 1")
        .version();
        let crlf = SchemaBundle::new(
            majored("A\r\nB\r\nC"),
            "D\r\nE",
            "F\r\nG",
            NO_TABLES.iter().copied(),
            NO_VIEWS.iter().copied(),
            None::<&str>,
        )
        .expect("the source declares major 1")
        .version();
        assert_eq!(lf, crlf);
    }
}
