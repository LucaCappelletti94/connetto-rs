//! Schema version shared between client and server.
//!
//! The client compares the [`SchemaVersion`] it was built against with the one
//! the server advertises in `HandshakeAck`. connetto does not migrate schemas at
//! runtime (the client never runs DDL), so a mismatch means this app build is
//! stale and must reload, not that a migration should run. A version is a
//! content hash of the schema, so two schemas are interchangeable iff their
//! hashes match.
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
//! as an outdated build.
//!
//! [`HandshakeAck`]: crate::messages::HandshakeAck

use core::fmt;

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
/// application applies and the version it presents cannot drift apart.
#[derive(Clone)]
pub struct SchemaBundle {
    schema_source: String,
    policies_source: String,
    replica_ddl: String,
    policy_tables: Vec<(String, String)>,
    policy_views: Vec<String>,
    local_tier_ddl: Option<String>,
    shared_tables: Vec<String>,
    shared_layout: Option<SharedLayout>,
    connection_ddl: String,
}

impl SchemaBundle {
    /// Build a bundle from its contents, in the one place the contents are
    /// authoritative, the build step that translated them or a test.
    ///
    /// `policy_tables` are the `(logical, physical)` pairs the translation
    /// split, `policy_views` every view it emitted, and `local_tier_ddl` the
    /// translated local tier, when the build has one. Order of the pairs and
    /// views does not matter, the hash sorts them.
    #[must_use]
    pub fn new<S, P, D, T, TL, TP, V, VN, L>(
        schema_source: S,
        policies_source: P,
        replica_ddl: D,
        policy_tables: T,
        policy_views: V,
        local_tier_ddl: Option<L>,
    ) -> Self
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
        Self {
            schema_source: schema_source.into(),
            policies_source: policies_source.into(),
            replica_ddl: replica_ddl.into(),
            policy_tables: policy_tables
                .into_iter()
                .map(|(logical, physical)| (logical.into(), physical.into()))
                .collect(),
            policy_views: policy_views.into_iter().map(Into::into).collect(),
            local_tier_ddl: local_tier_ddl.map(Into::into),
            shared_tables: Vec::new(),
            shared_layout: None,
            connection_ddl: String::new(),
        }
    }

    /// Return a copy of this bundle with its translated local tier, for the
    /// build step that translates the synced tier and the local tier as two
    /// separate reference universes. The version is unaffected, since the
    /// local tier is not part of the synced shape it covers.
    #[must_use]
    pub fn with_local_tier(mut self, local_tier_ddl: impl Into<String>) -> Self {
        self.local_tier_ddl = Some(local_tier_ddl.into());
        self
    }

    /// Return a copy of this bundle naming the tables a device stores once for
    /// every account. The version is unaffected, since where a device stores a
    /// table changes nothing on the wire.
    #[must_use]
    pub fn with_shared_tables<T: Into<String>>(
        mut self,
        tables: impl IntoIterator<Item = T>,
    ) -> Self {
        self.shared_tables = tables.into_iter().map(Into::into).collect();
        self
    }

    /// Return a copy of this bundle carrying the shared store's translated
    /// layout, for a build that stores a table once for every account. The
    /// version is unaffected, since the layout is a device-side artifact, not
    /// part of the synced shape it covers.
    #[must_use]
    pub fn with_shared_layout(mut self, layout: SharedLayout) -> Self {
        self.shared_layout = Some(layout);
        self
    }

    /// Return a copy of this bundle carrying its connection program, the
    /// statements a connection to an existing replica runs to recreate its
    /// `TEMP` objects. The version is unaffected, since the first
    /// initialization the replica DDL hashes already covers it.
    #[must_use]
    pub fn with_connection_ddl(mut self, ddl: impl Into<String>) -> Self {
        self.connection_ddl = ddl.into();
        self
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

    /// The tables a device stores once for every account, as the build
    /// validated them.
    #[must_use]
    pub fn shared_tables(&self) -> &[String] {
        &self.shared_tables
    }

    /// The shared store's translated layout, when the build shares a table.
    /// It is not part of the synced shape the version covers.
    #[must_use]
    pub fn shared_layout(&self) -> Option<&SharedLayout> {
        self.shared_layout.as_ref()
    }

    /// The connection program, the statements a connection to an existing
    /// replica runs to recreate its `TEMP` objects. Empty when the build has
    /// none. It is not part of the synced shape the version covers.
    #[must_use]
    pub fn connection_ddl(&self) -> &str {
        &self.connection_ddl
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
            .field("version", &self.version())
            .field("policy_tables", &self.policy_tables)
            .field("policy_views", &self.policy_views)
            .finish_non_exhaustive()
    }
}

/// The shared store's translated layout: the four SQL programs a device runs to
/// open a replica whose shared tables live in a separate database file, one for
/// each freshness situation of the main and shared files.
#[derive(Clone, Debug)]
pub struct SharedLayout {
    fresh_both: String,
    fresh_main: String,
    fresh_shared: String,
    reopen: String,
}

impl SharedLayout {
    /// Build a layout from its four programs, in the order both files fresh,
    /// main fresh only, shared fresh only, and connection reopen.
    #[must_use]
    pub fn new(
        fresh_both: impl Into<String>,
        fresh_main: impl Into<String>,
        fresh_shared: impl Into<String>,
        reopen: impl Into<String>,
    ) -> Self {
        Self {
            fresh_both: fresh_both.into(),
            fresh_main: fresh_main.into(),
            fresh_shared: fresh_shared.into(),
            reopen: reopen.into(),
        }
    }

    /// The program a device runs to open its replica, given whether each file
    /// is freshly created.
    #[must_use]
    pub fn sql(&self, fresh_main: bool, fresh_shared: bool) -> &str {
        match (fresh_main, fresh_shared) {
            (true, true) => &self.fresh_both,
            (true, false) => &self.fresh_main,
            (false, true) => &self.fresh_shared,
            (false, false) => &self.reopen,
        }
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

    /// One bundle of known contents, the reference every case below varies.
    fn reference() -> SchemaBundle {
        SchemaBundle::new(
            "CREATE TABLE orders (id INT);",
            "CREATE POLICY orders_p ON orders USING (true);",
            "CREATE TABLE orders_rls (id INTEGER); CREATE VIEW orders AS SELECT * FROM orders_rls;",
            [("orders", "orders_rls")],
            ["orders", "orders_rls_violations"],
            None::<&str>,
        )
    }

    #[test]
    fn every_field_of_the_bundle_changes_the_version() {
        let base = reference().version();
        let varied = [
            SchemaBundle::new(
                "CREATE TABLE orders (id INT, extra INT);",
                "CREATE POLICY orders_p ON orders USING (true);",
                "CREATE TABLE orders_rls (id INTEGER); CREATE VIEW orders AS SELECT * FROM orders_rls;",
                [("orders", "orders_rls")],
                ["orders", "orders_rls_violations"],
                None::<&str>,
            )
            .version(),
            SchemaBundle::new(
                "CREATE TABLE orders (id INT);",
                "CREATE POLICY orders_p ON orders USING (id > 0);",
                "CREATE TABLE orders_rls (id INTEGER); CREATE VIEW orders AS SELECT * FROM orders_rls;",
                [("orders", "orders_rls")],
                ["orders", "orders_rls_violations"],
                None::<&str>,
            )
            .version(),
            SchemaBundle::new(
                "CREATE TABLE orders (id INT);",
                "CREATE POLICY orders_p ON orders USING (true);",
                "CREATE TABLE orders_rls (id INTEGER NOT NULL); CREATE VIEW orders AS SELECT * FROM orders_rls;",
                [("orders", "orders_rls")],
                ["orders", "orders_rls_violations"],
                None::<&str>,
            )
            .version(),
            SchemaBundle::new(
                "CREATE TABLE orders (id INT);",
                "CREATE POLICY orders_p ON orders USING (true);",
                "CREATE TABLE orders_rls (id INTEGER); CREATE VIEW orders AS SELECT * FROM orders_rls;",
                [("orders", "orders_split")],
                ["orders", "orders_rls_violations"],
                None::<&str>,
            )
            .version(),
            SchemaBundle::new(
                "CREATE TABLE orders (id INT);",
                "CREATE POLICY orders_p ON orders USING (true);",
                "CREATE TABLE orders_rls (id INTEGER); CREATE VIEW orders AS SELECT * FROM orders_rls;",
                [("orders", "orders_rls")],
                ["orders"],
                None::<&str>,
            )
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
    fn the_shared_tables_do_not_change_the_version() {
        let without = reference();
        let with = without.clone().with_shared_tables(["orders"]);
        assert_eq!(
            without.version(),
            with.version(),
            "a server that names no shared table must accept the client that does"
        );
    }

    #[test]
    fn pair_and_view_order_does_not_change_the_version() {
        let base = SchemaBundle::new(
            "CREATE TABLE orders (id INT);",
            "CREATE POLICY orders_p ON orders USING (true);",
            "CREATE TABLE orders_rls (id INTEGER);",
            [("orders", "orders_rls"), ("notes", "notes_rls")],
            ["notes", "orders", "orders_rls_violations"],
            None::<&str>,
        )
        .version();
        let reordered = SchemaBundle::new(
            "CREATE TABLE orders (id INT);",
            "CREATE POLICY orders_p ON orders USING (true);",
            "CREATE TABLE orders_rls (id INTEGER);",
            [("notes", "notes_rls"), ("orders", "orders_rls")],
            ["orders_rls_violations", "orders", "notes"],
            None::<&str>,
        );
        assert_eq!(base, reordered.version(), "the hash sorts both lists");
    }

    #[test]
    fn pair_names_are_case_insensitive() {
        let base = reference().version();
        let recased = SchemaBundle::new(
            "CREATE TABLE orders (id INT);",
            "CREATE POLICY orders_p ON orders USING (true);",
            "CREATE TABLE orders_rls (id INTEGER); CREATE VIEW orders AS SELECT * FROM orders_rls;",
            [("ORDERS", "ORDERS_RLS")],
            ["ORDERS", "ORDERS_RLS_VIOLATIONS"],
            None::<&str>,
        );
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
            "AB",
            "",
            "DDL",
            NO_TABLES.iter().copied(),
            NO_VIEWS.iter().copied(),
            None::<&str>,
        )
        .version();
        let right = SchemaBundle::new(
            "A",
            "B",
            "DDL",
            NO_TABLES.iter().copied(),
            NO_VIEWS.iter().copied(),
            None::<&str>,
        )
        .version();
        assert_ne!(left, right, "the split at the field boundary is hashed");

        let left = SchemaBundle::new(
            "A\nB",
            "C",
            "DDL",
            NO_TABLES.iter().copied(),
            NO_VIEWS.iter().copied(),
            None::<&str>,
        )
        .version();
        let right = SchemaBundle::new(
            "A",
            "B\nC",
            "DDL",
            NO_TABLES.iter().copied(),
            NO_VIEWS.iter().copied(),
            None::<&str>,
        )
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
            "CREATE TABLE orders (id INT);",
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
            "A\nB\nC",
            "D\nE",
            "F\nG",
            NO_TABLES.iter().copied(),
            NO_VIEWS.iter().copied(),
            None::<&str>,
        )
        .version();
        let crlf = SchemaBundle::new(
            "A\r\nB\r\nC",
            "D\r\nE",
            "F\r\nG",
            NO_TABLES.iter().copied(),
            NO_VIEWS.iter().copied(),
            None::<&str>,
        )
        .version();
        assert_eq!(lf, crlf);
    }

    /// The four lifecycle programs of one shared store layout, each distinct so
    /// a selection that picks the wrong program reads wrong.
    fn layout() -> SharedLayout {
        SharedLayout::new("both", "main", "shared", "reopen")
    }

    /// A shared layout and a connection program are device-side artifacts, not
    /// part of the synced shape, so neither changes the version.
    #[test]
    fn the_shared_layout_and_connection_program_do_not_change_the_version() {
        let base = reference().version();
        assert_eq!(
            base,
            reference().with_shared_layout(layout()).version(),
            "the shared layout alone changes nothing on the wire"
        );
        assert_eq!(
            base,
            reference()
                .with_connection_ddl("CREATE TEMP VIEW reader AS SELECT 1;")
                .version(),
            "the connection program alone changes nothing on the wire"
        );
        assert_eq!(
            base,
            reference()
                .with_shared_layout(layout())
                .with_connection_ddl("CREATE TEMP VIEW reader AS SELECT 1;")
                .version(),
            "a device that shares a table must present the same schema as one that does not"
        );
    }

    /// `sql` hands back the program named by the two file-freshness flags, and
    /// no other.
    #[test]
    fn sql_selects_the_program_for_each_freshness_pair() {
        let layout = layout();
        assert_eq!(layout.sql(true, true), "both");
        assert_eq!(layout.sql(true, false), "main");
        assert_eq!(layout.sql(false, true), "shared");
        assert_eq!(layout.sql(false, false), "reopen");
    }

    /// A bundle built without a shared store has no layout and no connection
    /// program, so a device that never shares reads `None` and the empty
    /// program.
    #[test]
    fn a_fresh_bundle_has_no_shared_layout_and_no_connection_program() {
        let base = reference();
        assert!(base.shared_layout().is_none());
        assert_eq!(base.connection_ddl(), "");
    }
}
