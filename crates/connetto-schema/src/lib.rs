//! The schema build step connetto ships.
//!
//! [`translate`] runs pg2sqlite over a deployment's two Postgres source
//! documents with connetto's fixed options and returns the
//! [`connetto_core::SchemaBundle`] they produce. [`emit`] is the same step
//! from a build script. It reads the source files, translates the synced
//! tier and an optional local tier, validates both against a throwaway
//! SQLite database, and writes the one file an application `include!`s to
//! obtain its bundle.
//!
//! The server runs the same step at boot over its own sources, so a client
//! and its server agree on the version iff the pg2sqlite that built each of
//! them emitted the same replica DDL for the same sources.
//!
//! A build that carries a local tier passes [`TierSource`] to [`emit`],
//! which pairs the tier's source document with the directory its history
//! lives in. That directory holds one export per exported major, the file
//! `<N>.sql`, the local tier of major `N` translated the way the build
//! translates it, beside the optional `<N>.boundary.toml` that declares
//! the drops and renames the boundary into major `N` allows. The
//! declaration file holds `dropped_tables`, a top-level array of table
//! names, `dropped_columns`, a map from a table to the columns it drops,
//! `renamed_tables`, a map from an old table name to its new one, and
//! `renamed_columns`, a map from a table name at major `N - 1` to a map
//! from each old column to its new name. [`emit`] only reads that
//! directory and fails the build when the directory is missing, when its
//! current major holds no export, when that export is stale, or when its
//! majors hold a gap.
//!
//! The `connetto-schema export-tier` command, the crate's binary
//! `connetto-schema`, writes that current export instead. It translates the
//! tier over the major the schema source declares and writes that major's
//! `<N>.sql` alone, so it never rewrites the exports of the majors below
//! the current one. With `--check` it writes nothing and fails instead when
//! the current export is missing or stale, the gate a CI run adds to keep a
//! history fresh.

use std::collections::BTreeSet;
use std::path::Path;

use connetto_core::bots::BotRegistryIdSql;

use connetto_core::auth::CapabilityKey;
/// The registry id markers build scripts and other diesel-free callers pass
/// for `emit` and `translate`, re-exported beside [`translate`].
pub use connetto_core::bots::{TextIds, UuidIds};
use connetto_core::sql::quote_ident;
use connetto_core::{
    AUDIT_TABLE, BOT_LIST_FUNCTION, BOT_LIST_SEPARATOR, BOT_LIST_SETTING, BOT_LIST_WILDCARD,
    CALLER_FUNCTION, SUBJECTS_FUNCTION, SchemaBundle, UUID_FUNCTION, WRITE_EXEMPTION_FUNCTION,
};
use diesel::connection::SimpleConnection;
use diesel::{Connection, SqliteConnection};
use pg2sqlite::manifest::WrapperKind;
use pg2sqlite::prelude::{
    Pg2Sqlite, Pg2SqliteOptions, Script, SessionVariableMapping, UuidRepresentation,
};
use sqlparser::ast::{
    AlterTable, AlterTableOperation, CreateTable, CreateView, ObjectNamePart, Statement,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use thiserror::Error;
mod boundary;

diesel::table! {
    /// SQLite's own catalogue, read to list the views a translation built.
    #[sql_name = "sqlite_master"]
    sqlite_catalog (name) {
        /// The object kind: `table`, `view`, `index` or `trigger`.
        #[sql_name = "type"]
        kind -> diesel::sql_types::Text,
        /// The object name.
        name -> diesel::sql_types::Text,
    }
}

/// A failure to translate a deployment's sources or to write its bundle.
#[derive(Debug, Error)]
pub enum SchemaError {
    /// A source file could not be read, or the emitted file could not be written.
    #[error("reading a source document or writing the emitted bundle: {0}")]
    Io(#[from] std::io::Error),
    /// A source document does not parse, or the translation fails.
    #[error("the Postgres sources do not translate: {0}")]
    Translate(String),
    /// SQLite refuses the translated DDL of the named tier.
    #[error("SQLite refuses the translated {tier} DDL: {detail}")]
    Sqlite {
        /// Which tier's DDL was refused.
        tier: &'static str,
        /// What SQLite reported.
        detail: String,
    },
    /// The step ran outside a cargo build script.
    #[error("OUT_DIR is unset, so the bundle cannot be written from here")]
    MissingOutDir,
    /// The build has a tier but its history directory is not there.
    #[error("the tier history directory {dir} is missing, the build needs its exports", dir = .dir.display())]
    MissingHistoryDir {
        /// The directory the exports live in.
        dir: std::path::PathBuf,
    },
    /// The tier history holds no export for the build's own major.
    #[error("the tier history holds no export for major {major}, run `connetto-schema export-tier --schema <schema> --tier <tier> --dir {dir}`", dir = .dir.display())]
    MissingExport {
        /// The major the export is missing for.
        major: u32,
        /// The export file the command writes.
        path: std::path::PathBuf,
        /// The history directory the file would live in.
        dir: std::path::PathBuf,
    },
    /// The tier history's export for the build's major differs from the
    /// translation the build just computed.
    #[error("the export {path} for major {major} is stale against the current sources, run `connetto-schema export-tier` over them", path = .path.display())]
    StaleExport {
        /// The major the export is stale for.
        major: u32,
        /// The export file the command rewrites.
        path: std::path::PathBuf,
        /// The history directory the file lives in.
        dir: std::path::PathBuf,
    },
    /// The history's exported majors skip one the build's tier crossed.
    #[error(
        "the tier history jumps from major {lowest} to major {build} without exporting major {missing}"
    )]
    HistoryGap {
        /// The directory the exports live in.
        dir: std::path::PathBuf,
        /// The major the history skipped.
        missing: u32,
        /// The oldest major the history holds.
        lowest: u32,
        /// The build's own major.
        build: u32,
    },
    /// The diff between two exports drops a table the boundary file does
    /// not declare.
    #[error(
        "the boundary for major {boundary} drops table {table}, which its declaration file does not declare"
    )]
    UndeclaredTableDrop {
        /// The table the diff drops.
        table: String,
        /// The boundary the drop sits in.
        boundary: u32,
    },
    /// The diff between two exports drops a column the boundary file does
    /// not declare.
    #[error(
        "the boundary for major {boundary} drops column {column} of table {table}, which its declaration file does not declare"
    )]
    UndeclaredColumnDrop {
        /// The table the column sits in.
        table: String,
        /// The column the diff drops.
        column: String,
        /// The boundary the drop sits in.
        boundary: u32,
    },
    /// The diff adds a not null column without a default, which an add
    /// column cannot apply and a rebuild would fill with nulls.
    #[error(
        "the boundary for major {boundary} adds not null column {column} of table {table} without a default"
    )]
    NewNotNullColumnWithoutDefault {
        /// The table the column is added to.
        table: String,
        /// The column the diff adds.
        column: String,
        /// The boundary the add sits in.
        boundary: u32,
    },
    /// The boundary file declares a change the diff between the two
    /// exports does not hold.
    #[error("the boundary file {path} declares a change the diff does not hold, {detail}", path = .path.display())]
    DeclarationMismatch {
        /// The declaration file that holds the entry.
        path: std::path::PathBuf,
        /// The entry that does not match.
        detail: String,
    },
    /// A boundary declaration file does not parse.
    #[error("the boundary file {path} does not parse, {detail}", path = .path.display())]
    BoundaryFile {
        /// The file that does not parse.
        path: std::path::PathBuf,
        /// What the parser reported.
        detail: String,
    },
    /// The export for one major holds a view or a trigger that names a
    /// table or view the export does not hold, which a fresh install of the
    /// export would carry dangling.
    #[error(
        "the export for major {major} holds {kind} {name} that names a table or view the export does not hold: {detail}"
    )]
    DanglingExportObject {
        /// The major the export was written for.
        major: u32,
        /// The kind of the object, `view` or `trigger`.
        kind: String,
        /// The name of the object that names what is absent.
        name: String,
        /// What SQLite reported on the probe's rename.
        detail: String,
    },
    /// The tier history does not fit the bundle the build just translated.
    #[error(transparent)]
    TierHistory(#[from] connetto_core::TierHistoryError),
    /// The schema source does not declare a usable major.
    #[error("the schema source does not declare a usable major: {0}")]
    Major(#[from] connetto_core::MajorError),
}

/// The tables the schema document creates, in document order.
///
/// The one list the cap generator and the server's startup check both walk,
/// so the rules a deployment applies and the rules the server requires
/// cannot name different tables.
///
/// # Errors
///
/// [`SchemaError::Translate`] when the schema document does not parse.
pub fn schema_tables(schema_sql: &str) -> Result<Vec<String>, SchemaError> {
    Ok(parse(schema_sql, "the schema document")?
        .iter()
        .filter_map(|statement| match statement {
            Statement::CreateTable(CreateTable { name, .. }) => table_name(name),
            _ => None,
        })
        .collect())
}

/// The bot cap connetto generates for a deployment.
///
/// One `AS RESTRICTIVE` policy per synced table and verb, each admitting a
/// connection whose [`BOT_LIST_SETTING`] holds the table's `table:verb`
/// entry or the person's wildcard [`BOT_LIST_WILDCARD`]. Postgres holds
/// every bot to its declared list on every path, the cap admitting only what
/// it and the deployment's own rules both allow. A connection carrying no
/// list fails the search and sees or writes nothing, which is why every
/// person's connection carries the wildcard.
///
/// A restrictive policy bites only on a table with row-level security
/// enabled, and a table with it on and no permissive policy admits nobody,
/// so for a table the policies document leaves without row-level security
/// the rules also enable it and add one permissive `FOR ALL` policy
/// named `{table}_connetto_open`, which keeps a person's access what it was
/// while the cap holds the bot.
///
/// The rules are part of the translated policy document, so a changed rule
/// changes the replica DDL and with it the schema version.
///
/// # Errors
///
/// [`SchemaError::Translate`] when either document does not parse.
pub fn cap_policies<Id: BotRegistryIdSql>(
    schema_sql: &str,
    policies_sql: &str,
) -> Result<String, SchemaError> {
    let schema_sql = with_registry::<Id>(schema_sql);
    cap_policies_inner(&schema_sql, policies_sql)
}

fn cap_policies_inner(schema_sql: &str, policies_sql: &str) -> Result<String, SchemaError> {
    let tables = schema_tables(schema_sql)?;
    // A table is secured when either document enables row-level security on
    // it, so the schema document's own `ENABLE ROW LEVEL SECURITY` counts the
    // same as the policies document's. An open policy added over a table that
    // already carries it would OR with the real policy and let every row
    // through.
    let mut secured = rls_enabled(schema_sql)?;
    secured.extend(rls_enabled(policies_sql)?);
    let mut statements = Vec::new();
    for table in &tables {
        if !secured.contains(table) {
            statements.push(format!(
                "ALTER TABLE {} ENABLE ROW LEVEL SECURITY",
                quote_ident(table)
            ));
            statements.push(format!(
                "CREATE POLICY {} ON {} FOR ALL USING (true) WITH CHECK (true)",
                quote_ident(&cap_name(table, "open")),
                quote_ident(table)
            ));
        }
        for verb in ["read", "insert", "update", "delete"] {
            statements.push(cap_statement(table, verb));
        }
    }
    Ok(statements.join(";\n"))
}

/// The schema document connetto translates, the deployment's own document
/// with the registry tables connetto appends, a `;` between the deployment's
/// last statement and the registry DDL.
pub fn with_registry<Id: BotRegistryIdSql>(schema_sql: &str) -> String {
    let mut out = schema_sql.trim_end().to_owned();
    if !out.ends_with(';') {
        out.push(';');
    }
    out.push('\n');
    out.push_str(<Id as BotRegistryIdSql>::DDL);
    out
}

/// Translate the two Postgres source documents with connetto's fixed options
/// and return the bundle they produce.
///
/// The options are connetto's, not the caller's. They fix the `uuidv4` representation
/// and function, the `rls_audit` table, the `connetto_write_exempt` function,
/// and the caller, subjects and bot-list mappings built from the core
/// constants. `K` names the capability key type, which fixes the subjects
/// setting and separator the mapping holds. The documents are translated in
/// the order schema, policies and the [`cap_policies`] the pair generates, so
/// the replica holds the cap its Postgres source holds. The replica DDL is
/// applied to a throwaway in-memory database first, so a translation SQLite
/// refuses is an error here rather than a boot-time failure on the client.
///
/// # Errors
///
/// [`SchemaError::Translate`] when a source does not parse or the translation
/// fails, [`SchemaError::Major`] when the schema source does not declare its
/// major, and [`SchemaError::Sqlite`] when the replica DDL is not accepted.
pub fn translate<K: CapabilityKey, Id: BotRegistryIdSql>(
    schema_sql: &str,
    policies_sql: &str,
) -> Result<SchemaBundle, SchemaError> {
    let schema_sql = with_registry::<Id>(schema_sql);
    let options = options::<K>();
    let mut translator = parsed_documents(&schema_sql, policies_sql)?;
    let cap = cap_policies_inner(&schema_sql, policies_sql)?;
    if !cap.is_empty() {
        translator = translator
            .sql(&cap)
            .map_err(|err| SchemaError::Translate(err.to_string()))?;
    }
    let report = translator
        .translate_with_report(&options)
        .map_err(|err| SchemaError::Translate(err.to_string()))?;
    let ddl = statements_to_ddl(&report.script);
    validate(&ddl, "replica")?;
    let manifest = translator
        .translation_manifest(&options)
        .map_err(|err| SchemaError::Translate(err.to_string()))?;
    let pairs = manifest
        .iter()
        .filter(|entry| entry.wrapper == WrapperKind::RlsView)
        .map(|entry| (entry.logical.clone(), entry.physical.clone()))
        .collect::<Vec<(String, String)>>();
    Ok(SchemaBundle::new(
        schema_sql,
        policies_sql,
        ddl,
        pairs,
        view_names(&report.script),
        None::<&str>,
    )?)
}

/// The local tier a build translates beside its synced schema, and the
/// directory of its exports the build reads its tier history from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierSource {
    /// The Postgres source document the tier translates from.
    source: std::path::PathBuf,
    /// The directory the tier exports and boundary files live in.
    history: std::path::PathBuf,
}

impl TierSource {
    /// The tier source document and the directory its exports live in.
    #[must_use]
    pub fn new(
        source: impl Into<std::path::PathBuf>,
        history: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            source: source.into(),
            history: history.into(),
        }
    }

    /// The Postgres source document the tier translates from.
    #[must_use]
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// The directory the tier exports and boundary files live in.
    #[must_use]
    pub fn history(&self) -> &Path {
        &self.history
    }
}

/// The export one run of [`export_tier`] wrote or checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOutcome {
    /// The export file the run wrote or checked.
    pub path: std::path::PathBuf,
}

/// Translate one local tier source exactly the way the build translates it
/// and write, or with `check` check only, the export for the schema source's
/// major into the history directory.
///
/// A run never rewrites an export for a major it was not given, so a history
/// directory keeps its older exports intact while its current one is
/// refreshed. `check` writes nothing and fails when the current export is
/// missing or differs from the translation the same sources would compute
/// now, which is the CI gate that keeps a history fresh.
///
/// # Errors
///
/// As [`translate`], plus [`SchemaError::MissingExport`] and
/// [`SchemaError::StaleExport`] in `check` mode for the current export.
pub fn export_tier<K: CapabilityKey, Id: BotRegistryIdSql>(
    schema: &Path,
    tier: &Path,
    dir: &Path,
    check: bool,
) -> Result<ExportOutcome, SchemaError> {
    let schema_sql = std::fs::read_to_string(schema)?;
    let tier_sql = std::fs::read_to_string(tier)?;
    let major = connetto_core::Major::declared_in(&schema_sql)?;
    let tier_ddl = translate_tier::<K>(&tier_sql)?;
    let path = dir.join(format!("{major}.sql"));
    let existing = match std::fs::read_to_string(&path) {
        Ok(existing) => Some(existing),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err.into()),
    };
    let fresh = existing.as_deref() != Some(tier_ddl.as_str());
    if check && fresh {
        return Err(match existing {
            Some(_) => SchemaError::StaleExport {
                major: major.get(),
                path,
                dir: dir.to_path_buf(),
            },
            None => SchemaError::MissingExport {
                major: major.get(),
                path,
                dir: dir.to_path_buf(),
            },
        });
    }
    if fresh {
        std::fs::create_dir_all(dir)?;
        std::fs::write(&path, tier_ddl)?;
    }
    Ok(ExportOutcome { path })
}

/// The translated local tier one source document holds, validated against a
/// throwaway SQLite database the same way the build validates it.
///
/// # Errors
///
/// As [`translate`], with [`SchemaError::Sqlite`] for the local tier.
fn translate_tier<K: CapabilityKey>(tier_sql: &str) -> Result<String, SchemaError> {
    let options = options::<K>();
    let tier = parsed_documents(tier_sql, "")?;
    let report = tier
        .translate_with_report(&options)
        .map_err(|err| SchemaError::Translate(err.to_string()))?;
    let ddl = statements_to_ddl(&report.script);
    validate(&ddl, "local tier")?;
    Ok(ddl)
}

/// Print a rerun trigger for the history directory and every file in it,
/// failing the build when the directory is not there.
///
/// # Errors
///
/// [`SchemaError::MissingHistoryDir`] when the directory is absent,
/// [`SchemaError::Io`] when a file cannot be read.
fn rerun_history(dir: &Path) -> Result<(), SchemaError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(SchemaError::MissingHistoryDir {
                dir: dir.to_path_buf(),
            });
        }
        Err(err) => return Err(err.into()),
    };
    println!("cargo::rerun-if-changed={}", dir.display());
    for entry in entries {
        let path = entry.map_err(SchemaError::from)?.path();
        println!("cargo::rerun-if-changed={}", path.display());
    }
    Ok(())
}

/// The build-script entry point.
///
/// Reads the two Postgres source documents, translates the synced tier and,
/// when a [`TierSource`] is given, the deployment's own local tier as a
/// separate reference universe and the tier history its exports hold,
/// validates both DDLs against a throwaway SQLite database, and writes
/// `connetto-schema.rs` under `OUT_DIR`. It prints
/// `cargo::rerun-if-changed` for every file it reads, the history directory's
/// files included.
///
/// The application that ships the schema includes the file and reads the
/// bundle through the module it defines:
///
/// ```ignore
/// include!(concat!(env!("OUT_DIR"), "/connetto-schema.rs"));
/// let bundle = connetto_schema_bundle::bundle();
/// let version = bundle.version();
/// ```
///
/// The module also exposes the translated documents as `pub const` strings
/// (`SCHEMA_SOURCE`, `POLICIES_SOURCE`, `REPLICA_DDL`, `CAP_POLICIES`, and
/// `LOCAL_TIER_DDL` when the build has a local tier), so a `const` context
/// such as `concat!` can use them without re-deriving the bundle. `emit` also
/// writes the cap document to `connetto-cap-policies.sql` in `OUT_DIR`, the
/// SQL the deployment applies beside its schema and policies.
///
/// # Errors
///
/// As [`translate`], plus [`SchemaError::MissingOutDir`] outside a build
/// script, [`SchemaError::Sqlite`] for a refused local tier, the tier
/// history errors for a build with a tier, and
/// [`SchemaError::TierHistory`] when the history does not reach the bundle's
/// major.
pub fn emit<K: CapabilityKey, Id: BotRegistryIdSql>(
    schema: &Path,
    policies: &Path,
    tier: Option<&TierSource>,
) -> Result<(), SchemaError> {
    let out_dir = std::env::var("OUT_DIR").map_err(|_| SchemaError::MissingOutDir)?;
    emit_to::<K, Id>(schema, policies, tier, Path::new(&out_dir))
}

/// The body of [`emit`], its output directory supplied, so a test can run
/// the step without a build script.
///
/// # Errors
///
/// As [`emit`], minus [`SchemaError::MissingOutDir`].
pub(crate) fn emit_to<K: CapabilityKey, Id: BotRegistryIdSql>(
    schema: &Path,
    policies: &Path,
    tier: Option<&TierSource>,
    out_dir: &Path,
) -> Result<(), SchemaError> {
    println!("cargo::rerun-if-changed={}", schema.display());
    println!("cargo::rerun-if-changed={}", policies.display());
    if let Some(tier) = tier {
        println!("cargo::rerun-if-changed={}", tier.source().display());
        rerun_history(tier.history())?;
    }
    let schema_sql = std::fs::read_to_string(schema)?;
    let policies_sql = std::fs::read_to_string(policies)?;
    let cap = cap_policies::<Id>(&schema_sql, &policies_sql)?;
    let mut bundle = translate::<K, Id>(&schema_sql, &policies_sql)?;
    if let Some(tier) = tier {
        let tier_sql = std::fs::read_to_string(tier.source())?;
        let tier_ddl = translate_tier::<K>(&tier_sql)?;
        let history = boundary::tier_history(tier.history(), bundle.major(), &tier_ddl)?;
        bundle = bundle
            .with_local_tier(tier_ddl)
            .with_tier_history(history)?;
    }
    std::fs::write(out_dir.join("connetto-cap-policies.sql"), &cap)?;
    std::fs::write(out_dir.join("connetto-schema.rs"), render(&bundle, &cap))?;
    Ok(())
}

/// The one fixed option set the deployment's documents translate under.
fn options<K: CapabilityKey>() -> Pg2SqliteOptions {
    Pg2SqliteOptions::default()
        .with_uuid_representation(UuidRepresentation::Blob)
        .with_uuid_function_name(UUID_FUNCTION)
        .with_session_variable(SessionVariableMapping::current_setting(
            connetto_core::auth::DEFAULT_USER_SETTING,
            CALLER_FUNCTION,
        ))
        .with_session_variable(
            SessionVariableMapping::current_setting(K::SETTING, SUBJECTS_FUNCTION)
                .holding_set(K::SEPARATOR),
        )
        .with_session_variable(
            SessionVariableMapping::current_setting(BOT_LIST_SETTING, BOT_LIST_FUNCTION)
                .holding_set(BOT_LIST_SEPARATOR),
        )
        .with_rls_audit_table_name(AUDIT_TABLE.to_string())
        .with_write_exemption_function(WRITE_EXEMPTION_FUNCTION)
}

/// Parse the documents into one translator, in the given order.
fn parsed_documents(schema_sql: &str, policies_sql: &str) -> Result<Pg2Sqlite, SchemaError> {
    let mut translator = Pg2Sqlite::default()
        .sql(schema_sql)
        .map_err(|err| SchemaError::Translate(err.to_string()))?;
    if !policies_sql.is_empty() {
        translator = translator
            .sql(policies_sql)
            .map_err(|err| SchemaError::Translate(err.to_string()))?;
    }
    Ok(translator)
}

/// Parse one document into its statements.
fn parse(sql: &str, what: &str) -> Result<Vec<Statement>, SchemaError> {
    Parser::parse_sql(&PostgreSqlDialect {}, sql)
        .map_err(|err| SchemaError::Translate(format!("{what} does not parse: {err}")))
}

/// The unqualified name a statement's object names, its last part.
fn table_name(name: &sqlparser::ast::ObjectName) -> Option<String> {
    name.0
        .iter()
        .filter_map(ObjectNamePart::as_ident)
        .next_back()
        .map(|ident| ident.value.clone())
}

/// The tables the policies document enables row-level security on, by name.
fn rls_enabled(policies_sql: &str) -> Result<BTreeSet<String>, SchemaError> {
    Ok(parse(policies_sql, "the policies document")?
        .iter()
        .filter_map(|statement| match statement {
            Statement::AlterTable(AlterTable {
                name, operations, ..
            }) => operations
                .iter()
                .any(|operation| {
                    matches!(
                        operation,
                        AlterTableOperation::EnableRowLevelSecurity
                            | AlterTableOperation::ForceRowLevelSecurity
                    )
                })
                .then(|| table_name(name))
                .flatten(),
            _ => None,
        })
        .collect())
}

/// The policy name one generated rule takes on its table.
fn cap_name(table: &str, suffix: &str) -> String {
    format!("{table}_connetto_{suffix}")
}

/// The predicate one cap policy admits: the table's verb in the connection's
/// list, or the person's wildcard.
fn cap_clause(table: &str, verb: &str) -> String {
    let list = format!(
        "string_to_array(current_setting('{BOT_LIST_SETTING}', true), '{BOT_LIST_SEPARATOR}')"
    );
    format!("'{table}:{verb}' = ANY({list}) OR '{BOT_LIST_WILDCARD}' = ANY({list})")
}

/// The one `AS RESTRICTIVE` policy `table` carries for `verb`.
fn cap_statement(table: &str, verb: &str) -> String {
    let clause = cap_clause(table, verb);
    let on = format!(
        "{} ON {}",
        quote_ident(&cap_name(table, &format!("cap_{verb}"))),
        quote_ident(table)
    );
    match verb {
        "read" => format!("CREATE POLICY {on} AS RESTRICTIVE FOR SELECT USING ({clause})"),
        "insert" => format!("CREATE POLICY {on} AS RESTRICTIVE FOR INSERT WITH CHECK ({clause})"),
        "update" => format!(
            "CREATE POLICY {on} AS RESTRICTIVE FOR UPDATE USING ({clause}) WITH CHECK ({clause})"
        ),
        _ => format!("CREATE POLICY {on} AS RESTRICTIVE FOR DELETE USING ({clause})"),
    }
}

/// Join the translated statements the way the artifacts do: `;` between and
/// a `;` after the last, connection setup first.
fn statements_to_ddl(script: &Script) -> String {
    let mut ddl = script
        .iter()
        .map(Statement::to_string)
        .collect::<Vec<_>>()
        .join(";\n");
    ddl.push(';');
    ddl
}

/// Apply `ddl` to a throwaway in-memory database and fail when SQLite
/// refuses it.
fn validate(ddl: &str, tier: &'static str) -> Result<(), SchemaError> {
    let mut probe = SqliteConnection::establish(":memory:").map_err(|err| SchemaError::Sqlite {
        tier,
        detail: err.to_string(),
    })?;
    probe
        .batch_execute(ddl)
        .map_err(|err| SchemaError::Sqlite {
            tier,
            detail: err.to_string(),
        })?;
    Ok(())
}

/// The views a translation creates, read off the `CREATE VIEW` statements it
/// emits, so a server without SQLite can compute them.
fn view_names(script: &Script) -> Vec<String> {
    script
        .iter()
        .filter_map(|statement| match statement {
            Statement::CreateView(CreateView { name, .. }) => name
                .0
                .iter()
                .filter_map(ObjectNamePart::as_ident)
                .next_back()
                .map(|ident| ident.value.clone()),
            _ => None,
        })
        .collect()
}

/// The file an application `include!`s.
///
/// The translated documents are named as literals so the included module is
/// all the demo's runtime needs, a `bundle()` that builds the
/// [`connetto_core::SchemaBundle`], plus the `pub const` documents for the
/// `const` contexts that cannot re-derive the bundle. When the build has a
/// local tier, `bundle()` also attaches the tier history the build read from
/// its exports, so the device holds every generated step from the oldest
/// exported major to the build's own major.
fn render(bundle: &SchemaBundle, cap: &str) -> String {
    let tier = match bundle.local_tier_ddl() {
        Some(tier) => {
            // An `Option` either way, so the const's type never depends on
            // whether this build has a tier.
            format!(
                "pub const LOCAL_TIER_DDL: Option<&str> = Some({});",
                raw_literal(tier)
            )
        }
        None => "pub const LOCAL_TIER_DDL: Option<&str> = None;".to_string(),
    };
    let history = if bundle.local_tier_ddl().is_some() {
        history_call(bundle.tier_history())
    } else {
        String::new()
    };
    let tables = bundle
        .policy_tables()
        .iter()
        .map(|(logical, physical)| format!("({}, {})", raw_literal(logical), raw_literal(physical)))
        .collect::<Vec<_>>()
        .join(",\n            ");
    let tables = if tables.is_empty() {
        "&[]".to_string()
    } else {
        format!("&[\n            {tables}\n        ]")
    };
    let views = bundle
        .policy_views()
        .iter()
        .map(|view| raw_literal(view))
        .collect::<Vec<_>>()
        .join(", ");
    let views = if views.is_empty() {
        "&[]".to_string()
    } else {
        format!("&[{views}]")
    };
    format!(
        "// Generated by connetto_schema::emit. Do not edit.\n\
         #[doc(hidden)]\n\
         pub mod connetto_schema_bundle {{\n\
         /// The Postgres schema source document.\n\
         pub const SCHEMA_SOURCE: &str = {};\n\
        /// The Postgres policy source document.\n\
        pub const POLICIES_SOURCE: &str = {};\n\
        /// The translated replica DDL a client applies to a fresh replica.\n\
        pub const REPLICA_DDL: &str = {};\n\
        /// The bot cap the deployment applies beside its schema and policies.\n\
        pub const CAP_POLICIES: &str = {};\n\
         /// The translated local tier, when the build has one.\n\
         {tier}\n\
         /// The (logical, physical) pairs the translation split.\n\
         pub const POLICY_TABLES: &[(&str, &str)] = {tables};\n\
         /// Every view the translation emitted.\n\
         pub const POLICY_VIEWS: &[&str] = {views};\n\
         /// The schema bundle this build translated from its own Postgres\n\
         /// sources. The version is the hash of exactly these contents.\n\
         #[must_use]\n\
         pub fn bundle() -> connetto_core::SchemaBundle {{\n\
         connetto_core::SchemaBundle::new(\n\
             SCHEMA_SOURCE,\n\
             POLICIES_SOURCE,\n\
             REPLICA_DDL,\n\
             POLICY_TABLES.iter().copied(),\n\
             POLICY_VIEWS.iter().copied(),\n\
             LOCAL_TIER_DDL,\n\
         )\n\
         .expect(\"the build step translated this bundle\")\n\
         {history}\n\
         }}\n\
         }}\n",
        raw_literal(bundle.schema_source()),
        raw_literal(bundle.policies_source()),
        raw_literal(bundle.replica_ddl()),
        raw_literal(cap),
    )
}

/// The `bundle()` code that attaches the tier history a build with a tier
/// read from its exports.
fn history_call(history: &connetto_core::schema::TierHistory) -> String {
    let first = match history.first_with_tier() {
        Some(first) => format!("Some({})", major_literal(first)),
        None => "None".to_string(),
    };
    let boundaries = history
        .boundaries()
        .iter()
        .map(|boundary| {
            format!(
                "connetto_core::TierBoundary::new(\n    {},\n    {},\n)",
                major_literal(boundary.from()),
                raw_literal(boundary.sql())
            )
        })
        .collect::<Vec<_>>()
        .join(",\n        ");
    format!(
        ".with_tier_history(\n\
         connetto_core::TierHistory::new(\n\
         {},\n\
         {},\n\
         vec![\n\
         {}\n\
         ],\n\
         ),\n\
         )\n\
         .expect(\"the build step generated this history\")",
        major_literal(history.oldest()),
        first,
        boundaries
    )
}

/// The one-line code a build's `bundle()` holds for one checked major.
fn major_literal(major: connetto_core::Major) -> String {
    format!(
        "connetto_core::Major::new({major})\n    .expect(\"the build step checked the history majors\")"
    )
}

/// Wrap `text` in a Rust raw string literal, adding `#`s until the closing
/// delimiter cannot occur inside.
fn raw_literal(text: &str) -> String {
    let mut hashes = String::new();
    while text.contains(format!("\"{hashes}").as_str()) {
        hashes.push('#');
    }
    format!("r{hashes}\"{text}\"{hashes}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};

    /// The major a test bundle's schema source declares, prepended to `source`.
    fn majored(source: &str) -> String {
        format!("{} 1\n{source}", connetto_core::MAJOR_DIRECTIVE)
    }

    /// The views a translated tier's own catalogue reports after the DDL is
    /// applied, the ground truth the derivation is pinned against.
    fn sqlite_views(ddl: &str) -> Vec<String> {
        let mut probe = SqliteConnection::establish(":memory:").expect("open the probe");
        probe.batch_execute(ddl).expect("apply the translated DDL");
        sqlite_catalog::table
            .select(sqlite_catalog::name)
            .filter(sqlite_catalog::kind.eq("view"))
            .load::<String>(&mut probe)
            .expect("list the views")
    }

    /// The cap document is the four `AS RESTRICTIVE` policies per table the
    /// schema document creates, in document order, with the row-level
    /// security enabling pair only on a table the policies document leaves
    /// without it, and it reaches the registry tables connetto appends.
    #[test]
    fn cap_policies_cover_every_table_and_enable_rls_where_absent() {
        let schema = majored(
            "CREATE TABLE orders (id INT PRIMARY KEY, label TEXT); \
                              CREATE TABLE notes (id INT PRIMARY KEY, body TEXT);",
        );
        let policies = "ALTER TABLE orders ENABLE ROW LEVEL SECURITY; \
                        CREATE POLICY orders_p ON orders FOR ALL USING (true);";
        let list = |entry: &str| {
            format!(
                "'{entry}' = ANY(string_to_array(current_setting('app.bot_list', true), ',')) \
                 OR '*' = ANY(string_to_array(current_setting('app.bot_list', true), ','))"
            )
        };
        // The deployment's tables in document order, then the five registry
        // tables connetto appends. `orders` is secured; the rest are not.
        let tables = [
            ("orders", false),
            ("notes", true),
            ("connetto_bots", true),
            ("connetto_registration_codes", true),
            ("connetto_bot_lists", true),
            ("connetto_installations", true),
            ("connetto_installation_optional_tables", true),
        ];
        let mut expected = Vec::new();
        for (table, needs_enable) in tables {
            if needs_enable {
                expected.push(format!("ALTER TABLE \"{table}\" ENABLE ROW LEVEL SECURITY"));
                expected.push(format!(
                    "CREATE POLICY \"{table}_connetto_open\" ON \"{table}\" \
                     FOR ALL USING (true) WITH CHECK (true)"
                ));
            }
            expected.push(format!(
                "CREATE POLICY \"{table}_connetto_cap_read\" ON \"{table}\" AS RESTRICTIVE \
                 FOR SELECT USING ({})",
                list(&format!("{table}:read"))
            ));
            expected.push(format!(
                "CREATE POLICY \"{table}_connetto_cap_insert\" ON \"{table}\" AS RESTRICTIVE \
                 FOR INSERT WITH CHECK ({})",
                list(&format!("{table}:insert"))
            ));
            let update = list(&format!("{table}:update"));
            expected.push(format!(
                "CREATE POLICY \"{table}_connetto_cap_update\" ON \"{table}\" AS RESTRICTIVE \
                 FOR UPDATE USING ({update}) WITH CHECK ({update})"
            ));
            expected.push(format!(
                "CREATE POLICY \"{table}_connetto_cap_delete\" ON \"{table}\" AS RESTRICTIVE \
                 FOR DELETE USING ({})",
                list(&format!("{table}:delete"))
            ));
        }
        assert_eq!(
            cap_policies::<connetto_core::bots::TextIds>(&schema, policies)
                .expect("the documents parse"),
            expected.join(";\n")
        );
    }

    /// A table the schema document itself enables row-level security on is
    /// secured, so the cap adds no open policy for it. A `FOR ALL USING
    /// (true)` policy would admit every row alongside the table's real
    /// policy.
    #[test]
    fn a_schema_document_rls_enable_counts_as_secured() {
        let schema = majored(
            "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT); \
                              ALTER TABLE notes ENABLE ROW LEVEL SECURITY;",
        );
        let policies = "CREATE POLICY notes_p ON notes FOR ALL USING \
                        (owner = current_setting('app.user_id', true));";
        let cap = cap_policies::<connetto_core::bots::TextIds>(&schema, policies)
            .expect("the documents parse");
        assert!(
            !cap.contains("notes_connetto_open"),
            "the schema document enabled row-level security, so the cap adds \
             no open policy that would OR with the real one: {cap}"
        );
        assert!(
            !cap.contains("ALTER TABLE \"notes\" ENABLE ROW LEVEL SECURITY"),
            "the schema document already enabled row-level security: {cap}"
        );
    }

    /// The cap reaches the replica. The translated DDL names the
    /// `current_bot_list()` function the client registers, so a replica
    /// enforces the same rule its Postgres source holds.
    #[test]
    fn the_replica_carries_the_cap_through_the_bot_list_function() {
        let schema =
            majored("CREATE TABLE items (id INT PRIMARY KEY, owner TEXT NOT NULL, label TEXT);");
        let policies = "ALTER TABLE items ENABLE ROW LEVEL SECURITY;\n\
                        CREATE POLICY items_p ON items FOR ALL USING \
                        (owner = current_setting('app.user_id', true));";
        let bundle = translate::<String, connetto_core::bots::TextIds>(&schema, policies)
            .expect("translates");
        assert!(
            bundle.replica_ddl().contains("current_bot_list"),
            "the replica DDL names the bot list function: {}",
            bundle.replica_ddl()
        );
        // connetto adds the registry tables to the document it translates, so
        // the Postgres source and the replica DDL both carry them.
        for table in [
            "connetto_bots",
            "connetto_registration_codes",
            "connetto_bot_lists",
            "connetto_installations",
            "connetto_installation_optional_tables",
        ] {
            assert!(
                bundle
                    .schema_source()
                    .contains(&format!("CREATE TABLE {table} ")),
                "the Postgres source carries {table}: {}",
                bundle.schema_source()
            );
            assert!(
                bundle.replica_ddl().contains(table),
                "the replica DDL carries {table}"
            );
        }
    }

    /// The derivation and the database agree on the views over the
    /// deployment's own schema and policies.
    #[test]
    fn the_derived_views_are_the_views_sqlite_builds() {
        let options = options::<String>();
        let translator = parsed_documents(
            connetto_demo_deployment::SCHEMA_SQL,
            connetto_demo_deployment::POLICIES_SQL,
        )
        .expect("parse the deployment documents");
        let report = translator
            .translate_with_report(&options)
            .expect("translate the deployment");
        let ddl = statements_to_ddl(&report.script);
        let derived = view_names(&report.script);
        let built = sqlite_views(&ddl);
        assert!(!derived.is_empty(), "the deployment's policies build views");
        assert_eq!(
            derived, built,
            "the views a server derives without SQLite are the views SQLite builds"
        );
    }

    /// `raw_literal` round-trips, the emitted literal being a well-formed raw
    /// string that names the input byte for byte.
    #[test]
    fn raw_literal_round_trips_through_a_quote_and_a_hash_quote() {
        for text in [
            "plain",
            "with a \"quote\" inside",
            "with a #\" sequence",
            "with \" and #\" together",
        ] {
            let literal = raw_literal(text);
            assert!(literal.starts_with('r'), "raw literals open with r");
            let start = literal.find('"').expect("an opening quote");
            let end = literal.rfind('"').expect("a closing quote");
            assert!(end > start, "the literal has an interior");
            assert_eq!(&literal[start + 1..end], text, "the interior is the input");
        }
    }

    /// The rendered file names the bundle module and embeds the DDL verbatim.
    #[test]
    fn render_embeds_the_bundle_contents() {
        let bundle = SchemaBundle::new(
            majored("CREATE TABLE orders (id INT);"),
            "CREATE POLICY orders_p ON orders USING (true);",
            "CREATE TABLE orders_rls (id INTEGER);",
            [("orders", "orders_rls")],
            ["orders"],
            None::<&str>,
        )
        .expect("the source declares major 1");
        let source = render(&bundle, "");
        assert!(source.contains("pub mod connetto_schema_bundle"));
        assert!(source.contains("pub fn bundle() -> connetto_core::SchemaBundle"));
        assert!(source.contains(&raw_literal(bundle.replica_ddl())));
        assert!(
            source.contains("LOCAL_TIER_DDL: Option<&str> = None"),
            "the tier is an Option even when the build has none"
        );
    }

    /// The tier const is an `Option` with a tier too, so its type does not
    /// depend on the build input.
    #[test]
    fn render_keeps_the_tier_const_an_option_with_a_tier() {
        let bundle = SchemaBundle::new(
            majored("CREATE TABLE orders (id INT);"),
            "",
            "CREATE TABLE orders (id INTEGER);",
            [] as [(&str, &str); 0],
            [] as [&str; 0],
            None::<&str>,
        )
        .expect("the source declares major 1")
        .with_local_tier("CREATE TABLE notes (id INTEGER);");
        let source = render(&bundle, "");
        assert!(
            source.contains("LOCAL_TIER_DDL: Option<&str> = Some("),
            "the tier const stays an Option when the build has a tier"
        );
        assert!(source.contains(&raw_literal("CREATE TABLE notes (id INTEGER);")));
    }

    /// The slice consts borrow, so the file an application `include!`s
    /// compiles with any number of pairs, zero included.
    #[test]
    fn render_borrows_the_slice_consts() {
        let bundle = SchemaBundle::new(
            majored("CREATE TABLE orders (id INT);"),
            "",
            "CREATE TABLE orders_rls (id INTEGER);",
            [("orders", "orders_rls")],
            ["orders"],
            None::<&str>,
        )
        .expect("the source declares major 1");
        let source = render(&bundle, "");
        assert!(
            source.contains(
                "pub const POLICY_TABLES: &[(&str, &str)] = &[\n            (r\"orders\", r\"orders_rls\")\n        ];"
            ),
            "the pairs const is a borrowed slice: {source}"
        );
        assert!(
            source.contains("pub const POLICY_VIEWS: &[&str] = &[r\"orders\"];"),
            "the views const is a borrowed slice: {source}"
        );
        let empty = SchemaBundle::new(
            majored("CREATE TABLE orders (id INT);"),
            "",
            "CREATE TABLE orders (id INTEGER);",
            [] as [(&str, &str); 0],
            [] as [&str; 0],
            None::<&str>,
        )
        .expect("the source declares major 1");
        let source = render(&empty, "");
        assert!(
            source.contains("pub const POLICY_TABLES: &[(&str, &str)] = &[];"),
            "zero pairs still emit a borrowed slice: {source}"
        );
        assert!(
            source.contains("pub const POLICY_VIEWS: &[&str] = &[];"),
            "zero views still emit a borrowed slice: {source}"
        );
    }
    /// The source documents a build step reads, the schema source declaring
    /// `major`, written under `dir`. The last result is the DDL the same
    /// tier source translates to now.
    fn emit_inputs(
        dir: &std::path::Path,
        major: u32,
    ) -> (
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        String,
    ) {
        let schema = dir.join("schema.sql");
        let policies = dir.join("policies.sql");
        let tier = dir.join("tier.sql");
        let schema_sql = format!(
            "{} {major}\nCREATE TABLE orders (id INT PRIMARY KEY, label TEXT);",
            connetto_core::MAJOR_DIRECTIVE
        );
        let policies_sql = "ALTER TABLE orders ENABLE ROW LEVEL SECURITY; \
                            CREATE POLICY orders_p ON orders FOR ALL USING (true);";
        let tier_sql = "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT);";
        std::fs::write(&schema, schema_sql).expect("the schema source writes");
        std::fs::write(&policies, policies_sql).expect("the policies source writes");
        std::fs::write(&tier, tier_sql).expect("the tier source writes");
        (
            schema,
            policies,
            tier,
            translate_tier::<String>(tier_sql).expect("the tier translates"),
        )
    }

    /// A build without a tier writes the bundle file and attaches no
    /// history to it.
    #[test]
    fn emit_without_a_tier_attaches_no_history() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let (schema, policies, _, _) = emit_inputs(dir.path(), 1);
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).expect("the output directory writes");
        emit_to::<String, TextIds>(&schema, &policies, None, &out).expect("emits");
        let rendered =
            std::fs::read_to_string(out.join("connetto-schema.rs")).expect("the bundle file");
        assert!(
            rendered.contains("LOCAL_TIER_DDL: Option<&str> = None"),
            "a build without a tier has no tier const: {rendered}"
        );
        assert!(
            !rendered.contains("with_tier_history"),
            "a build without a tier attaches no history: {rendered}"
        );
        assert!(
            out.join("connetto-cap-policies.sql").exists(),
            "the cap document lands beside the bundle file"
        );
    }

    /// A build whose history holds a fresh export for its major attaches
    /// the history to the bundle it renders.
    #[test]
    fn emit_with_a_fresh_history_attaches_it() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let (schema, policies, tier, tier_ddl) = emit_inputs(dir.path(), 1);
        let history = dir.path().join("tier_history");
        std::fs::create_dir_all(&history).expect("the history directory writes");
        std::fs::write(history.join("1.sql"), tier_ddl).expect("the current export writes");
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).expect("the output directory writes");
        let source = TierSource::new(&tier, &history);
        emit_to::<String, TextIds>(&schema, &policies, Some(&source), &out)
            .expect("emits with the history");
        let rendered =
            std::fs::read_to_string(out.join("connetto-schema.rs")).expect("the bundle file");
        assert!(
            rendered.contains("LOCAL_TIER_DDL: Option<&str> = Some("),
            "a build with a tier carries its tier: {rendered}"
        );
        assert!(
            rendered.contains(".with_tier_history("),
            "the bundle attaches the history: {rendered}"
        );
        assert!(rendered.contains("connetto_core::TierHistory::new("));
        assert!(rendered.contains("connetto_core::Major::new(1)"));
        assert!(rendered.contains("the build step generated this history"));
    }

    /// A tier whose history directory is absent refuses the build.
    #[test]
    fn emit_refuses_a_missing_history_directory() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let (schema, policies, tier, _) = emit_inputs(dir.path(), 1);
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).expect("the output directory writes");
        let source = TierSource::new(&tier, dir.path().join("absent"));
        let err = emit_to::<String, TextIds>(&schema, &policies, Some(&source), &out)
            .expect_err("an absent history directory refuses");
        match err {
            SchemaError::MissingHistoryDir { dir: reported } => {
                assert_eq!(reported, dir.path().join("absent"));
            }
            other => panic!("the absent directory must refuse, got {other}"),
        }
    }

    /// A current export the translation no longer computes refuses the
    /// build as stale.
    #[test]
    fn emit_refuses_a_stale_current_export() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let (schema, policies, tier, _) = emit_inputs(dir.path(), 1);
        let history = dir.path().join("tier_history");
        std::fs::create_dir_all(&history).expect("the history directory writes");
        std::fs::write(
            history.join("1.sql"),
            "an export the sources no longer compute",
        )
        .expect("the stale export writes");
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).expect("the output directory writes");
        let source = TierSource::new(&tier, &history);
        let err = emit_to::<String, TextIds>(&schema, &policies, Some(&source), &out)
            .expect_err("a stale export refuses");
        match err {
            SchemaError::StaleExport { major, path, .. } => {
                assert_eq!(major, 1);
                assert_eq!(path, history.join("1.sql"));
            }
            other => panic!("a stale export must refuse, got {other}"),
        }
    }

    /// A history without the build's own major refuses the build.
    #[test]
    fn emit_refuses_a_missing_current_export() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let (schema, policies, tier, _) = emit_inputs(dir.path(), 1);
        let history = dir.path().join("tier_history");
        std::fs::create_dir_all(&history).expect("the history directory writes");
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).expect("the output directory writes");
        let source = TierSource::new(&tier, &history);
        let err = emit_to::<String, TextIds>(&schema, &policies, Some(&source), &out)
            .expect_err("a missing export refuses");
        match err {
            SchemaError::MissingExport { major, path, .. } => {
                assert_eq!(major, 1);
                assert_eq!(path, history.join("1.sql"));
            }
            other => panic!("a missing export must refuse, got {other}"),
        }
    }

    /// A history that skips a major between its lowest export and the
    /// build's major refuses the build.
    #[test]
    fn emit_refuses_a_gap_between_exports() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let (schema, policies, tier, tier_ddl) = emit_inputs(dir.path(), 3);
        let history = dir.path().join("tier_history");
        std::fs::create_dir_all(&history).expect("the history directory writes");
        std::fs::write(history.join("1.sql"), tier_ddl.clone()).expect("the first export writes");
        std::fs::write(history.join("3.sql"), tier_ddl).expect("the current export writes");
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).expect("the output directory writes");
        let source = TierSource::new(&tier, &history);
        let err = emit_to::<String, TextIds>(&schema, &policies, Some(&source), &out)
            .expect_err("a gap refuses");
        match err {
            SchemaError::HistoryGap { dir, missing, .. } => {
                assert_eq!(dir, history);
                assert_eq!(missing, 2);
            }
            other => panic!("a gap must refuse, got {other}"),
        }
    }

    /// The export command writes the current major's export and leaves
    /// the history's older exports untouched.
    #[test]
    fn export_tier_writes_the_current_major_and_keeps_the_older_ones() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let (schema, _policies, tier, tier_ddl) = emit_inputs(dir.path(), 2);
        let history = dir.path().join("tier_history");
        std::fs::create_dir_all(&history).expect("the history directory writes");
        std::fs::write(
            history.join("1.sql"),
            "an export the command never rewrites",
        )
        .expect("the older export writes");
        let outcome = export_tier::<String, TextIds>(&schema, &tier, &history, false)
            .expect("writes the current export");
        assert_eq!(outcome.path, history.join("2.sql"));
        assert_eq!(
            std::fs::read_to_string(&outcome.path).expect("the export"),
            tier_ddl
        );
        assert_eq!(
            std::fs::read_to_string(history.join("1.sql")).expect("the older export"),
            "an export the command never rewrites"
        );
    }

    /// The check mode writes nothing and reports the export it would
    /// write or refresh.
    #[test]
    fn export_tier_check_mode_reports_a_missing_or_stale_export() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let (schema, _policies, tier, tier_ddl) = emit_inputs(dir.path(), 1);
        let history = dir.path().join("tier_history");
        std::fs::create_dir_all(&history).expect("the history directory writes");
        std::fs::write(history.join("1.sql"), tier_ddl).expect("the export writes");
        let fresh = export_tier::<String, TextIds>(&schema, &tier, &history, true)
            .expect("a fresh export checks clean");
        assert_eq!(fresh.path, history.join("1.sql"));
        std::fs::write(history.join("1.sql"), "a drifted export").expect("the drift writes");
        let err = export_tier::<String, TextIds>(&schema, &tier, &history, true)
            .expect_err("a drifted export fails the check");
        match err {
            SchemaError::StaleExport { major, .. } => assert_eq!(major, 1),
            other => panic!("a drifted export must fail the check, got {other}"),
        }
        std::fs::remove_file(history.join("1.sql")).expect("the export deletes");
        let err = export_tier::<String, TextIds>(&schema, &tier, &history, true)
            .expect_err("a missing export fails the check");
        match err {
            SchemaError::MissingExport { major, .. } => assert_eq!(major, 1),
            other => panic!("a missing export must fail the check, got {other}"),
        }
        assert!(
            !history.join("1.sql").exists(),
            "the check mode never writes"
        );
    }
}
