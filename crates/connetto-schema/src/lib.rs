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
use pg2sqlite::prelude::{Pg2Sqlite, Pg2SqliteOptions, SessionVariableMapping, UuidRepresentation};
use sqlparser::ast::{
    AlterTable, AlterTableOperation, CreateTable, CreateView, ObjectNamePart, Statement,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use thiserror::Error;

diesel::table! {
    /// SQLite's own catalogue, read to list the views a translation built.
    #[sql_name = "sqlite_schema"]
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
/// fails, [`SchemaError::Sqlite`] when the replica DDL is not accepted.
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
    let statements = report.script.into_vec();
    let ddl = statements_to_ddl(&statements);
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
        view_names(&statements),
        None::<&str>,
    ))
}

/// The build-script entry point.
///
/// Reads the two Postgres source documents, translates the synced tier and,
/// when `local_tier` is given, the demo's own local tier as a separate
/// reference universe, validates both DDLs against a throwaway SQLite
/// database, and writes `connetto-schema.rs` under `OUT_DIR`. It prints
/// `cargo::rerun-if-changed` for every file it reads.
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
/// # Errors
///
/// As [`translate`], plus [`SchemaError::MissingOutDir`] outside a build
/// script and [`SchemaError::Sqlite`] for a refused local tier.
pub fn emit<K: CapabilityKey, Id: BotRegistryIdSql>(
    schema: &Path,
    policies: &Path,
    local_tier: Option<&Path>,
) -> Result<(), SchemaError> {
    println!("cargo::rerun-if-changed={}", schema.display());
    println!("cargo::rerun-if-changed={}", policies.display());
    let schema_sql = std::fs::read_to_string(schema)?;
    let policies_sql = std::fs::read_to_string(policies)?;
    let cap = cap_policies::<Id>(&schema_sql, &policies_sql)?;
    let mut bundle = translate::<K, Id>(&schema_sql, &policies_sql)?;
    if let Some(local_tier) = local_tier {
        println!("cargo::rerun-if-changed={}", local_tier.display());
        let tier_sql = std::fs::read_to_string(local_tier)?;
        let options = options::<K>();
        let tier = parsed_documents(&tier_sql, "")?;
        let report = tier
            .translate_with_report(&options)
            .map_err(|err| SchemaError::Translate(err.to_string()))?;
        let ddl = statements_to_ddl(&report.script.into_vec());
        validate(&ddl, "local tier")?;
        bundle = bundle.with_local_tier(ddl);
    }
    let out_dir = std::env::var("OUT_DIR").map_err(|_| SchemaError::MissingOutDir)?;
    std::fs::write(Path::new(&out_dir).join("connetto-cap-policies.sql"), &cap)?;
    std::fs::write(
        Path::new(&out_dir).join("connetto-schema.rs"),
        render(&bundle, &cap),
    )?;
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
/// a `;` after the last.
fn statements_to_ddl(statements: &[Statement]) -> String {
    let mut ddl = statements
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
fn view_names(statements: &[Statement]) -> Vec<String> {
    statements
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
/// `const` contexts that cannot re-derive the bundle.
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
         }}\n\
         }}\n",
        raw_literal(bundle.schema_source()),
        raw_literal(bundle.policies_source()),
        raw_literal(bundle.replica_ddl()),
        raw_literal(cap),
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
        let schema = "CREATE TABLE orders (id INT PRIMARY KEY, label TEXT); \
                      CREATE TABLE notes (id INT PRIMARY KEY, body TEXT);";
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
            cap_policies::<connetto_core::bots::TextIds>(schema, policies)
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
        let schema = "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT); \
                      ALTER TABLE notes ENABLE ROW LEVEL SECURITY;";
        let policies = "CREATE POLICY notes_p ON notes FOR ALL USING \
                        (owner = current_setting('app.user_id', true));";
        let cap = cap_policies::<connetto_core::bots::TextIds>(schema, policies)
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
        let schema = "CREATE TABLE items (id INT PRIMARY KEY, owner TEXT NOT NULL, label TEXT);";
        let policies = "ALTER TABLE items ENABLE ROW LEVEL SECURITY;\n\
                        CREATE POLICY items_p ON items FOR ALL USING \
                        (owner = current_setting('app.user_id', true));";
        let bundle = translate::<String, connetto_core::bots::TextIds>(schema, policies)
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
        let statements = report.script.into_vec();
        let ddl = statements_to_ddl(&statements);
        let derived = view_names(&statements);
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
            "CREATE TABLE orders (id INT);",
            "CREATE POLICY orders_p ON orders USING (true);",
            "CREATE TABLE orders_rls (id INTEGER);",
            [("orders", "orders_rls")],
            ["orders"],
            None::<&str>,
        );
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
            "CREATE TABLE orders (id INT);",
            "",
            "CREATE TABLE orders (id INTEGER);",
            [] as [(&str, &str); 0],
            [] as [&str; 0],
            None::<&str>,
        )
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
            "CREATE TABLE orders (id INT);",
            "",
            "CREATE TABLE orders_rls (id INTEGER);",
            [("orders", "orders_rls")],
            ["orders"],
            None::<&str>,
        );
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
            "CREATE TABLE orders (id INT);",
            "",
            "CREATE TABLE orders (id INTEGER);",
            [] as [(&str, &str); 0],
            [] as [&str; 0],
            None::<&str>,
        );
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
}
