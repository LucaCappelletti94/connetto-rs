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

use std::path::Path;

use connetto_core::auth::CapabilityKey;
use connetto_core::{
    AUDIT_TABLE, CALLER_FUNCTION, SUBJECTS_FUNCTION, SchemaBundle, UUID_FUNCTION,
    WRITE_EXEMPTION_FUNCTION,
};
use diesel::connection::SimpleConnection;
use diesel::{Connection, SqliteConnection};
use pg2sqlite::manifest::WrapperKind;
use pg2sqlite::prelude::{Pg2Sqlite, Pg2SqliteOptions, SessionVariableMapping, UuidRepresentation};
use sqlparser::ast::{CreateView, ObjectNamePart, Statement};
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

/// Translate the two Postgres source documents with connetto's fixed options
/// and return the bundle they produce.
///
/// The options are connetto's, not the caller's. They fix the `uuidv4` representation
/// and function, the `rls_audit` table, the `connetto_write_exempt` function,
/// and the caller and subjects mappings built from the core constants. `K`
/// names the capability key type, which fixes the subjects setting and
/// separator the mapping holds. The replica DDL is applied to a throwaway
/// in-memory database first, so a translation SQLite refuses is an error
/// here rather than a boot-time failure on the client.
///
/// # Errors
///
/// [`SchemaError::Translate`] when a source does not parse or the translation
/// fails, [`SchemaError::Sqlite`] when the replica DDL is not accepted.
pub fn translate<K: CapabilityKey>(
    schema_sql: &str,
    policies_sql: &str,
) -> Result<SchemaBundle, SchemaError> {
    let options = options::<K>();
    let translator = parsed_documents(schema_sql, policies_sql)?;
    let report = translator
        .translate_with_report(&options)
        .map_err(|err| SchemaError::Translate(err.to_string()))?;
    let ddl = statements_to_ddl(&report.statements);
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
        view_names(&report.statements),
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
/// (`SCHEMA_SOURCE`, `POLICIES_SOURCE`, `REPLICA_DDL`, and `LOCAL_TIER_DDL`
/// when the build has a local tier), so a `const` context such as `concat!`
/// can use them without re-deriving the bundle.
///
/// # Errors
///
/// As [`translate`], plus [`SchemaError::MissingOutDir`] outside a build
/// script and [`SchemaError::Sqlite`] for a refused local tier.
pub fn emit<K: CapabilityKey>(
    schema: &Path,
    policies: &Path,
    local_tier: Option<&Path>,
) -> Result<(), SchemaError> {
    println!("cargo::rerun-if-changed={}", schema.display());
    println!("cargo::rerun-if-changed={}", policies.display());
    let schema_sql = std::fs::read_to_string(schema)?;
    let policies_sql = std::fs::read_to_string(policies)?;
    let mut bundle = translate::<K>(&schema_sql, &policies_sql)?;
    if let Some(local_tier) = local_tier {
        println!("cargo::rerun-if-changed={}", local_tier.display());
        let tier_sql = std::fs::read_to_string(local_tier)?;
        let options = options::<K>();
        let tier = parsed_documents(&tier_sql, "")?;
        let report = tier
            .translate_with_report(&options)
            .map_err(|err| SchemaError::Translate(err.to_string()))?;
        let ddl = statements_to_ddl(&report.statements);
        validate(&ddl, "local tier")?;
        bundle = bundle.with_local_tier(ddl);
    }
    let out_dir = std::env::var("OUT_DIR").map_err(|_| SchemaError::MissingOutDir)?;
    std::fs::write(
        Path::new(&out_dir).join("connetto-schema.rs"),
        render(&bundle),
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
fn render(bundle: &SchemaBundle) -> String {
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
        let ddl = statements_to_ddl(&report.statements);
        let derived = view_names(&report.statements);
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
        let source = render(&bundle);
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
        let source = render(&bundle);
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
        let source = render(&bundle);
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
        let source = render(&empty);
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
