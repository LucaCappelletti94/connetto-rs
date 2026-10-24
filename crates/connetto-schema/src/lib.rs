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

use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;
use std::path::Path;

use connetto_core::bots::BotRegistryIdSql;

use connetto_core::auth::CapabilityKey;
/// The registry id markers build scripts and other diesel-free callers pass
/// for `emit` and `translate`, re-exported beside [`translate`].
pub use connetto_core::bots::{TextIds, UuidIds};
use connetto_core::sql::quote_ident;
use connetto_core::{
    AUDIT_TABLE, BOT_LIST_FUNCTION, BOT_LIST_SEPARATOR, BOT_LIST_SETTING, BOT_LIST_WILDCARD,
    CALLER_FUNCTION, SUBJECTS_FUNCTION, SchemaBundle, SharedLayout, UUID_FUNCTION,
    WRITE_EXEMPTION_FUNCTION,
};
use diesel::connection::SimpleConnection;
use diesel::{Connection, SqliteConnection};
use pg2sqlite::manifest::WrapperKind;
use pg2sqlite::prelude::{Pg2Sqlite, Pg2SqliteOptions, SessionVariableMapping, UuidRepresentation};
use pg2sqlite::script::{FreshFiles, Script};
use sqlparser::ast::{
    AlterTable, AlterTableOperation, ColumnDef, ColumnOption, CreateTable, CreateView, Expr,
    Function, FunctionArg, FunctionArgExpr, FunctionArguments, ObjectNamePart, Statement,
    TableConstraint, Value, ValueWithSpan, visit_expressions, visit_relations,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::{Parser, ParserError};
use sqlparser::tokenizer::{Location, Token};
use thiserror::Error;

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
    /// The shared table list names a table the synced schema does not declare.
    #[error("the shared table list names `{table}`, which the synced schema does not declare")]
    SharedTableUndeclared {
        /// The listed name.
        table: String,
    },
    /// A listed table's rows differ by caller, so one copy cannot serve every
    /// account on a device.
    #[error("`{table}` cannot be shared, because its policy `{policy}` reads the caller")]
    SharedTableReadsCaller {
        /// The listed table.
        table: String,
        /// The policy on it that reads the caller, directly or through a
        /// table it reads.
        policy: String,
    },
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

/// The listed tables, as the schema declares them, that a device may store
/// once for every account.
///
/// A table qualifies only when every caller reads the same rows of it, since
/// a withdrawal reaches its caller as a plain delete and would take a row out
/// of the one copy another account still reads. A deployment policy reading
/// any session setting but the bot list reads the caller, and so does one
/// reading a table whose own policy does, because Postgres applies that
/// table's policy inside the subquery.
///
/// # Errors
///
/// [`SchemaError::SharedTableUndeclared`] for a name the synced schema does
/// not declare, [`SchemaError::SharedTableReadsCaller`] for a table whose
/// rows differ by caller, and [`SchemaError::Translate`] when a document does
/// not parse.
pub fn shared_tables<Id: BotRegistryIdSql>(
    schema_sql: &str,
    policies_sql: &str,
    tables: &[&str],
) -> Result<Vec<String>, SchemaError> {
    let schema_sql = with_registry::<Id>(schema_sql);
    let declared = schema_tables(&schema_sql)?;
    let mut per_caller = per_caller_tables(&[&schema_sql, policies_sql])?;
    let mut shared: Vec<String> = Vec::new();
    for listed in tables {
        let table = declared
            .iter()
            .find(|declared| declared.eq_ignore_ascii_case(listed))
            .ok_or_else(|| SchemaError::SharedTableUndeclared {
                table: (*listed).to_owned(),
            })?;
        if let Some(policy) = per_caller.remove(&table.to_lowercase()) {
            return Err(SchemaError::SharedTableReadsCaller {
                table: table.clone(),
                policy,
            });
        }
        if !shared.contains(table) {
            shared.push(table.clone());
        }
    }
    Ok(shared)
}

/// Every table whose rows differ by caller, lowercased, mapped to the policy
/// that makes them differ.
fn per_caller_tables(documents: &[&str]) -> Result<BTreeMap<String, String>, SchemaError> {
    /// What one policy reads.
    struct Reads {
        table: String,
        policy: String,
        caller: bool,
        tables: BTreeSet<String>,
    }
    let mut policies = Vec::new();
    for document in documents {
        for statement in parse(document, "a source document")? {
            let Statement::CreatePolicy(policy) = statement else {
                continue;
            };
            let Some(table) = table_name(&policy.table_name) else {
                continue;
            };
            let mut reads = Reads {
                table: table.to_lowercase(),
                policy: policy.name.value,
                caller: false,
                tables: BTreeSet::new(),
            };
            for expr in policy.using.iter().chain(&policy.with_check) {
                reads.caller |= reads_caller(expr);
                let _ = visit_relations(expr, |relation| {
                    if let Some(name) = table_name(relation) {
                        reads.tables.insert(name.to_lowercase());
                    }
                    ControlFlow::<()>::Continue(())
                });
            }
            policies.push(reads);
        }
    }
    let mut per_caller = BTreeMap::new();
    loop {
        let known = per_caller.len();
        for reads in &policies {
            if !per_caller.contains_key(&reads.table)
                && (reads.caller || reads.tables.iter().any(|t| per_caller.contains_key(t)))
            {
                per_caller.insert(reads.table.clone(), reads.policy.clone());
            }
        }
        if per_caller.len() == known {
            return Ok(per_caller);
        }
    }
}

/// Whether `expr` reads a session setting other than the bot list, which is
/// how a policy reads the caller's identity or the keys it holds.
fn reads_caller(expr: &Expr) -> bool {
    visit_expressions(expr, |expr| match expr {
        Expr::Function(function) if reads_a_caller_setting(function) => ControlFlow::Break(()),
        _ => ControlFlow::Continue(()),
    })
    .is_break()
}

/// Whether `function` is `current_setting` over anything but the bot list.
fn reads_a_caller_setting(function: &Function) -> bool {
    if !table_name(&function.name).is_some_and(|name| name.eq_ignore_ascii_case("current_setting"))
    {
        return false;
    }
    let FunctionArguments::List(list) = &function.args else {
        return true;
    };
    !matches!(
        list.args.first(),
        Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(ValueWithSpan {
            value: Value::SingleQuotedString(setting),
            ..
        })))) if setting == BOT_LIST_SETTING
    )
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
/// the replica holds the cap its Postgres source holds. The schema reaches the
/// replica translation without its references, which the server alone
/// enforces, while the bundle keeps the source as written. The replica DDL is
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
    translated::<K, Id>(schema_sql, policies_sql, &[])
}

/// Translate the two Postgres source documents with connetto's fixed options,
/// placing the validated `shared` tables in a separate `connetto_shared` store.
///
/// As [`translate`], but first checks `shared` under [`shared_tables`] and
/// compiles the shared store's four lifecycle programs from a second
/// translation that places those tables in the `connetto_shared` schema. The
/// bundle carries the shared tables and the layout beside the unshared
/// replica DDL; the version is the unshared one, since where a device stores a
/// table changes nothing on the wire.
///
/// # Errors
///
/// As [`translate`], plus [`SchemaError::SharedTableUndeclared`] and
/// [`SchemaError::SharedTableReadsCaller`] when the list is refused.
pub fn translate_shared<K: CapabilityKey, Id: BotRegistryIdSql>(
    schema_sql: &str,
    policies_sql: &str,
    shared: &[&str],
) -> Result<SchemaBundle, SchemaError> {
    let shared = shared_tables::<Id>(schema_sql, policies_sql, shared)?;
    translated::<K, Id>(schema_sql, policies_sql, &shared)
}

/// The shared step behind [`translate`] and [`translate_shared`]: translate
/// the synced tier, and when `shared` is non-empty compile its layout.
fn translated<K: CapabilityKey, Id: BotRegistryIdSql>(
    schema_sql: &str,
    policies_sql: &str,
    shared: &[String],
) -> Result<SchemaBundle, SchemaError> {
    let schema_sql = with_registry::<Id>(schema_sql);
    let options = options::<K>();
    let mut translator = parsed_documents(&without_references(&schema_sql)?, policies_sql)?;
    let cap = cap_policies_inner(&schema_sql, policies_sql)?;
    if !cap.is_empty() {
        translator = translator
            .sql(&cap)
            .map_err(|err| SchemaError::Translate(err.to_string()))?;
    }
    let report = translator
        .translate_with_report(&options)
        .map_err(|err| SchemaError::Translate(err.to_string()))?;
    let replica_ddl = statements_to_ddl(report.script.iter());
    validate(&replica_ddl, "replica")?;
    let connection_ddl = connection_program(&report.script)?;
    let manifest = translator
        .translation_manifest(&options)
        .map_err(|err| SchemaError::Translate(err.to_string()))?;
    let pairs = manifest
        .iter()
        .filter(|entry| entry.wrapper == WrapperKind::RlsView)
        .map(|entry| (entry.logical.clone(), entry.physical.clone()))
        .collect::<Vec<(String, String)>>();
    let views = view_names(report.script.iter());
    let mut bundle = SchemaBundle::new(
        schema_sql,
        policies_sql,
        replica_ddl,
        pairs,
        views,
        None::<&str>,
    )
    .with_connection_ddl(connection_ddl)
    .with_shared_tables(shared.iter().cloned());
    if !shared.is_empty() {
        let shared_options =
            options.with_attached_tables("connetto_shared", shared.iter().cloned());
        let shared_report = translator
            .translate_with_report(&shared_options)
            .map_err(|err| SchemaError::Translate(err.to_string()))?;
        let layout = shared_layout(&shared_report.script)?;
        bundle = bundle.with_shared_layout(layout);
    }
    Ok(bundle)
}

/// `schema_sql` with every column `REFERENCES` and table `FOREIGN KEY` clause
/// removed.
///
/// A replica is a partial copy, so visibility, paging and eviction all leave
/// a child without its parent, and SQLite enforcing the server's references
/// there could only refuse what the server already accepted (R92). A
/// statement declaring one is rendered back from its parsed form without it,
/// an `ALTER TABLE` adding nothing else is dropped, and every other statement
/// passes through as its source text.
fn without_references(schema_sql: &str) -> Result<String, SchemaError> {
    let unparsable = |err: ParserError| {
        SchemaError::Translate(format!("the schema document does not parse: {err}"))
    };
    let mut parser = Parser::new(&PostgreSqlDialect {})
        .try_with_sql(schema_sql)
        .map_err(unparsable)?;
    let lines = line_starts(schema_sql);
    let mut out = String::with_capacity(schema_sql.len());
    loop {
        while parser.consume_token(&Token::SemiColon) {}
        let start = parser.peek_token_ref();
        if start.token == Token::EOF {
            return Ok(out);
        }
        let from = offset(schema_sql, &lines, start.span.start);
        let mut statement = parser.parse_statement().map_err(unparsable)?;
        match drop_references(&mut statement) {
            Dropped::Nothing => {
                let to = offset(schema_sql, &lines, parser.get_current_token().span.end);
                out.push_str(&schema_sql[from..to]);
            }
            Dropped::Some => out.push_str(&statement.to_string()),
            Dropped::All => continue,
        }
        out.push_str(";\n");
    }
}

/// What removing a statement's references left of it.
enum Dropped {
    /// It declared none.
    Nothing,
    /// It declared some and keeps the rest.
    Some,
    /// It declared nothing else.
    All,
}

/// Remove the references `statement` declares.
fn drop_references(statement: &mut Statement) -> Dropped {
    let mut dropped = false;
    match statement {
        Statement::CreateTable(table) => {
            table.constraints.retain(|constraint| {
                let reference = matches!(constraint, TableConstraint::ForeignKey(_));
                dropped |= reference;
                !reference
            });
            for column in &mut table.columns {
                dropped |= drop_column_references(column);
            }
        }
        Statement::AlterTable(alter) => {
            alter.operations.retain_mut(|operation| match operation {
                AlterTableOperation::AddConstraint {
                    constraint: TableConstraint::ForeignKey(_),
                    ..
                } => {
                    dropped = true;
                    false
                }
                AlterTableOperation::AddColumn { column_def, .. } => {
                    dropped |= drop_column_references(column_def);
                    true
                }
                _ => true,
            });
            if alter.operations.is_empty() {
                return Dropped::All;
            }
        }
        _ => {}
    }
    if dropped {
        Dropped::Some
    } else {
        Dropped::Nothing
    }
}

/// Remove a column's `REFERENCES`, reporting whether it had one.
fn drop_column_references(column: &mut ColumnDef) -> bool {
    let before = column.options.len();
    column
        .options
        .retain(|option| !matches!(option.option, ColumnOption::ForeignKey(_)));
    column.options.len() != before
}

/// The byte offset each line of `text` starts at.
fn line_starts(text: &str) -> Vec<usize> {
    core::iter::once(0)
        .chain(text.match_indices('\n').map(|(at, _)| at + 1))
        .collect()
}

/// The byte offset of a tokenizer location, whose line and column both count
/// from one and whose column counts characters.
fn offset(text: &str, lines: &[usize], at: Location) -> usize {
    let line = usize::try_from(at.line)
        .unwrap_or(usize::MAX)
        .saturating_sub(1);
    let column = usize::try_from(at.column)
        .unwrap_or(usize::MAX)
        .saturating_sub(1);
    let start = lines.get(line).copied().unwrap_or(text.len());
    text[start..]
        .char_indices()
        .nth(column)
        .map_or(text.len(), |(at, _)| start + at)
}

/// The build-script entry point.
///
/// Reads the two Postgres source documents, translates the synced tier and,
/// when `local_tier` is given, the demo's own local tier as a separate
/// reference universe, validates both DDLs against a throwaway SQLite
/// database, checks `shared` under [`shared_tables`], and writes
/// `connetto-schema.rs` under `OUT_DIR`. It prints `cargo::rerun-if-changed`
/// for every file it reads.
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
/// As [`translate`] and [`shared_tables`], plus [`SchemaError::MissingOutDir`]
/// outside a build script and [`SchemaError::Sqlite`] for a refused local
/// tier.
pub fn emit<K: CapabilityKey, Id: BotRegistryIdSql>(
    schema: &Path,
    policies: &Path,
    local_tier: Option<&Path>,
    shared: &[&str],
) -> Result<(), SchemaError> {
    println!("cargo::rerun-if-changed={}", schema.display());
    println!("cargo::rerun-if-changed={}", policies.display());
    let schema_sql = std::fs::read_to_string(schema)?;
    let policies_sql = std::fs::read_to_string(policies)?;
    let cap = cap_policies::<Id>(&schema_sql, &policies_sql)?;
    let mut bundle = translate_shared::<K, Id>(&schema_sql, &policies_sql, shared)?;
    if let Some(local_tier) = local_tier {
        println!("cargo::rerun-if-changed={}", local_tier.display());
        let tier_sql = std::fs::read_to_string(local_tier)?;
        let options = options::<K>();
        let tier = parsed_documents(&tier_sql, "")?;
        let report = tier
            .translate_with_report(&options)
            .map_err(|err| SchemaError::Translate(err.to_string()))?;
        let ddl = statements_to_ddl(report.script.iter());
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
fn statements_to_ddl<'a>(statements: impl Iterator<Item = &'a Statement>) -> String {
    let mut ddl = statements
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
fn view_names<'a>(statements: impl Iterator<Item = &'a Statement>) -> Vec<String> {
    statements
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

/// The program a connection to an existing replica runs, the statements that
/// recreate the source's `TEMP` objects.
fn connection_program(script: &Script) -> Result<String, SchemaError> {
    let program = script.connect().map_err(|err| {
        SchemaError::Translate(format!("the connection program cannot be rendered: {err}"))
    })?;
    Ok(statements_to_ddl(program))
}

/// The shared store's four lifecycle programs, compiled from the shared
/// translation's script and validated against a throwaway database with the
/// store attached.
fn shared_layout(script: &Script) -> Result<SharedLayout, SchemaError> {
    let fresh_both = selection(script, FreshFiles::Both, "the both-fresh program")?;
    let fresh_main = selection(script, FreshFiles::Main, "the main-fresh program")?;
    let fresh_shared = selection(script, FreshFiles::Attached, "the shared-fresh program")?;
    let reopen = connection_program(script)?;
    // The both-fresh program creates every file object, so applying it to a
    // throwaway database with the store attached is what proves SQLite accepts
    // the placement.
    validate_shared(&fresh_both)?;
    Ok(SharedLayout::new(
        fresh_both,
        fresh_main,
        fresh_shared,
        reopen,
    ))
}

/// One fresh-file selection of a script, rendered as its DDL.
fn selection(
    script: &Script,
    files: FreshFiles,
    what: &'static str,
) -> Result<String, SchemaError> {
    let program = script
        .initialize(files)
        .map_err(|err| SchemaError::Translate(format!("{what} cannot be rendered: {err}")))?;
    Ok(statements_to_ddl(program))
}

/// Apply `program` to a throwaway in-memory database with the shared store
/// attached, failing when SQLite refuses it.
fn validate_shared(program: &str) -> Result<(), SchemaError> {
    let mut probe = SqliteConnection::establish(":memory:").map_err(|err| SchemaError::Sqlite {
        tier: "shared store",
        detail: err.to_string(),
    })?;
    probe
        .batch_execute("ATTACH ':memory:' AS connetto_shared")
        .map_err(|err| SchemaError::Sqlite {
            tier: "shared store",
            detail: err.to_string(),
        })?;
    probe
        .batch_execute(program)
        .map_err(|err| SchemaError::Sqlite {
            tier: "shared store",
            detail: err.to_string(),
        })?;
    Ok(())
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
    let views = borrowed_slice(bundle.policy_views());
    let shared = borrowed_slice(bundle.shared_tables());
    let layout = match bundle.shared_layout() {
        Some(layout) => {
            // An `Option` either way, so the const's type never depends on
            // whether this build shares a table.
            format!(
                "pub const SHARED_LAYOUT: Option<(&str, &str, &str, &str)> = Some(({}, {}, {}, {}));",
                raw_literal(layout.sql(true, true)),
                raw_literal(layout.sql(true, false)),
                raw_literal(layout.sql(false, true)),
                raw_literal(layout.sql(false, false)),
            )
        }
        None => "pub const SHARED_LAYOUT: Option<(&str, &str, &str, &str)> = None;".to_string(),
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
        /// The connection program that recreates the TEMP objects a source leaves.\n\
        pub const CONNECTION_DDL: &str = {};\n\
        /// The bot cap the deployment applies beside its schema and policies.\n\
        pub const CAP_POLICIES: &str = {};\n\
         /// The translated local tier, when the build has one.\n\
         {tier}\n\
         /// The (logical, physical) pairs the translation split.\n\
         pub const POLICY_TABLES: &[(&str, &str)] = {tables};\n\
         /// Every view the translation emitted.\n\
         pub const POLICY_VIEWS: &[&str] = {views};\n\
         /// The tables a device stores once for every account.\n\
         pub const SHARED_TABLES: &[&str] = {shared};\n\
         /// The shared store's four lifecycle programs, when the build shares a\n\
         /// table. The tuple is (both-fresh, main-fresh, shared-fresh, reopen).\n\
         {layout}\n\
         /// The schema bundle this build translated from its own Postgres\n\
         /// sources. The version is the hash of exactly these contents.\n\
         #[must_use]\n\
         pub fn bundle() -> connetto_core::SchemaBundle {{\n\
         let mut bundle = connetto_core::SchemaBundle::new(\n\
             SCHEMA_SOURCE,\n\
             POLICIES_SOURCE,\n\
             REPLICA_DDL,\n\
             POLICY_TABLES.iter().copied(),\n\
             POLICY_VIEWS.iter().copied(),\n\
             LOCAL_TIER_DDL,\n\
         )\n\
         .with_shared_tables(SHARED_TABLES.iter().copied())\n\
         .with_connection_ddl(CONNECTION_DDL);\n\
         if let Some((both_fresh, main_fresh, shared_fresh, reopen)) = SHARED_LAYOUT {{\n\
             bundle = bundle.with_shared_layout(\n\
                 connetto_core::SharedLayout::new(both_fresh, main_fresh, shared_fresh, reopen),\n\
             );\n\
         }}\n\
         bundle\n\
         }}\n\
         }}\n",
        raw_literal(bundle.schema_source()),
        raw_literal(bundle.policies_source()),
        raw_literal(bundle.replica_ddl()),
        raw_literal(bundle.connection_ddl()),
        raw_literal(cap),
    )
}

/// `names` as a borrowed slice literal of raw strings.
fn borrowed_slice(names: &[String]) -> String {
    let names = names
        .iter()
        .map(|name| raw_literal(name))
        .collect::<Vec<_>>()
        .join(", ");
    format!("&[{names}]")
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
        let ddl = statements_to_ddl(report.script.iter());
        let derived = view_names(report.script.iter());
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

    /// A deployment schema with a public table, a constant-policy table, an
    /// owned table, a keyed table and a table whose policy reads the owned one.
    const SHARING_SCHEMA: &str = "CREATE TABLE words (id INT PRIMARY KEY, word TEXT); \
                                  CREATE TABLE posts (id INT PRIMARY KEY, published BOOLEAN); \
                                  CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT); \
                                  CREATE TABLE papers (id INT PRIMARY KEY, viewer TEXT); \
                                  CREATE TABLE tags (id INT PRIMARY KEY, note_id INT);";

    /// The policies [`SHARING_SCHEMA`] carries.
    fn sharing_policies() -> String {
        let keys = <String as CapabilityKey>::SETTING;
        format!(
            "ALTER TABLE posts ENABLE ROW LEVEL SECURITY; \
             CREATE POLICY posts_p ON posts FOR SELECT USING (published); \
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY; \
             CREATE POLICY notes_p ON notes FOR ALL USING \
               (owner = current_setting('app.user_id', true)); \
             ALTER TABLE papers ENABLE ROW LEVEL SECURITY; \
             CREATE POLICY papers_p ON papers FOR SELECT USING \
               (viewer = ANY(string_to_array(current_setting('{keys}', true), ','))); \
             ALTER TABLE tags ENABLE ROW LEVEL SECURITY; \
             CREATE POLICY tags_p ON tags FOR SELECT USING \
               (EXISTS (SELECT 1 FROM notes n WHERE n.id = tags.note_id));"
        )
    }

    fn shared(tables: &[&str]) -> Result<Vec<String>, SchemaError> {
        shared_tables::<connetto_core::bots::TextIds>(SHARING_SCHEMA, &sharing_policies(), tables)
    }

    /// A table every caller reads in full is shareable, whether it carries no
    /// policy of its own or one naming neither the caller nor its keys.
    #[test]
    fn caller_independent_tables_are_shareable() {
        assert_eq!(
            shared(&["Words", "posts"]).expect("both are shareable"),
            ["words", "posts"]
        );
    }

    /// A policy reading the caller makes the table's rows differ by account.
    #[test]
    fn a_table_whose_policy_reads_the_caller_is_refused() {
        assert!(matches!(
            shared(&["words", "notes"]),
            Err(SchemaError::SharedTableReadsCaller { table, policy })
                if table == "notes" && policy == "notes_p"
        ));
    }

    /// A policy reading the keys the caller holds is refused the same way.
    #[test]
    fn a_table_whose_policy_reads_the_keys_is_refused() {
        assert!(matches!(
            shared(&["papers"]),
            Err(SchemaError::SharedTableReadsCaller { table, policy })
                if table == "papers" && policy == "papers_p"
        ));
    }

    /// Postgres applies the read table's own policy inside a policy's
    /// subquery, so reading a per-caller table makes this one per-caller too.
    #[test]
    fn a_table_whose_policy_reads_a_per_caller_table_is_refused() {
        assert!(matches!(
            shared(&["tags"]),
            Err(SchemaError::SharedTableReadsCaller { table, policy })
                if table == "tags" && policy == "tags_p"
        ));
    }

    /// A name the synced schema does not declare is refused rather than
    /// silently shared as nothing.
    #[test]
    fn an_undeclared_table_is_refused() {
        assert!(matches!(
            shared(&["drafts"]),
            Err(SchemaError::SharedTableUndeclared { table }) if table == "drafts"
        ));
    }

    /// The replica a translation produces carries no synced reference, and
    /// it is the replica the same schema written without references produces,
    /// while the source the server enforces keeps its keys.
    #[test]
    fn the_replica_translation_drops_references_and_keeps_the_rest() {
        let with = "CREATE TABLE folders (id INT PRIMARY KEY, code TEXT UNIQUE); \
                    CREATE TABLE notes (id INT PRIMARY KEY, \
                      folder_id INT NOT NULL REFERENCES folders(id) ON DELETE CASCADE, \
                      code TEXT, label TEXT DEFAULT 'x' CHECK (label <> ''), \
                      CONSTRAINT to_code FOREIGN KEY (code) REFERENCES folders(code)); \
                    CREATE TABLE pins (id INT PRIMARY KEY, note_id INT); \
                    ALTER TABLE pins ADD CONSTRAINT to_note FOREIGN KEY (note_id) REFERENCES notes(id);";
        let without = "CREATE TABLE folders (id INT PRIMARY KEY, code TEXT UNIQUE); \
                       CREATE TABLE notes (id INT PRIMARY KEY, folder_id INT NOT NULL, \
                         code TEXT, label TEXT DEFAULT 'x' CHECK (label <> '')); \
                       CREATE TABLE pins (id INT PRIMARY KEY, note_id INT);";
        let bundle = translate::<String, connetto_core::bots::TextIds>(with, "")
            .expect("translates with references");
        let plain = translate::<String, connetto_core::bots::TextIds>(without, "")
            .expect("translates without references");
        assert_eq!(bundle.replica_ddl(), plain.replica_ddl());
        assert!(bundle.schema_source().contains("REFERENCES folders(id)"));
        assert!(bundle.schema_source().contains("REFERENCES notes(id)"));
    }

    // The consumer behavior of the shared store layout, read through the
    // replica's logical names the way an application does.

    diesel::table! {
        /// The shareable table the layout consumer tests translate.
        words (id) {
            id -> Integer,
            word -> Text,
        }
    }

    diesel::table! {
        /// The caller-private main table the shared one joins against.
        notes (id) {
            id -> Integer,
            word_id -> Integer,
            owner_id -> Text,
            body -> Text,
        }
    }

    diesel::allow_tables_to_appear_in_same_query!(words, notes);

    /// The schema the layout consumer tests translate, a shareable table and a
    /// caller-private one.
    const SHARED_CONSUMER_SCHEMA: &str = "CREATE TABLE words (id INT PRIMARY KEY, word TEXT); \
                                          CREATE TABLE notes (id INT PRIMARY KEY, \
                                            word_id INT NOT NULL, owner_id TEXT NOT NULL, \
                                            body TEXT);";

    /// The policies [`SHARED_CONSUMER_SCHEMA`] carries, constant on the shared
    /// `words` and private to the caller on `notes`.
    const SHARED_CONSUMER_POLICIES: &str = "ALTER TABLE words ENABLE ROW LEVEL SECURITY; \
                                            CREATE POLICY words_p ON words FOR ALL USING (true); \
                                            ALTER TABLE notes ENABLE ROW LEVEL SECURITY; \
                                            CREATE POLICY notes_p ON notes FOR ALL USING \
                                              (owner_id = current_setting('app.user_id', true));";

    /// The bundle a build of the consumer schema sharing `words` produces.
    fn shared_consumer_bundle() -> connetto_core::SchemaBundle {
        translate_shared::<String, connetto_core::bots::TextIds>(
            SHARED_CONSUMER_SCHEMA,
            SHARED_CONSUMER_POLICIES,
            &["words"],
        )
        .expect("the schema translates with a shared store")
    }

    /// A fresh replica connection with the shared store attached from `shared`.
    fn conn_with_shared(shared: &str) -> SqliteConnection {
        let mut conn = SqliteConnection::establish(":memory:").expect("open the replica");
        conn.batch_execute(&format!("ATTACH '{shared}' AS connetto_shared"))
            .expect("attach the shared store");
        conn
    }

    /// Register the replica functions a translated replica calls, holding the
    /// write exemption open so the test's own writes are admitted.
    fn register_replica_functions(conn: &mut SqliteConnection, caller: &str, bot_list: &str) {
        use diesel::sqlite::SqliteFunctionBehavior;
        let behavior = SqliteFunctionBehavior::DETERMINISTIC | SqliteFunctionBehavior::INNOCUOUS;
        let caller = caller.to_owned();
        conn.register_noarg_sql_function::<diesel::sql_types::Text, _, _>(
            CALLER_FUNCTION,
            behavior,
            move || caller.clone(),
        )
        .expect("register the caller");
        conn.register_noarg_sql_function::<
            diesel::sql_types::Nullable<diesel::sql_types::Text>,
            _,
            _,
        >(
            SUBJECTS_FUNCTION,
            behavior,
            move || None::<String>,
        )
        .expect("register the subjects");
        let bot_list = bot_list.to_owned();
        conn.register_noarg_sql_function::<diesel::sql_types::Text, _, _>(
            BOT_LIST_FUNCTION,
            behavior,
            move || bot_list.clone(),
        )
        .expect("register the bot list");
        conn.register_noarg_sql_function::<diesel::sql_types::Bool, _, _>(
            WRITE_EXEMPTION_FUNCTION,
            SqliteFunctionBehavior::INNOCUOUS,
            move || true,
        )
        .expect("register the write exemption");
    }

    /// A guard that removes its temp files on drop.
    struct TempFiles(Vec<std::path::PathBuf>);

    impl Drop for TempFiles {
        fn drop(&mut self) {
            for path in &self.0 {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    /// A unique temp file path for one test run.
    fn temp_file(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("connetto-shared-{}-{name}", std::process::id()));
        path
    }

    fn url(path: &std::path::Path) -> String {
        path.to_str().expect("a utf-8 temporary path").to_owned()
    }

    /// A policy-independent shared table joins with a caller-private main table
    /// on the replica the layout builds.
    #[test]
    fn a_shared_table_joins_with_a_private_main_table() {
        use diesel::JoinOnDsl as _;
        let bundle = shared_consumer_bundle();
        let layout = bundle.shared_layout().expect("the build shares a table");
        let mut conn = conn_with_shared(":memory:");
        conn.batch_execute(layout.sql(true, true))
            .expect("apply the fresh layout");
        register_replica_functions(&mut conn, "alice", "*");
        diesel::insert_into(words::table)
            .values((words::id.eq(1), words::word.eq("hello")))
            .execute(&mut conn)
            .expect("seed the shared table");
        diesel::insert_into(notes::table)
            .values((
                notes::id.eq(1),
                notes::word_id.eq(1),
                notes::owner_id.eq("alice"),
                notes::body.eq("b"),
            ))
            .execute(&mut conn)
            .expect("seed the main table");
        let joined: Vec<String> = words::table
            .inner_join(notes::table.on(words::id.eq(notes::word_id)))
            .select(words::word)
            .load(&mut conn)
            .expect("read the join");
        assert_eq!(joined, vec!["hello".to_owned()]);
    }

    /// Reopening with a fresh main file over an existing shared file keeps the
    /// shared rows and applies the main-fresh program to the new main.
    #[test]
    fn a_reopen_with_a_fresh_main_keeps_the_shared_file() {
        let bundle = shared_consumer_bundle();
        let layout = bundle.shared_layout().expect("the build shares a table");
        let shared = temp_file("shared.db");
        let main_first = temp_file("main-first.db");
        let main_second = temp_file("main-second.db");
        let _guard = TempFiles(vec![
            shared.clone(),
            main_first.clone(),
            main_second.clone(),
        ]);

        // First open: both files fresh, seed a shared row.
        {
            let mut conn = SqliteConnection::establish(url(&main_first).as_str())
                .expect("open the first main");
            conn.batch_execute(&format!("ATTACH '{}' AS connetto_shared", url(&shared)))
                .expect("attach the shared store");
            conn.batch_execute(layout.sql(true, true))
                .expect("apply the fresh layout");
            register_replica_functions(&mut conn, "alice", "*");
            diesel::insert_into(words::table)
                .values((words::id.eq(1), words::word.eq("hello")))
                .execute(&mut conn)
                .expect("seed the shared store");
        }

        // Second open: a fresh main over the existing shared file.
        let mut conn =
            SqliteConnection::establish(url(&main_second).as_str()).expect("open the fresh main");
        conn.batch_execute(&format!("ATTACH '{}' AS connetto_shared", url(&shared)))
            .expect("attach the existing shared store");
        conn.batch_execute(layout.sql(true, false))
            .expect("apply the main-fresh layout");
        register_replica_functions(&mut conn, "alice", "*");
        diesel::insert_into(notes::table)
            .values((
                notes::id.eq(1),
                notes::word_id.eq(1),
                notes::owner_id.eq("alice"),
                notes::body.eq("b"),
            ))
            .execute(&mut conn)
            .expect("seed the fresh main");
        let shared_rows: Vec<String> = words::table
            .select(words::word)
            .load(&mut conn)
            .expect("read the shared store");
        assert_eq!(
            shared_rows,
            vec!["hello".to_owned()],
            "the shared row survived the main being rebuilt"
        );
        let bodies: Vec<String> = notes::table
            .select(notes::body)
            .load(&mut conn)
            .expect("read the fresh main");
        assert_eq!(bodies, vec!["b".to_owned()]);
    }

    /// Reopening both existing files recreates the shared table's readers.
    #[test]
    fn a_reopen_recreates_the_shared_readers() {
        let bundle = shared_consumer_bundle();
        let layout = bundle.shared_layout().expect("the build shares a table");
        let shared = temp_file("shared-reopen.db");
        let main = temp_file("main-reopen.db");
        let _guard = TempFiles(vec![shared.clone(), main.clone()]);
        {
            let mut conn = SqliteConnection::establish(url(&main).as_str()).expect("open the main");
            conn.batch_execute(&format!("ATTACH '{}' AS connetto_shared", url(&shared)))
                .expect("attach the shared store");
            conn.batch_execute(layout.sql(true, true))
                .expect("apply the fresh layout");
            register_replica_functions(&mut conn, "alice", "*");
            diesel::insert_into(words::table)
                .values((words::id.eq(1), words::word.eq("hello")))
                .execute(&mut conn)
                .expect("seed the shared store");
        }
        let mut conn = SqliteConnection::establish(url(&main).as_str()).expect("reopen the main");
        conn.batch_execute(&format!("ATTACH '{}' AS connetto_shared", url(&shared)))
            .expect("attach the shared store");
        conn.batch_execute(layout.sql(false, false))
            .expect("apply the reopen layout");
        register_replica_functions(&mut conn, "alice", "*");
        let words: Vec<String> = words::table
            .select(words::word)
            .load(&mut conn)
            .expect("read through the recreated reader");
        assert_eq!(words, vec!["hello".to_owned()]);
    }

    /// The schema a device shares and the one it does not present the same wire
    /// version, so a server that names no shared table accepts the client that
    /// does.
    #[test]
    fn sharing_a_table_does_not_change_the_wire_version() {
        let unshared = translate::<String, connetto_core::bots::TextIds>(
            SHARED_CONSUMER_SCHEMA,
            SHARED_CONSUMER_POLICIES,
        )
        .expect("translates unshared");
        let shared = shared_consumer_bundle();
        assert_eq!(
            unshared.version(),
            shared.version(),
            "sharing a table changes nothing the server sees"
        );
    }
}
