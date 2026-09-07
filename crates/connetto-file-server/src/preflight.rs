//! Startup preflight checks.
//!
//! [`preflight`] verifies every required artifact before the server accepts any
//! request and refuses with an error that names exactly what is missing or
//! misconfigured.
//!
//! Catalog access is typed against declared `pg_catalog` tables.  Two
//! fragments stay SQL text because their Postgres types have no diesel
//! `SqlType`: `pg_index.indkey` is `int2vector`, and `pg_class.relkind` is
//! `"char"`.  `pg_proc`'s signature check stays text for the same reason
//! (`oidvector`).  Deployment-chosen table names are bind values, not schema
//! elements, so they never force text SQL.

use std::collections::HashMap;

use diesel::QueryableByName;
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use thiserror::Error;

diesel::define_sql_function! {
    /// `to_regclass(text)`: relation OID, or NULL when the name resolves to nothing.
    fn to_regclass(name: diesel::sql_types::Text) -> diesel::sql_types::Nullable<diesel::sql_types::Oid>;
}

diesel::define_sql_function! {
    /// `format_type(oid, integer)`: the SQL spelling of a column's type.
    fn format_type(
        oid: diesel::sql_types::Oid,
        typemod: diesel::sql_types::Nullable<diesel::sql_types::Integer>,
    ) -> diesel::sql_types::Text;
}

diesel::table! {
    /// Subset of `pg_catalog.pg_index` the sweep-index check reads.
    pg_catalog.pg_index (indexrelid) {
        /// Index OID.
        indexrelid -> diesel::sql_types::Oid,
        /// OID of the indexed table.
        indrelid -> diesel::sql_types::Oid,
        /// Whether the index is usable by queries.
        indisvalid -> diesel::sql_types::Bool,
        /// Whether the index is ready for inserts.
        indisready -> diesel::sql_types::Bool,
        /// Partial-index predicate, NULL for a total index.
        indpred -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
    }
}

diesel::table! {
    /// Subset of `pg_catalog.pg_attribute` the index and column checks read.
    pg_catalog.pg_attribute (attrelid, attnum) {
        /// OID of the owning relation.
        attrelid -> diesel::sql_types::Oid,
        /// 1-based column position.
        attnum -> diesel::sql_types::SmallInt,
        /// Column name.
        attname -> diesel::sql_types::Text,
        /// OID of the column's type.
        atttypid -> diesel::sql_types::Oid,
        /// Type-specific modifier, such as a length.
        atttypmod -> diesel::sql_types::Integer,
        /// Whether the column has been dropped.
        attisdropped -> diesel::sql_types::Bool,
    }
}

diesel::table! {
    /// Subset of `pg_catalog.pg_class` the table-existence check reads.
    pg_catalog.pg_class (oid) {
        /// Relation OID.
        oid -> diesel::sql_types::Oid,
    }
}

diesel::allow_tables_to_appear_in_same_query!(pg_index, pg_attribute, pg_class);

use crate::schema::ConnettoFileSchema;

/// Error returned when a required artifact is absent or misconfigured.
#[derive(Debug, Error)]
pub enum PreflightError {
    /// One of the file-server's own tables is absent.
    #[error("missing table: {0}")]
    MissingTable(&'static str),
    /// A required column is absent from an own table.
    #[error("table {table}: column {column} is missing")]
    MissingColumn {
        /// Table name.
        table: &'static str,
        /// Column name.
        column: &'static str,
    },
    /// A column exists but carries the wrong Postgres type.
    #[error("table {table}: column {column} has wrong type (expected {expected}, found {actual})")]
    WrongColumnType {
        /// Table name.
        table: &'static str,
        /// Column name.
        column: &'static str,
        /// The Postgres type required by the schema contract.
        expected: &'static str,
        /// The Postgres type actually present.
        actual: String,
    },
    /// `connetto_visible_files(bytea[]) RETURNS bytea[]` is absent.
    #[error("function connetto_visible_files(bytea[]) is missing")]
    MissingVisibleFiles,
    /// `connetto_set_content_state(bytea, text, text)` is absent.
    #[error("function connetto_set_content_state(bytea, text, text) is missing")]
    MissingSetterFunction,
    /// An index the sweep's anti-join depends on is absent.
    #[error("table {table}: no index leads with column {column}")]
    MissingIndex {
        /// Table name.
        table: &'static str,
        /// Column the index must lead with.
        column: &'static str,
    },
    /// A function argument has the wrong Postgres type.
    #[error("function {function} argument {pos}: expected {expected}, found {actual}")]
    WrongArgType {
        /// SQL function name.
        function: &'static str,
        /// Zero-based argument position.
        pos: u8,
        /// The Postgres argument type required by the contract.
        expected: &'static str,
        /// The Postgres argument type actually present.
        actual: String,
    },
    /// A function return type does not match the contract.
    #[error("function {function} return type: expected {expected}, found {actual}")]
    WrongReturnType {
        /// SQL function name.
        function: &'static str,
        /// The Postgres return type required by the contract.
        expected: &'static str,
        /// The Postgres return type actually present.
        actual: String,
    },
    /// A function has the wrong security mode.
    ///
    /// `connetto_visible_files` must be SECURITY INVOKER so RLS evaluates as
    /// the caller.  `connetto_set_content_state` must be SECURITY DEFINER so it
    /// can UPDATE the application table without a direct grant to the file-server
    /// role.
    #[error("function {function} must be {expected_mode}")]
    WrongSecurityMode {
        /// SQL function name.
        function: &'static str,
        /// Required mode string (`"SECURITY INVOKER"` or `"SECURITY DEFINER"`).
        expected_mode: &'static str,
    },
    /// A SECURITY DEFINER or INVOKER function has no pinned `search_path`.
    ///
    /// A missing `SET search_path` allows privilege escalation through a
    /// crafted search-path replacement for schema-qualified names inside the
    /// function body.
    #[error("function {function} must have SET search_path in proconfig")]
    UnpinnedSearchPath {
        /// SQL function name.
        function: &'static str,
    },
    /// Database query error.
    #[error("database: {0}")]
    Db(#[from] diesel::result::Error),
    /// Connection pool error.
    #[error("pool: {0}")]
    Pool(String),
}

impl<E: std::error::Error + 'static> From<bb8::RunError<E>> for PreflightError {
    fn from(e: bb8::RunError<E>) -> Self {
        Self::Pool(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Column specifications for each own table
// ---------------------------------------------------------------------------

const MANIFESTS_COLS: &[(&str, &str)] = &[
    ("file_id", "bytea"),
    ("total_len", "bigint"),
    ("accepted_bytes", "bigint"),
    ("committed", "boolean"),
    ("uploaded_by", "text"),
    ("created_at", "timestamp with time zone"),
];

const CHUNKS_COLS: &[(&str, &str)] = &[
    ("file_id", "bytea"),
    ("position", "integer"),
    ("chunk_hash", "bytea"),
    ("chunk_len", "bigint"),
    ("stored", "boolean"),
];

const REGISTRY_COLS: &[(&str, &str)] = &[("chunk_hash", "bytea"), ("state", "text")];

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Verifies all deployment artifacts.  Returns `Err` naming the first missing
/// or misconfigured artifact.
pub async fn preflight<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
) -> Result<(), PreflightError> {
    check_own_tables::<S>(conn).await?;
    check_visible_files_fn(conn).await?;
    check_setter_fn(conn).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Own-table checks
// ---------------------------------------------------------------------------

async fn check_own_tables<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
) -> Result<(), PreflightError> {
    check_table_exists(conn, S::MANIFESTS_SQL).await?;
    check_column_types(conn, S::MANIFESTS_SQL, MANIFESTS_COLS).await?;

    check_table_exists(conn, S::MANIFEST_CHUNKS_SQL).await?;
    check_column_types(conn, S::MANIFEST_CHUNKS_SQL, CHUNKS_COLS).await?;

    check_table_exists(conn, S::CHUNK_REGISTRY_SQL).await?;
    check_column_types(conn, S::CHUNK_REGISTRY_SQL, REGISTRY_COLS).await?;
    // The chunk-hash probe runs per candidate, so only a total index serves it.
    // The grace scan accepts the partial index the shipped DDL creates, but
    // only with that exact predicate.
    check_leading_index(
        conn,
        S::MANIFEST_CHUNKS_SQL,
        "chunk_hash",
        IndexScope::Total,
    )
    .await?;
    check_leading_index(
        conn,
        S::MANIFESTS_SQL,
        "created_at",
        IndexScope::TotalOr("(NOT committed)"),
    )
    .await?;

    Ok(())
}

/// Checks that the named table exists and is a table, not another relation.
async fn check_table_exists(
    conn: &mut AsyncPgConnection,
    table: &'static str,
) -> Result<(), PreflightError> {
    // `relkind` is `"char"`, which has no diesel `SqlType`, so the relation-kind
    // predicate is the one fragment that stays SQL text.  `r` is an ordinary
    // table and `p` a partitioned one; a view or index must not satisfy this.
    let is_table = diesel::dsl::sql::<diesel::sql_types::Bool>("pg_class.relkind IN ('r', 'p')");
    let present: bool = diesel::select(diesel::dsl::exists(
        pg_class::table
            .filter(pg_class::oid.nullable().eq(to_regclass(table)))
            .filter(is_table),
    ))
    .get_result(conn)
    .await?;
    if present {
        Ok(())
    } else {
        Err(PreflightError::MissingTable(table))
    }
}

/// Which index predicates satisfy a probe.
#[derive(Clone, Copy)]
enum IndexScope {
    /// Only a total index qualifies: every candidate must be served.
    Total,
    /// A total index, or a partial one whose predicate is exactly this.
    TotalOr(&'static str),
}

/// Checks that some valid, ready index on `table` leads with `column`.
///
/// The sweep locks doomed hashes through a correlated anti-join, which degrades
/// to a sequential scan per candidate without these indexes.  Index names are
/// never checked: a deployment owns its own names and any equivalent index
/// serves.  Predicates are compared as normalized text rather than for logical
/// equivalence, which is undecidable here, so a degenerate predicate such as
/// `WHERE false` is rejected by not matching.
async fn check_leading_index(
    conn: &mut AsyncPgConnection,
    table: &'static str,
    column: &'static str,
    scope: IndexScope,
) -> Result<(), PreflightError> {
    // Two fragments stay SQL text: `indkey` is `int2vector`, and `indpred` is
    // `pg_node_tree`, readable only through `pg_get_expr`.
    let leading = diesel::dsl::sql::<diesel::sql_types::SmallInt>("pg_index.indkey[0]");
    let predicate = diesel::dsl::sql::<diesel::sql_types::Nullable<diesel::sql_types::Text>>(
        "pg_get_expr(pg_index.indpred, pg_index.indrelid)",
    );
    let candidates = pg_index::table
        .inner_join(
            pg_attribute::table.on(pg_attribute::attrelid
                .eq(pg_index::indrelid)
                .and(pg_attribute::attnum.eq(leading))),
        )
        .filter(pg_index::indrelid.nullable().eq(to_regclass(table)))
        .filter(pg_index::indisvalid)
        .filter(pg_index::indisready)
        .filter(pg_attribute::attname.eq(column));
    let present: bool = match scope {
        IndexScope::Total => {
            diesel::select(diesel::dsl::exists(
                candidates.filter(pg_index::indpred.is_null()),
            ))
            .get_result(conn)
            .await?
        }
        IndexScope::TotalOr(expected) => {
            diesel::select(diesel::dsl::exists(
                candidates.filter(pg_index::indpred.is_null().or(predicate.eq(expected))),
            ))
            .get_result(conn)
            .await?
        }
    };
    if present {
        Ok(())
    } else {
        Err(PreflightError::MissingIndex { table, column })
    }
}

/// Verifies that each expected column exists with the correct Postgres type.
async fn check_column_types(
    conn: &mut AsyncPgConnection,
    table: &'static str,
    expected: &[(&'static str, &'static str)],
) -> Result<(), PreflightError> {
    let rows: Vec<(String, String)> = pg_attribute::table
        .filter(pg_attribute::attrelid.nullable().eq(to_regclass(table)))
        .filter(pg_attribute::attnum.gt(0))
        .filter(diesel::ExpressionMethods::eq(
            pg_attribute::attisdropped,
            false,
        ))
        .order(pg_attribute::attnum)
        .select((
            pg_attribute::attname,
            format_type(pg_attribute::atttypid, pg_attribute::atttypmod.nullable()),
        ))
        .load(conn)
        .await?;

    let actual: HashMap<String, String> = rows.into_iter().collect();

    for &(col, expected_type) in expected {
        match actual.get(col) {
            None => return Err(PreflightError::MissingColumn { table, column: col }),
            Some(found) if found.as_str() != expected_type => {
                return Err(PreflightError::WrongColumnType {
                    table,
                    column: col,
                    expected: expected_type,
                    actual: found.clone(),
                });
            }
            Some(_) => {}
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Function-signature checks
// ---------------------------------------------------------------------------

/// Checks `connetto_visible_files`:
/// - argument: `bytea[]`
/// - return: `bytea[]`
/// - security: SECURITY INVOKER (prosecdef = false)
///
/// A DEFINER function evaluates RLS as the function owner, not as the caller,
/// so it leaks every file regardless of the caller's identity.
async fn check_visible_files_fn(conn: &mut AsyncPgConnection) -> Result<(), PreflightError> {
    let row = fn_meta(conn, "connetto_visible_files").await?;
    let Some(row) = row else {
        return Err(PreflightError::MissingVisibleFiles);
    };
    if row.prosecdef {
        return Err(PreflightError::WrongSecurityMode {
            function: "connetto_visible_files",
            expected_mode: "SECURITY INVOKER",
        });
    }
    check_arg_type(&row, "connetto_visible_files", 0, "bytea[]")?;
    check_return_type(&row, "connetto_visible_files", "bytea[]")?;
    if !row.has_search_path {
        return Err(PreflightError::UnpinnedSearchPath {
            function: "connetto_visible_files",
        });
    }
    Ok(())
}

/// Checks `connetto_set_content_state`:
/// - arguments: `bytea`, `text`, `text`
/// - return: `bytea`
/// - security: SECURITY DEFINER (prosecdef = true)
/// - `search_path`: must be pinned in proconfig
async fn check_setter_fn(conn: &mut AsyncPgConnection) -> Result<(), PreflightError> {
    let row = fn_meta(conn, "connetto_set_content_state").await?;
    let Some(row) = row else {
        return Err(PreflightError::MissingSetterFunction);
    };
    if !row.prosecdef {
        return Err(PreflightError::WrongSecurityMode {
            function: "connetto_set_content_state",
            expected_mode: "SECURITY DEFINER",
        });
    }
    check_arg_type(&row, "connetto_set_content_state", 0, "bytea")?;
    check_arg_type(&row, "connetto_set_content_state", 1, "text")?;
    check_arg_type(&row, "connetto_set_content_state", 2, "text")?;
    check_return_type(&row, "connetto_set_content_state", "bytea")?;
    if !row.has_search_path {
        return Err(PreflightError::UnpinnedSearchPath {
            function: "connetto_set_content_state",
        });
    }
    Ok(())
}

/// Queries `pg_proc` for the function's signature, security mode, and
/// whether `search_path` is pinned in `proconfig`.
///
/// Stays SQL text: `proargtypes` is `oidvector`, which has no diesel
/// `SqlType`, and every projected column is a `format_type` call on a
/// subscript of it.  `proconfig` is `text[]`; the `has_search_path` column
/// is a boolean derived from an `EXISTS(unnest(...))` expression.
async fn fn_meta(
    conn: &mut AsyncPgConnection,
    fn_name: &str,
) -> Result<Option<FnMetaRow>, diesel::result::Error> {
    // pg_catalog.pg_proc has no diesel table! entry; sql_query is required.
    let mut rows: Vec<FnMetaRow> = diesel::sql_query(
        "SELECT p.prosecdef, \
                pg_catalog.format_type(p.prorettype, NULL) AS ret_type, \
                pg_catalog.format_type(p.proargtypes[0], NULL) AS arg0_type, \
                pg_catalog.format_type(p.proargtypes[1], NULL) AS arg1_type, \
                pg_catalog.format_type(p.proargtypes[2], NULL) AS arg2_type, \
                COALESCE((SELECT TRUE FROM unnest(p.proconfig) AS cfg \
                          WHERE cfg LIKE 'search_path=%' LIMIT 1), FALSE) \
                    AS has_search_path \
         FROM   pg_proc p \
         JOIN   pg_namespace n ON n.oid = p.pronamespace \
         WHERE  n.nspname = current_schema() \
           AND  p.proname = $1 \
         LIMIT  1",
    )
    .bind::<diesel::sql_types::Text, _>(fn_name)
    .load(conn)
    .await?;
    Ok(rows.pop())
}

fn check_arg_type(
    row: &FnMetaRow,
    function: &'static str,
    pos: u8,
    expected: &'static str,
) -> Result<(), PreflightError> {
    let actual = match pos {
        0 => row.arg0_type.as_deref(),
        1 => row.arg1_type.as_deref(),
        2 => row.arg2_type.as_deref(),
        _ => None,
    };
    match actual {
        None => Err(PreflightError::WrongArgType {
            function,
            pos,
            expected,
            actual: "(missing)".to_owned(),
        }),
        Some(t) if t != expected => Err(PreflightError::WrongArgType {
            function,
            pos,
            expected,
            actual: t.to_owned(),
        }),
        Some(_) => Ok(()),
    }
}

fn check_return_type(
    row: &FnMetaRow,
    function: &'static str,
    expected: &'static str,
) -> Result<(), PreflightError> {
    if row.ret_type != expected {
        return Err(PreflightError::WrongReturnType {
            function,
            expected,
            actual: row.ret_type.clone(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Query result types
// ---------------------------------------------------------------------------

#[derive(QueryableByName)]
struct FnMetaRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    prosecdef: bool,
    #[diesel(sql_type = diesel::sql_types::Text)]
    ret_type: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    arg0_type: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    arg1_type: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    arg2_type: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    has_search_path: bool,
}
