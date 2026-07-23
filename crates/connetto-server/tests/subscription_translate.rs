//! Server-side handling of the client's SQLite-dialect subscription query:
//! reverse translation into the Postgres SQL that subql parses, placeholder
//! syntax included, with bind values riding the registration natively.
//!
//! The client speaks SQLite (the dialect it runs against its local replica)
//! and ships `?` placeholders with typed bind values. The server owns the
//! schema, so translation happens server-side on the AST, and the binds are
//! never rendered into SQL text: pg2sqlite maps the placeholder syntax to
//! `$N` and subql resolves the values at registration. These tests pin that
//! seam: a dialect-divergent query is actually rewritten, placeholders
//! translate as syntax, a missing bind fails registration cleanly, and an
//! unparseable query fails as `Translate` rather than reaching subql.

use connetto_core::messages::BindValue;
use connetto_server::{Materializer, MaterializerError, Registration};

const PG_DDL: &str =
    "CREATE TABLE t (id INT PRIMARY KEY, name TEXT, amount INT, price FLOAT, tag BYTEA);";

fn materializer() -> Materializer {
    Materializer::new(PG_DDL).expect("build materializer")
}

#[test]
fn reverse_translates_a_dialect_divergent_function() {
    // SQLite `unicode(x)` reverse-translates to Postgres `ascii(x)`, proving the
    // translation actually fires and is dialect-aware rather than a passthrough.
    let pg = materializer()
        .translate_subscription_sql("SELECT * FROM t WHERE unicode(name) > 65")
        .expect("translate")
        .to_lowercase();
    assert!(
        pg.contains("ascii"),
        "expected ascii in translated SQL, got {pg}"
    );
    assert!(
        !pg.contains("unicode"),
        "unicode should be rewritten, got {pg}"
    );
}

#[test]
fn translates_plain_placeholders_to_numbered_parameters() {
    let pg = materializer()
        .translate_subscription_sql("SELECT * FROM t WHERE amount > ? AND name = ?")
        .expect("translate");
    assert!(
        pg.contains("$1") && pg.contains("$2"),
        "bare placeholders number in textual order, got {pg}"
    );
    assert!(
        !pg.contains('?'),
        "no SQLite placeholder survives translation, got {pg}"
    );
}

#[test]
fn numbered_placeholders_keep_their_index_and_may_repeat() {
    let pg = materializer()
        .translate_subscription_sql("SELECT * FROM t WHERE amount > ?1 AND id < ?1")
        .expect("translate");
    assert_eq!(
        pg.matches("$1").count(),
        2,
        "both `?1` references keep parameter one, got {pg}",
    );
}

#[test]
fn mixed_placeholders_follow_the_sqlite_assignment_rule() {
    // A bare `?` takes one greater than the largest index assigned so far, so
    // `?` after `?2` becomes `$3`.
    let pg = materializer()
        .translate_subscription_sql("SELECT * FROM t WHERE amount > ?2 AND id < ?")
        .expect("translate");
    assert!(
        pg.contains("$2") && pg.contains("$3"),
        "bare placeholder numbers past the explicit one, got {pg}",
    );
}

#[test]
fn placeholder_inside_string_literal_is_not_a_bind() {
    let pg = materializer()
        .translate_subscription_sql("SELECT * FROM t WHERE name = '?'")
        .expect("translate");
    assert!(
        pg.contains("'?'"),
        "a question mark inside a string literal is data, got {pg}",
    );
}

#[test]
fn register_sqlite_rejects_a_missing_bind() {
    // Placeholder pairing is subql's job now: a `$1` with no bind behind it
    // fails registration, not translation.
    let mut mat = materializer();
    match mat.register_sqlite(1, "SELECT * FROM t WHERE amount > ?", &[]) {
        Err(MaterializerError::Register(_)) => {}
        Err(other) => panic!("expected a registration error, got {other:?}"),
        Ok(_) => panic!("a placeholder without a bind must not register"),
    }
}

#[test]
fn register_sqlite_classifies_translated_query() {
    let mut mat = materializer();
    let agg = mat
        .register_sqlite(1, "SELECT COUNT(*) FROM t", &[])
        .expect("register aggregate");
    assert!(
        matches!(agg.registration, Registration::DeltaAggregate(_)),
        "COUNT(*) should classify as a delta aggregate after translation",
    );

    let row = mat
        .register_sqlite(
            2,
            "SELECT * FROM t WHERE amount > ?",
            &[BindValue::Integer(0)],
        )
        .expect("register row");
    assert!(
        matches!(row.registration, Registration::Row(_)),
        "a bound row filter should classify as a row subscription after translation",
    );
    assert!(
        row.pg_sql.contains("$1"),
        "the registration carries the translated parameterized SQL, got {}",
        row.pg_sql,
    );
}

#[test]
fn register_sqlite_accepts_a_real_bind() {
    // Float binds ride natively as typed values. Under the old literal
    // substitution they were rejected outright.
    let mut mat = materializer();
    let row = mat
        .register_sqlite(
            1,
            "SELECT * FROM t WHERE price > ?",
            &[BindValue::Real(1.5)],
        )
        .expect("a REAL bind registers");
    assert!(matches!(row.registration, Registration::Row(_)));
}

#[test]
fn register_sqlite_accepts_a_blob_bind() {
    // Blob binds resolve through subql's hex literal round trip.
    let mut mat = materializer();
    let row = mat
        .register_sqlite(
            1,
            "SELECT * FROM t WHERE tag = ?",
            &[BindValue::Blob(vec![0xde, 0xad, 0xbe, 0xef])],
        )
        .expect("a BLOB bind registers");
    assert!(matches!(row.registration, Registration::Row(_)));
}

#[test]
fn register_sqlite_rejects_unparseable_query() {
    let mut mat = materializer();
    match mat.register_sqlite(1, "SELECT ((( FROM", &[]) {
        Err(MaterializerError::Translate(_)) => {}
        Err(other) => panic!("expected a translation error, got {other:?}"),
        Ok(_) => panic!("unparseable query must not register"),
    }
}

#[test]
fn registers_the_exact_shape_diesel_renders() {
    // diesel's SQLite rendering emits backtick-quoted identifiers, the
    // complete column list as an explicit projection, a parenthesized WHERE
    // with a `?` bind, and any ORDER BY the app added. This is the wire shape
    // every typed live query produces, so it must register end to end, and
    // its translation must be parameterized Postgres SQL with double-quoted
    // identifiers.
    let mut mat = materializer();
    let row = mat
        .register_sqlite(
            1,
            "SELECT `t`.`id`, `t`.`name`, `t`.`amount`, `t`.`price`, `t`.`tag` FROM `t` \
             WHERE (`t`.`amount` > ?) ORDER BY `t`.`id`",
            &[BindValue::Integer(0)],
        )
        .expect("diesel-rendered shape registers");
    assert!(
        matches!(row.registration, Registration::Row(_)),
        "the diesel shape classifies as a row subscription",
    );
    assert!(
        row.pg_sql.contains("$1") && !row.pg_sql.contains('`') && !row.pg_sql.contains('?'),
        "the translation is parameterized Postgres SQL, got {}",
        row.pg_sql,
    );
}
