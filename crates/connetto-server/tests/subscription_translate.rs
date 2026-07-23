//! Server-side handling of the client's SQLite-dialect subscription query:
//! bind placeholder substitution in the parsed statement, then reverse
//! translation into the Postgres SQL that subql parses.
//!
//! The client speaks SQLite (the dialect it runs against its local replica)
//! and ships `?` placeholders with typed bind values. The server owns the
//! schema, so substitution and translation happen server-side, on the AST,
//! never by string splicing. These tests pin that seam: a dialect-divergent
//! query is actually rewritten, binds pair with placeholders positionally and
//! by explicit index, mismatches fail cleanly, and an unparseable query fails
//! as `Translate` rather than reaching subql.

use connetto_core::messages::BindValue;
use connetto_server::{Materializer, MaterializerError, Registration};

const PG_DDL: &str = "CREATE TABLE t (id INT PRIMARY KEY, name TEXT, amount INT);";

fn materializer() -> Materializer {
    Materializer::new(PG_DDL).expect("build materializer")
}

#[test]
fn reverse_translates_a_dialect_divergent_function() {
    // SQLite `unicode(x)` reverse-translates to Postgres `ascii(x)`, proving the
    // translation actually fires and is dialect-aware rather than a passthrough.
    let pg = materializer()
        .translate_subscription_sql("SELECT * FROM t WHERE unicode(name) > 65", &[])
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
fn substitutes_plain_placeholders_in_textual_order() {
    let pg = materializer()
        .translate_subscription_sql(
            "SELECT * FROM t WHERE amount > ? AND name = ?",
            &[BindValue::Integer(5), BindValue::Text("O'Brien".to_owned())],
        )
        .expect("translate");
    assert!(
        pg.contains("amount > 5"),
        "first bind pairs positionally, got {pg}"
    );
    assert!(
        pg.contains("'O''Brien'"),
        "text bind is a properly escaped literal, got {pg}",
    );
    assert!(
        !pg.contains('?'),
        "no placeholder survives substitution, got {pg}"
    );
}

#[test]
fn numbered_placeholders_pair_by_index_and_may_repeat() {
    let pg = materializer()
        .translate_subscription_sql(
            "SELECT * FROM t WHERE amount > ?1 AND id < ?1",
            &[BindValue::Integer(7)],
        )
        .expect("translate");
    assert!(
        pg.contains("amount > 7") && pg.contains("id < 7"),
        "one bind serves both `?1` references, got {pg}",
    );
}

#[test]
fn placeholder_inside_string_literal_is_not_a_bind() {
    let pg = materializer()
        .translate_subscription_sql("SELECT * FROM t WHERE name = '?'", &[])
        .expect("translate");
    assert!(
        pg.contains("'?'"),
        "a question mark inside a string literal is data, got {pg}",
    );
}

#[test]
fn bind_placeholder_mismatches_are_rejected() {
    let mat = materializer();
    // A placeholder with no bind behind it.
    let missing = mat
        .translate_subscription_sql("SELECT * FROM t WHERE amount > ?", &[])
        .expect_err("missing bind must fail");
    assert!(matches!(missing, MaterializerError::Translate(_)));

    // A bind no placeholder references.
    let unused = mat
        .translate_subscription_sql(
            "SELECT * FROM t WHERE amount > ?",
            &[BindValue::Integer(1), BindValue::Integer(2)],
        )
        .expect_err("unused bind must fail");
    assert!(matches!(unused, MaterializerError::Translate(_)));

    // Mixing plain and explicitly numbered placeholders is ambiguous.
    let mixed = mat
        .translate_subscription_sql(
            "SELECT * FROM t WHERE amount > ? AND id < ?1",
            &[BindValue::Integer(1)],
        )
        .expect_err("mixed placeholder styles must fail");
    assert!(matches!(mixed, MaterializerError::Translate(_)));
}

#[test]
fn register_sqlite_classifies_translated_query() {
    let mut mat = materializer();
    let agg = mat
        .register_sqlite(1, "SELECT COUNT(*) FROM t", &[])
        .expect("register aggregate");
    assert!(
        matches!(agg, Registration::DeltaAggregate(_)),
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
        matches!(row, Registration::Row(_)),
        "a bound row filter should classify as a row subscription after translation",
    );
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
    // diesel's SqliteQueryBuilder emits backtick-quoted identifiers, an
    // explicit projection, a parenthesized WHERE with a `?` bind, and any
    // ORDER BY the app added. This is the wire shape every typed live query
    // produces, so it must register end to end.
    let mut mat = materializer();
    let row = mat
        .register_sqlite(
            1,
            "SELECT `t`.`id`, `t`.`name`, `t`.`amount` FROM `t` \
             WHERE (`t`.`amount` > ?) ORDER BY `t`.`id`",
            &[BindValue::Integer(0)],
        )
        .expect("diesel-rendered shape registers");
    assert!(
        matches!(row, Registration::Row(_)),
        "the diesel shape classifies as a row subscription",
    );
}
