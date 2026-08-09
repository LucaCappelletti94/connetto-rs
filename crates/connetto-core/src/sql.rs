//! SQL text helpers shared by every side that builds a statement from a name
//! resolved at run time.
//!
//! A table or column named by the deployment's own DDL has no `table!` schema
//! to go through, so the statement is assembled as text and the name has to be
//! quoted by hand. Postgres and SQLite quote identifiers identically, which is
//! why one definition serves the server, the browser relay, and the client.

/// Quote a SQL identifier, doubling embedded quotes.
///
/// ```
/// use connetto_core::sql::quote_ident;
///
/// assert_eq!(quote_ident("orders"), "\"orders\"");
/// assert_eq!(quote_ident("we\"ird"), "\"we\"\"ird\"");
/// ```
#[must_use]
pub fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
