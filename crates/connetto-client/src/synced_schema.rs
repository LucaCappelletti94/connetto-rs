//! The replica's synced tables carry no foreign keys (R92 decision 1).
//!
//! A replica is a partial copy. Visibility, paging and eviction all leave a
//! child without its parent, so SQLite enforcing the server's references there
//! could only refuse what the server already accepted. The server stays the one
//! enforcer of synced references.

use sqlparser::ast::{ColumnOption, Statement, TableConstraint};
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::{Parser, ParserError};
use sqlparser::tokenizer::{Location, Token};

use crate::ClientError;

/// `ddl` with every column `REFERENCES` and table `FOREIGN KEY` clause removed.
///
/// A `CREATE TABLE` that declares a reference is rendered back from its parsed
/// form without it. Every other statement, a `CREATE TABLE` declaring none
/// included, passes through as its source text, so a trigger or view body
/// reaches SQLite exactly as written.
///
/// # Errors
///
/// [`ClientError::Schema`] when `ddl` does not parse as SQLite.
pub(crate) fn without_references(ddl: &str) -> Result<String, ClientError> {
    let unparsable = |err: ParserError| ClientError::Schema(err.to_string());
    let mut parser = Parser::new(&SQLiteDialect {})
        .try_with_sql(ddl)
        .map_err(unparsable)?;
    let lines = line_starts(ddl);
    let mut out = String::with_capacity(ddl.len());
    loop {
        while parser.consume_token(&Token::SemiColon) {}
        let start = parser.peek_token_ref();
        if start.token == Token::EOF {
            return Ok(out);
        }
        let from = offset(ddl, &lines, start.span.start);
        let mut statement = parser.parse_statement().map_err(unparsable)?;
        if drop_references(&mut statement) {
            out.push_str(&statement.to_string());
        } else {
            let to = offset(ddl, &lines, parser.get_current_token().span.end);
            out.push_str(&ddl[from..to]);
        }
        out.push_str(";\n");
    }
}

/// Remove the references `statement` declares, reporting whether it had any.
fn drop_references(statement: &mut Statement) -> bool {
    let Statement::CreateTable(table) = statement else {
        return false;
    };
    let mut dropped = false;
    table.constraints.retain(|constraint| {
        let reference = matches!(constraint, TableConstraint::ForeignKey(_));
        dropped |= reference;
        !reference
    });
    for column in &mut table.columns {
        column.options.retain(|option| {
            let reference = matches!(option.option, ColumnOption::ForeignKey(_));
            dropped |= reference;
            !reference
        });
    }
    dropped
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

#[cfg(test)]
mod tests {
    use super::without_references;

    #[test]
    fn a_statement_without_references_passes_through_as_written() {
        let ddl = "CREATE TABLE  a (id INTEGER PRIMARY KEY) STRICT;\n\
                   CREATE TRIGGER t AFTER INSERT ON a BEGIN SELECT 1; SELECT   2; END;";
        assert_eq!(
            without_references(ddl).expect("strip"),
            "CREATE TABLE  a (id INTEGER PRIMARY KEY) STRICT;\n\
             CREATE TRIGGER t AFTER INSERT ON a BEGIN SELECT 1; SELECT   2; END;\n",
        );
    }

    #[test]
    fn a_reference_is_removed_and_the_rest_kept() {
        let ddl = "CREATE TABLE c (id INTEGER PRIMARY KEY, p INTEGER NOT NULL REFERENCES p(id) \
                   ON DELETE CASCADE, FOREIGN KEY (p) REFERENCES p (id)) STRICT";
        assert_eq!(
            without_references(ddl).expect("strip"),
            "CREATE TABLE c (id INTEGER PRIMARY KEY, p INTEGER NOT NULL) STRICT;\n",
        );
    }

    #[test]
    fn text_after_a_multibyte_character_is_cut_where_it_starts() {
        let ddl = "CREATE VIEW v AS SELECT 'é' AS x; CREATE VIEW w AS SELECT 'ü' AS y";
        assert_eq!(
            without_references(ddl).expect("strip"),
            "CREATE VIEW v AS SELECT 'é' AS x;\nCREATE VIEW w AS SELECT 'ü' AS y;\n",
        );
    }

    #[test]
    fn unparsable_ddl_is_refused() {
        assert!(matches!(
            without_references("CREATE TABLE ("),
            Err(crate::ClientError::Schema(_))
        ));
    }
}
