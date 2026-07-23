# pg2sqlite reverse translation should translate placeholder syntax (resolved)

## Status

Resolved in `LucaCappelletti94/pg2sqlite` at `ee65e309` (branch `reverse-translate-placeholders`), pinned by `crates/connetto-server`. Placeholders now translate as syntax and connetto deleted its literal substitution pass. The proposal below is kept for the record.

## The problem

`reverse_translate` converts SQLite dialect SQL into Postgres SQL, but it has no handling for bind placeholders anywhere in the crate (zero matches for `Placeholder` under `src/`). A `SqlValue::Placeholder` leaf rides the generic `translate_expr_recursive::<Reverse>` walk (`src/impls/reverse_translator_impls/expr.rs`) untouched, so SQLite's `?` tokens survive verbatim into the output.

That output is therefore not executable parameterized Postgres SQL. The Postgres protocol accepts only `$N` parameters. Any consumer that feeds the translation to a real Postgres connection has to rewrite the tokens itself, which is dialect logic in the wrong repo and invites divergent copies of the same rewrite.

SQLite accepts four placeholder forms: positional `?`, numbered `?N`, and the named forms `:name`, `@name`, and `$name`. Postgres accepts only `$N`. The translation gap is exactly this mapping.

## Context in connetto

connetto clients send diesel-rendered SQLite SQL with bare `?` placeholders plus a typed bind vector (`SubscriptionSpec { query, binds }`). The server reverse translates the query through pg2sqlite and hands it to two consumers: `subql` registration (which resolves placeholders against typed binds natively, accepting bare `?` and `$N`) and `PgSnapshotSource` (which executes the query on a real Postgres, where only `$N` is valid). Until this lands, connetto substitutes binds into literals before translation, which loses bind typing and forces a `Real` bind rejection. That substitution is being deleted in favor of placeholder passthrough, so the translated SQL must carry valid Postgres placeholders.

## Proposed change

During reverse translation, map placeholder tokens to Postgres numbered parameters:

- `?N` becomes `$N`, preserving the number. Both are 1-based, so the mapping is direct.
- Bare `?` is assigned a number by SQLite's own rule: one greater than the largest parameter number assigned so far in the statement. A statement using only bare `?` therefore numbers them `$1..$N` in textual order.
- The named forms `:name`, `@name`, and `$name` return a typed translation error. Postgres has no named protocol parameters, silent passthrough would produce SQL that misparses (`$name` reads as a dollar-quoted string opener), and diesel never emits them, so rejection loses nothing.

The rewrite must apply to a placeholder in any expression position: `WHERE` predicates, `IN` lists, `BETWEEN` bounds, function arguments, `LIMIT` and `OFFSET`, and select-list expressions. Implementation-wise that means the mapping lives in the shared expression walk, not in a clause-specific pass.

Number assignment must follow the source order of the SQL text, because the caller's bind vector is in that order. The walk must visit expressions in source order or the pass must run on the token level before the walk.

## Tests

- Bare positionals: `SELECT * FROM t WHERE a > ? AND b = ?` translates to `... WHERE a > $1 AND b = $2`.
- Numbered: `WHERE a > ?2 AND b = ?1` translates to `WHERE a > $2 AND b = $1`.
- Mixed, pinning the SQLite assignment rule: `WHERE a > ? AND b = ?5 AND c = ?` translates to `WHERE a > $1 AND b = $5 AND c = $6`.
- Positions beyond `WHERE`: `LIMIT ?` and `OFFSET ?`, a placeholder inside `IN (?, ?)`, inside `BETWEEN ? AND ?`, and as a function argument such as `length(?)`.
- Named forms `:name`, `@name`, `$name` each produce the typed error, never output.
- Interplay with identifier normalization: a statement with backticked identifiers and placeholders together, since diesel emits both at once, for example ``SELECT `t`.`a` FROM `t` WHERE `t`.`a` > ?``.
- No placeholders: existing translations byte-identical (regression guard).
- Executability: every translated output in the tests above parses under sqlparser's `PostgreSqlDialect` and contains no `?` token.

## Correctness expectations

Every input placeholder maps to exactly one `$N` and the assignment equals SQLite's own bind-index assignment, so one bind vector drives both the SQLite original and the Postgres translation without reordering. The pass is purely syntactic on placeholder tokens and changes nothing else in the output. Failure is always a typed error, never silently dropped or passed-through tokens. Translation of a statement without placeholders is unchanged.
