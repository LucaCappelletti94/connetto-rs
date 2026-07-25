# pg2sqlite: synchronous write denial for read-only tables without RLS (proposal, not yet filed)

## Status

Proposal for `LucaCappelletti94/pg2sqlite`, grounded in the source at the workspace pin `ee65e30`. Not filed yet. This closes the gap between what connetto's roadmap assumed ("pg2sqlite's role-aware translation emits deny triggers that fail the write synchronously at the statement") and what the source actually does today.

## The problem

The role-aware translation surface (`translate_create_table_for_role`, `src/impls/translator_impls/statement.rs:246`) handles three cases:

- **Not selectable by the role**: the table is omitted entirely (the function returns an empty statement list). Correct, nothing to add.
- **Selectable but not writable, WITH RLS**: `generate_readonly_rls_statements` (`src/impls/translator_impls/rls.rs:1765`) emits the renamed inner table plus a view carrying the public name, in `RlsStatementMode::ReadOnly`, which omits the `INSTEAD OF` write triggers (`rls.rs:1672`, only `ReadWrite` mode adds them). A write against a view with no `INSTEAD OF` trigger fails synchronously at the statement. Denial exists here.
- **Selectable but not writable, WITHOUT RLS**: `build_create_table_statements(create_table, schema, options, None)` emits a plain, fully writable table. **No local denial of any kind.**

Consequence in a connetto replica built with a session role: a client write to a read-only non-RLS table succeeds locally, is captured by the session, uploaded, rejected by the server catalog (`MaterializerError::NotWritable`), and rolled back. The end state is correct (server truth restored, nothing device-private is lost because the table is synced), but the denial is asynchronous, costs a round trip, and surfaces as a `MutationRejected` event instead of an immediate statement error the UI can act on. The server catalog should be the version-skew backstop, not the primary enforcement.

## Proposed change

In `translate_create_table_for_role`, for the `is_readonly && !has_row_level_security` branch, emit the plain table followed by three deny triggers:

```sql
CREATE TRIGGER "orders__readonly_insert" BEFORE INSERT ON "orders"
BEGIN SELECT RAISE(ABORT, 'permission denied: orders is read-only for this role'); END;

CREATE TRIGGER "orders__readonly_update" BEFORE UPDATE ON "orders"
BEGIN SELECT RAISE(ABORT, 'permission denied: orders is read-only for this role'); END;

CREATE TRIGGER "orders__readonly_delete" BEFORE DELETE ON "orders"
BEGIN SELECT RAISE(ABORT, 'permission denied: orders is read-only for this role'); END;
```

Trigger names derive deterministically from the table name with a reserved suffix, mirroring how the RLS path derives its inner-table and trigger names, and the generator must reject a user schema that already contains an object with a colliding name.

## The critical interaction: changeset apply fires triggers

Verified against the SQLite session source (`ext/session/sqlite3session.c`): `sqlite3changeset_apply` executes ordinary SQL against the target (`UPDATE main.<t>` at line 4460, `DELETE FROM main.<t>` at 4567, `INSERT INTO main.<t>` at 4636 and 4650). Ordinary DML fires triggers. connetto delivers server patches to the replica through exactly this apply path, so deny triggers, emitted naively, would abort server patch delivery to every read-only table, which is precisely the table kind that receives all of its data that way.

So the deny triggers carry an explicit contract: **authoritative applies run with triggers disabled**. SQLite provides the switch connection-wide (`SQLITE_DBCONFIG_ENABLE_TRIGGER`, exposed by diesel as `set_triggers_enabled`). This is principled, not a workaround: a server patch is the outcome of statements whose triggers already ran on the server, so replaying local triggers during apply would be double execution even for ordinary user triggers. connetto already has the identical shape for capture (`SuspendedCapture` disables the session around `apply_patch` and `rollback`), and the trigger window is the same two sites wrapped the same way with a re-enable drop guard.

The alternative, gating each trigger on some mutable context table (`WHEN (SELECT ...)`) so apply can flip a flag in SQL, was rejected: that is a policy check any SQL can flip, weaker than a connection-level dbconfig owned by the sync engine, and it leaks generator implementation detail into user-visible schema.

pg2sqlite's side of the contract is documentation: the role-aware translation docs state that consumers applying authoritative changesets must do so with triggers disabled, and that the deny triggers are for interactive statements only.

## Adjacent finding, flagged but not solved here

The RLS read-only path has a deeper question mark against changeset apply. Role translation renames the real table to an inner name and puts a view at the public name (`rename_table_for_rls`, `rls.rs:1780`). But `sqlite3changeset_apply` requires a compatible **table with the same name** as recorded in the changeset, and when none exists it silently skips every change for that table with only an `SQLITE_SCHEMA` warning through `sqlite3_log` (per the `sqlite3changeset_apply` documentation). A server patchset addressed to `orders` would find only the `orders` view on a role-translated replica and drop the changes silently. connetto does not exercise role-translated replicas yet (the demo translates with default options and no session role), so this is latent, but it means the RLS translation as it stands may be incompatible with patch delivery, and disabling triggers does not help because the issue is name resolution, not triggers. This needs its own characterization test and its own design decision (rewrite table names during apply upstream in `sqlite-diff-rs`, or invert the naming so the real table keeps the public name). Out of scope for this proposal, recorded so it is not lost.

## What to test

In pg2sqlite:

- Read-only non-RLS table for the session role: `INSERT`, `UPDATE`, and `DELETE` each fail at the statement with the `RAISE(ABORT)` message, `SELECT` still works.
- Writable table for the role: no deny triggers are emitted.
- Non-selectable table: still omitted entirely, no triggers referencing it.
- The deny is inert when triggers are disabled through `SQLITE_DBCONFIG_ENABLE_TRIGGER`: with the dbconfig off, the same `INSERT` succeeds. This pins the documented apply contract.
- Deterministic trigger naming, and a generation-time error when the user schema already defines an object with the reserved name.

In connetto, once the pg2sqlite change lands (Docker-gated, per the existing e2e conventions):

- A client write to a read-only synced table fails synchronously, and the capture session stays empty (nothing is uploaded, no `MutationRejected` round trip).
- A server patch to the same table still applies, through the triggers-disabled window around `apply_patch`, and the rollback path stays functional for other tables.
- A characterization test for the RLS rename finding above: build a role-translated replica with an RLS table, apply a changeset addressed to the public name, and pin whatever the current behavior is so the incompatibility is visible instead of silent.

## Non-goals

- No change to the RLS read-only path in this proposal. Its denial mechanism (view without write triggers) already exists, and its apply-compatibility problem is a separate decision.
- No change to the server catalog backstop. `NotWritable` on upload stays, as version-skew protection for clients holding a stale replica schema.
- No general trigger-translation changes. Only the three generated deny triggers per read-only non-RLS table.
