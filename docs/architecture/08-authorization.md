# 08 — Authorization

**Status**: draft

---

## Purpose

Define how permissions are enforced throughout the system: on reads (subscription snapshot and CDC delivery), on writes (mutations), and on file access. Authorization is on the hot path of every data delivery — it must be correct, auditable, and fast.

---

## Principles

1. **Every row delivered to a client has been authorized** — there is no client-trusted filtering.
2. **Authorization is derived from PostgreSQL RLS** — the server's policy engine mirrors what the database enforces, ensuring the two cannot diverge.
3. **Authorization is evaluated server-side** — the client never receives rows it is not allowed to see, even partially.
4. **Auth failures are silent on the read path** — a row that fails the auth check is omitted from results, not returned as an error. (On the write path, rejections are explicit.)
5. **Authorization is batched** — per-row serial evaluation is too expensive on the CDC hot path; policies are evaluated in bulk.

---

## Auth Context

Each session carries an **auth context** established at handshake time and valid for the session lifetime:

```
AuthContext {
  user_id:   String,
  tenant_id: Option<String>,
  roles:     Vec<String>,
  claims:    HashMap<String, Value>,  // arbitrary JWT/session claims
}
```

The auth context is derived from the auth token sent in `Handshake`. Token validation (JWT verification or session lookup) happens once at connect time.

If the auth context changes (e.g. a role is revoked), the session must be terminated and the client re-authenticates. In-session re-auth is not supported in the initial design.

---

## Policy Source: PostgreSQL RLS

PostgreSQL Row-Level Security (RLS) policies define who can see and modify which rows. The server's authorization engine uses these policies as its source of truth.

### Approaches to policy evaluation

| Approach | Description | Pros | Cons |
|---|---|---|---|
| Direct SQL execution | For each auth check, run `SET LOCAL role = ...; SELECT ...` in PostgreSQL with RLS active | Always correct; no sync lag | Slow; every row check is a DB round-trip |
| Policy compilation | Parse RLS policy expressions and compile them to an in-process evaluator | Fast; no DB round-trip | Complex; must handle all policy expression forms |
| Materialized policy table | Precompute authorized `(user_id, table, pk)` tuples into a fast lookup table | Very fast lookups | Expensive to maintain; stale if not updated promptly |
| Hybrid | Compile simple policies in-process; fall back to SQL for complex ones | Balances speed and correctness | More complex implementation |

The hybrid approach is likely the right long-term answer. For the initial version, the approach is an open question.

---

## Read Authorization

### At snapshot time

When delivering an initial snapshot for a subscription:

1. The query is run with the auth context applied (either via PostgreSQL RLS or the in-process engine).
2. Only rows that pass the auth check are included in `SnapshotRows`.

This is the natural behavior if the snapshot query is executed as the authenticated user in PostgreSQL.

### At CDC time

When a `ChangeRecord` arrives from the CDC source:

1. The matcher identifies candidate subscriptions.
2. For each candidate subscription, the auth engine checks: can this session's auth context see the new row? Can it see the old row?
3. The visibility of old and new rows determines the event type delivered:

| Old visible | New visible | Event delivered |
|---|---|---|
| No | No | None |
| No | Yes | Insert (row became visible) |
| Yes | No | Delete (row became invisible) |
| Yes | Yes | Update (or Insert+Delete if the row identity changed) |

This handles the case where an authorization policy change (not a data change) causes a row to appear or disappear for a client.

### Auth policy changes

If an RLS policy is altered, this may change which rows are visible to existing sessions without any row data changing. The system must handle this:

- Option A: invalidate all active subscriptions and trigger re-snapshot (expensive but simple).
- Option B: treat policy changes as CDC events affecting all rows in the table (targeted but complex).
- Option C: ignore policy changes until the client reconnects (simple; may show stale data briefly).

This is an open question.

---

## Write Authorization

When a mutation arrives:

1. The auth engine checks whether the session's auth context is permitted to perform the operation (INSERT / UPDATE / DELETE) on the specified table and row.
2. If not authorized: `MutationReject(client_seq, reason=Unauthorized)` — no data about why is returned to the client beyond the reason code.
3. If authorized: proceed with validation and apply.

Write authorization should use the same policy source as read authorization. Ideally, the mutation is applied inside PostgreSQL with RLS active so the database itself enforces the policy — this ensures the two cannot diverge.

---

## File Authorization

File metadata is authorized through normal row-level authorization on the `files` table.

File content authorization uses a session token model to avoid per-chunk checks:

1. Server checks the session's auth context against the `files` metadata row.
2. If authorized, server issues a `FileAccessToken { file_id, content_hash, expires_at, token }`.
3. The token is embedded in `FileDownloadManifest` or `FileUploadAck`.
4. Client presents the token when fetching/uploading chunks.
5. Server validates the token (signature + expiry) without a DB lookup.
6. Token expiry (e.g. 5 minutes) is short enough that revoking access by invalidating the session prevents prolonged unauthorized access.

---

## Authorization Batching

On the CDC hot path, a single CDC event may affect hundreds of subscriptions. Evaluating authorization serially per subscription is too slow.

Batching strategies:

1. **Group by auth context**: sessions with the same auth context can share an auth evaluation result. This is common when many sessions belong to the same tenant or role.
2. **Policy compilation**: compiled in-process policies can be evaluated in a tight loop over many sessions without any I/O.
3. **Parallel evaluation**: auth checks for different sessions are independent and can run on a thread pool.

The auth batching implementation is a performance-critical component. Its design depends on the policy evaluation approach chosen.

---

## Audit Logging

Every authorization decision (both grant and deny) should be optionally logged for audit purposes:

```
auth_log(
  timestamp    TIMESTAMPTZ,
  session_id   TEXT,
  user_id      TEXT,
  op           TEXT,    -- 'read' | 'write' | 'file_read' | 'file_write'
  table_name   TEXT,
  pk           BYTEA,
  decision     TEXT,    -- 'allow' | 'deny'
  reason       TEXT
)
```

Audit logging is optional and configurable; it must not be on the synchronous hot path (write asynchronously).

---

## Open Questions

1. **Policy evaluation approach**: direct SQL execution vs. in-process compilation vs. hybrid? What is the v1 approach?
2. **Policy change handling**: which of the three options (re-snapshot all, targeted re-check, defer to reconnect) is acceptable?
3. **Auth context lifetime**: can the auth context be refreshed mid-session (e.g. roles change without disconnect)? Is this required?
4. **Token revocation**: if a file access token is issued and the session is subsequently revoked, can the token still be used until it expires? Is this acceptable?
5. **Tenant isolation**: in a multi-tenant deployment, is there a top-level tenant isolation layer above RLS, or is tenant isolation fully expressed in RLS policies?
6. **Audit log format and destination**: is the `auth_log` table in PostgreSQL the right destination, or should audit events go to a separate log aggregator?

---

## Decisions

*(none yet)*

---

## Notes

- RLS is the source of truth, but the server's auth engine must be able to evaluate policies faster than PostgreSQL can when operating at scale. The gap between "correct but slow" (SQL evaluation) and "fast but must match" (compiled in-process) is the central tension in this component.
- Authorization denies on the read path are silent by design. Leaking information about the existence of rows the client cannot see (via error messages) is a data privacy concern.
- The file session token model trades off some revocation latency (a revoked session can still use an issued token until it expires) for avoiding per-chunk DB checks. The expiry window should be short enough that this is acceptable.
