# Refactor: identity, session, and capability

> **`plans/master-implementation-plan.md` is authoritative on phase definitions and dependencies.** This document is retained for the evidence, the decision record, and the recorded answers it uniquely holds.

Investigation complete, every decision settled, no code written.

None of it is implemented. E6 step one (`Credential`, `Principal`, `SessionConfig::allow_anonymous`, the anonymous refusals) is written and green but uncommitted, and the decisions below supersede parts of it. `plans/master-implementation-plan.md` covers the disposition of that tree under Step zero.

## The defect in one paragraph

connetto has no representation of "nobody is logged in". `AuthContext<Id>.user_id` has been non-optional since the first commit, and three mechanisms demand it: the Postgres RLS GUC, the write path, and the exactly-once watermark keyed on `(user_id, session_id)`. Running without authentication was therefore made to work by inventing an identity. `TrustingSessionVerifier` takes the client's own handshake string, uses it verbatim as the `user_id`, and hashes it into a `session_id`. So "no authentication" does not mean anonymous, it means every caller is authenticated as whoever they claim to be, and that stand-in is the DEFAULT.

## How it happened, so it is not repeated

Nobody made a wrong decision. `AuthContext` with a mandatory `user_id` predates all authentication work (`7f71e7d`, the bootstrap commit), where the server simply did `AuthContext::new(handshake.client_id)`. For a sync prototype with no auth that is reasonable. Authentication arrived later (`54a2da1`) as a SEAM OVER that assumption rather than a replacement of it: `SessionVerifier` closed the spoofing hole for anyone injecting a real verifier, and the old behaviour was preserved behind a named type to keep pre-auth loops running. The prototype assumption was never deleted, only renamed and documented as dangerous, and left as the default.

The security review looked directly at it and accepted the documentation as the mitigation (`docs/review-oauth-authentication.md`: "The default `TrustingSessionVerifier` is documented as non-production"). A doc comment is not a guard. That is the lesson worth carrying: a dangerous default is not made safe by describing it.

## The map

Nine read-only investigations produced this. Every claim is cited.

### 1. Identity mandatory, absence faked

- `AuthContext<Id>.user_id` non-optional, `crates/connetto-core/src/auth.rs`.
- `SessionVerifier::verify_session` returns only `Result<VerifiedSession<Id>, _>`, so the trait cannot express "no credential presented".
- `TrustingSessionVerifier`, `crates/connetto-core/src/auth.rs`. Twelve references in the whole repository, every one its definition, its re-export, or the line installing it as the default (`SessionManager::with_oplog` in `crates/connetto-server/src/session.rs`). Nothing names it deliberately. No test uses it on purpose.
- Only genuine need for a USER identity is the RLS GUC (`PgWriteTarget::commit` in `crates/connetto-server/src/write_target.rs`, `PgSnapshotSource::snapshot` in `crates/connetto-server/src/snapshot.rs`). The watermark needs a per-session handle, not a user. Routing, credits, and subscriptions already use `connection_num` and need neither.

### 2. Three session concepts, none of them the designed one

| Name | Minted | Lifetime | Survives reconnect | Durable |
|---|---|---|---|---|
| `connection_num` | `SessionManager::next_connection_num` in `crates/connetto-server/src/session.rs`, atomic counter | per connection | no | no |
| `SessionId` | `new_session_id` in `crates/connetto-server/src/authn/store.rs`, UUIDv4 at LOGIN | per login | yes, via the `sid` claim | yes, watermark key |
| `session_token` | `SessionManager::run_handshake` in `crates/connetto-server/src/session.rs`, `format!("token-{connection_num}")` | per connection | no | no |

`session_token` is the protocol's server-issued resume handle, documented in the first commit as "Server-issued and opaque to the client". The server never reads the client's value back and no client ever stores it. It has been a stub since day one.

Correction to an earlier reading: the auth work did NOT take the session concept over. The session layer never had a durable identity. It was designed on the wire, never built, and when auth needed one it built its own. A gap was filled once, on the wrong side of the boundary.

Correction to a second earlier reading: commit `6eee169` ("Key the mutation watermark on the verified session id") did not diverge from its title. Before it, the watermark was keyed on `(user_id, client_id)` where `client_id` is the CLIENT-SUPPLIED handshake string. It replaced the client-chosen half with the verified `session_id`. That was a security fix.

### 3. Seams that decide nothing

- `AuthPolicy::can_write` returns `Ok(true)` unconditionally in BOTH production implementations (`crates/connetto-server/src/auth.rs`, `PermissiveAuth::can_write` and `RlsAuth::can_write`), ignoring all four arguments. The call path is live: `crates/connetto-server/src/session.rs` inside `every_op_authorized`, once per op, and `DenyAuth` in `tests/write_path.rs` proves a denial yields `Unauthorized`. So it is a live, wired, tested hook with no live policy. NOT vestigial: it is the seam OpenFGA is meant to land in (`crates/connetto-server/src/auth.rs`, module doc). Do not delete it.
- `AuthContext.tenant_id`, `.roles`, `.claims`: set at login, encoded into the JWT, decoded, stored in the session record, and NEVER read by anything. Multi-tenancy and RBAC look implemented and are not. `docs/architecture/open-questions.md` (Q8.5) explains why: tenant isolation was decided to live in the translated FGA model.
- `FatalErrorReason::SessionRevoked` and `::ServerShuttingDown`: never constructed. E3 built revocation, and a session revoked mid-connection is simply never told.
- `Oplog::prune`: never called through the trait, only internally by `PgOplog::append`.
- `MutationConflict.server_updated_at` and `.server_row_json`: placeholder empty strings in the browser relay (`conflict_tab_mutation` in `crates/connetto-web/src/relay.rs`), genuine on the server.

### 4. Insecure stand-ins are defaults, and they compose

| Layer | Stand-in | Reached by | Result |
|---|---|---|---|
| Verifier | `TrustingSessionVerifier` | `SessionManager` default, `SessionManager::with_oplog` in `crates/connetto-server/src/session.rs` | caller's string becomes `user_id` |
| Provider | `PermissiveProvider` | `CONNETTO_OIDC_PROVIDER` unset OR MISSPELLED, `build_registry` in `crates/connetto-server/src/bin/connetto-server.rs` (`_ =>` arm) | every login becomes `dev-user` |
| Authorizer | `PermissiveAuth` | `CONNETTO_READER_URL` unset, `main` in `crates/connetto-server/src/bin/connetto-server.rs` | every read and write authorized, and snapshot plus write target run on the OWNER pool so RLS is bypassed |

Composed worst case: `CONNETTO_AUTH=database` with a capitalised provider name and no reader role gives a deployment that looks fully authenticated, mints real Ed25519 tokens that verify correctly, in which every user is `dev-user` and `dev-user` reads and writes every row with RLS off. The only guard is an `eprintln!`.

### 5. Pre-existing performance finding, unrelated to the defect

`can_read` fires PER ROW on the CDC hot path (`SessionManager::dispatch_event` and `SessionManager::catch_up_row` in `crates/connetto-server/src/session.rs`). Each call takes a pooled connection, opens a transaction, sets the GUC, and runs an `EXISTS`. That is an N-query pattern before capabilities or OpenFGA enter the picture.

## Decisions taken

1. **All three stand-ins go, staged.** Security first: delete `PermissiveProvider` and stop the binary falling back to `PermissiveAuth`, neither of which is blocked on anything. Then remove `PermissiveAuth` from tests and delete `TrustingSessionVerifier` once the session identity exists. Measured basis: all 18 `PermissiveAuth` users already run Postgres, and `RlsAuth` against a table with no policy returns every row, verified by probe, so swapping them changes no behaviour. `oauth2-test-server` and `dev_idp` already replace `PermissiveProvider`.

2. **The session layer owns its own durable identity, as originally designed.** Build `session_token` for real: the server mints an opaque handle at handshake, the client persists it and presents it on reconnect. Auth then layers on top, so a session may or may not have a user. `docs/architecture/11-authentication.md` already says the two do different jobs.

3. **Capabilities are in scope.** A bearer capability from a share link is a third orthogonal thing beside identity and session. Designing `Principal` for identity alone would repeat the exact failure being fixed.

4. **Capabilities live in the authorization model as relations, not as a Postgres GUC.** A share link is natively a Zanzibar tuple (`document:readme#viewer@link:abc123`). A share link is also a READ grant before it is a write grant, so a capability must reach the read path. Putting it in a GUC would split authorization across two engines and reintroduce the divergence problem that `rls2fga` exists to prevent. (Superseded an earlier GUC-based decision, see the correction below.)

5. **RLS DDL is the source language for policy. OpenFGA is the runtime executor.** This is not a new decision, it is the one already recorded at `docs/architecture/open-questions.md` (Q8.1): "At runtime, visibility checks query OpenFGA via its Rust SDK, not direct SQL evaluation or in-process RLS compilation." `rls2fga` compiles the policies into the FGA model, so there is one source of truth and the two cannot diverge.

   The reason it is urgent rather than aspirational is the CDC path. `SessionManager::dispatch_event` in `crates/connetto-server/src/session.rs` loops over every matching consumer and calls `can_read` with a sequential `.await` inside the loop. Each call takes a pooled connection, opens a transaction, runs `set_config`, runs a `SELECT EXISTS`, and commits. No batching, no concurrency, no cache. This is on the SHARED CDC ingestion path, so throughput is roughly `1 / (subscribers x RTT)`: at an optimistic 1 ms pooled round trip that is about 10 events per second at 100 subscribers and 1 per second at 1000. **Using RLS as the CDC authorization layer was always a temporary patch and it does not scale.**

   OpenFGA is strictly better than that today, with no extra infrastructure, using two mechanisms verified against upstream sources rather than assumed:

   - **`BatchCheck`**, verified in `openfga/api` `openfga_service.proto` alongside `Check`, `Expand`, `ListObjects`, and `StreamedListObjects`. One call covers every subscriber of one row, so the per-row fan-out stops being N round trips.
   - **Caching**, verified in `openfga/openfga` `.config-schema.json`: `checkQueryCache` (query to boolean), `checkIteratorCache` (the underlying datastore iterators, for example which groups a user belongs to), `listObjectsIteratorCache`, `sharedIterator`, `cacheTTLJitterPercentage`, and `cacheController`, which invalidates the caches from recent tuple writes by polling the datastore changelog.

   Each CDC row has a distinct primary key so final `Check` keys differ, but the expensive shared graph work is what `checkIteratorCache` holds, and that repeats across every row. `cacheController` gives revocation a bounded propagation time.

   | Path | Shape | Volume | Executor |
   |---|---|---|---|
   | Snapshot | set filter | one query, many rows | RLS inline today, `ListObjects` later if wanted |
   | CDC live patch | point check | rows x subscribers, hot path | OpenFGA `BatchCheck`, one call per event |
   | Mutation | point check | one per op | OpenFGA `Check` |

6. **`AuthPolicy::can_write` survives** as the OpenFGA attachment point, despite being inert today.

7. **An anonymous session writes when it is authorized to, and not otherwise.** Authorization for an unidentified caller arrives as a grant the application obtained however it likes: a URL parameter, a cookie, a Bearer header, or a general access token. The transport is the application's business and connetto never sees it, it only receives whatever the application extracted and put on the handshake. This settles the question the plan carried open through several attempts, and it settles it on capability rather than on identity or on the watermark.

   The consequence for the wire is that `Credential::{Anonymous, Token}` as written today is insufficient, because it assumes a credential either identifies you or does not exist. A caller may present something that identifies nobody yet authorizes plenty. The shape wanted is closer to a caller presenting zero or more GRANTS, each of which resolves to an identity, or to permissions over resources, or is refused. `Principal` and `Credential` must both be designed for that before either is committed.

   This also re-opens decisions 3 and 5 of the E6 anonymous-replica set, which concluded that adoption carries no queued mutations and that an unadopted anonymous replica can be wiped with no unsynced guard. Both rested on anonymous being read-only. An anonymous session holding a capability can now have unsynced writes, so the guard is needed on both paths.

8. **Revocation propagation uses OpenFGA's per-request `ConsistencyPreference`.** Verified in `openfga/api` `openfga_service.proto`: `Check`, `BatchCheck`, and `ListObjects` each take a `consistency` field, defaulting to `MINIMIZE_LATENCY` (served from a short-lived cache) with `HIGHER_CONSISTENCY` available at the cost of latency. A tuple write is visible immediately under the latter because it is the same store with no replication hop, which is strictly better than a Postgres replication mesh, where staleness is physical lag and cannot be tightened per request without routing to the primary.

   Two constraints on using it. `HIGHER_CONSISTENCY` bypasses the cache, so putting it on the CDC hot path would defeat the caching that makes the path viable: the preference is chosen per call site, not globally. And OpenFGA has **no zookies**, so nothing can express "this read must reflect that specific write", only the coarse two-level preference. That is weaker than the Zanzibar paper and bounds how precise a revocation promise connetto can make.

9. **A caller presents a list of grants, each resolved independently.** The handshake carries zero or more opaque grants. The server resolves each one into an identity, into a set of capabilities, or into a refusal. `Principal` then holds an optional identity plus whatever capabilities resolved, which expresses all four arrival cases: nothing, identity only, capability only, and both at once. The last is real, a signed-in user holding a share link to someone else's document, and is the case a single-grant shape cannot represent.

   Chosen over a fixed pair of optional fields deliberately. Fixing the arity at two would mean a third kind of grant later forces another wire change, which is precisely the bolt-on pattern this whole refactor exists to stop. `Credential::{Anonymous, Token}` as it stands today cannot express a capability at all and does not survive.

   **Resolution rule, settled.** A grant that fails to resolve is REPORTED, not fatal: the handshake succeeds on whatever resolved and the ack names each grant that did not, so a client can tell the user its share link expired while still signing them in. An expired link beside a valid login is the ordinary case, not an edge case, and refusing the whole connection for it would be wrong. The failure stays loud, it just is not terminal. This needs a new field on `HandshakeAck` listing the rejected grants, and applications are expected to read it.

   **SUPERSEDED IN PART, 2026-07-30.** The semantics stand and the reporting is struck. The reply says nothing about a failed grant: no reason, and not which grant it was, so `HandshakeAck` gains NO field. Not allowed, no longer allowed, and never existed are indistinguishable, on the same reasoning that a service does not distinguish an authorization failure from a missing resource, since a caller able to tell a withdrawn key from a guessed one would hold an oracle over other people's keys. The consequence, accepted deliberately: an application cannot tell a user whether to retry or to obtain a new key. The failure stays loud in the server's structured log and silent on the wire. Corrected 2026-07-30: it is a denial, and denials go to structured logging rather than to the `auth_events` table, which holds state changes.

10. **Snapshots stay on RLS, permanently and by design.** Not interim. A snapshot is a set filter and RLS answers it in one round trip using the planner's indexes with no result cap. OpenFGA's `ListObjects` measurably cannot stand in: verified in `.config-schema.json`, it defaults to `listObjectsMaxResults` of 1000 and a `listObjectsDeadline` of 3 seconds, and carries its own dispatch and datastore throttling. Enumerating everything a subject can see is the expensive direction in Zanzibar, and a truncated snapshot would be silent data loss rather than an error.

    So the split is deliberate: **RLS answers set-shaped questions at snapshot time, OpenFGA answers point-shaped questions on the CDC and write paths.** Two executors for one policy is only safe because `rls2fga` compiles both from the same source, which makes that compilation load-bearing rather than a convenience. It must be tested as such.

11. **`RlsAuth` survives and is no longer a stand-in.** It follows from decision 10: something must execute the snapshot filter and RLS is that something. It stops being scaffolding awaiting OpenFGA and becomes half the design, which also means it needs the treatment of a permanent component rather than a placeholder.

    **CORRECTED, 2026-07-30.** Half right. RLS survives, `RlsAuth` does not. Its `can_read` exists only for the change path that moves to `subql` under R5a, and its `can_write` returns true unconditionally. RLS keeps filtering the snapshot and gating the write through `PgSnapshotSource` and `PgWriteTarget`, which bind `app.user_id` directly (`PgSnapshotSource::snapshot` in `crates/connetto-server/src/snapshot.rs`, `PgWriteTarget::commit` in `crates/connetto-server/src/write_target.rs`) and never go through the trait at all. So `RlsAuth` as an `AuthPolicy` implementation dissolves.

12. **CDC authorization checks BOTH the old and the new row, and today's single check is a confidentiality leak.** `docs/architecture/08-authorization.md` (`### At change time`) already specifies the two-check form with a table mapping old-visible and new-visible onto the event delivered. The code checks once and skips the check entirely for deletes (`SessionManager::dispatch_event` in `crates/connetto-server/src/session.rs`), so **a client that loses access to a row keeps the last version it saw, in its local replica, forever.** Nothing withdraws it. That is a leak, not a missing feature, and it is the reason this is not merely a documentation mismatch.

    The cost objection that made this look expensive evaporates under decision 5. With `BatchCheck`, the old-image and new-image checks for one row travel in the SAME call as one another and as every other subscriber's, so the price is one extra tuple per check rather than a second round trip. It only looked prohibitive while the executor was RLS, where each check was its own transaction.

    Two consequences for the work. The dispatch path must obtain the OLD image, which it does not do today. And a withdrawal must reach the client as a tombstone the replica applies, which is the existing delete path, so the client side may need nothing new. Verify that rather than assume it.

    **CORRECTED, 2026-07-30, on three counts.** First, the cost claim is wrong in detail: `maxChecksPerBatchCheck` defaults to 50 and `maxConcurrentChecksPerBatchCheck` to 50, so one event with N subscribers costs the ceiling of its question count over 50 calls, not one. Second, the second check is conditional rather than unconditional: check the current version, deliver and stop if visible, and consult the previous version only when the current one is absent or invisible. Third, this is HARD-blocked on decision 5 rather than merely expensive without it, because `RlsAuth::can_read` runs `SELECT EXISTS` against the LIVE table (`crates/connetto-server/src/auth.rs`), so for an update it can only answer about the current version and for a deletion it answers false for everyone. `AuthPolicy::can_read(principal, table, pk)` also cannot say which version is meant, so the trait signature changes.

    **AND THE LEAK IS TWO-WAY.** The unconditional tombstone replay is not merely a skipped check. It forwards the primary key of a deleted row to every subscriber of the table including those who could never see it, which discloses existence, identifier, timing, and for sequential keys the row count. `08-authorization.md` forbids that in writing. The two-check form closes both directions. The good news half of this decision is confirmed: the tombstone path already exists and already replays, so the client side needs nothing new.

13. **Revocation policy: writes strict, CDC cached, revocation tears the subscription down.** Mutations use `HIGHER_CONSISTENCY`, because they are low volume and a write accepted against a just-revoked capability is the case that must never slip through, which is exactly the moment a leaked share link is being withdrawn. The CDC read filter keeps `MINIMIZE_LATENCY` and its caches, because that is what makes the fan-out affordable at all, so a revoked reader may see at most one further patch within the cache TTL.

    Revocation does not wait to be discovered on the next check. It tears the affected subscription down and the client re-subscribes, which under decision 12 also withdraws the rows it may no longer see rather than leaving stale copies behind. That needs a mechanism to notice a revocation and act, which does not exist today: `docs/architecture/open-questions.md` (Q8.2) covers policy DDL changes and forces a full re-snapshot, but a tuple change has no path at all. OpenFGA's changelog, the same stream `cacheController` polls, is the obvious source.

    **CORRECTED, 2026-07-30.** OpenFGA's changelog is NOT the source and nothing polls it. Every permission is backed by a Postgres row, because RLS policy text is the source language and a permission existing only in OpenFGA would make OpenFGA a second source of truth. So a grant change is a Postgres row change and arrives on the change log connetto already reads end to end, with `rls2fga` naming which tables carry authorization meaning. (OpenFGA could not be watched cheaply anyway: `read_changes` is a unary paged call with a default maximum page size of 100 and there is no streaming changelog.) The response is a per-subscription `FullResyncRequired`, which is Built end to end already, and NEVER a synthesized row deletion, because finding the affected rows is the capped enumeration direction and a truncated withdrawal would look complete. The changed row names its grantee, which is all that is needed: resyncing that grantee's subscriptions recomputes the whole visible set under RLS without enumerating anything.

    Documented promise, to be stated plainly for deployments: an authorization change takes effect immediately for writes, and within the cache TTL for reads, unless it triggers a teardown, in which case immediately for both.

## Rasterization is NOT part of this plan

A locally materialised permission set (a "raster") is not a component of this design and no phase builds one. The two systems it named are both unusable here: **Leopard** is internal to Google and described only in the Zanzibar paper, and **AuthZed Materialize** is a commercial early-access product for SpiceDB. Neither is available to an open-source project.

OpenFGA does not offer rasterization either. It offers demand-driven caching with changelog invalidation, which is a different mechanism and, combined with `BatchCheck`, is sufficient. Precomputation can be revisited if measurement ever demands it, and only then.

### If OpenFGA fan-out is still too expensive, measure first, then consider a local negative filter

Recorded as a contingency with a trigger, NOT as a design element. Do not build it before measuring.

What OpenFGA has, verified in `go.mod` and `.config-schema.json`: no bloom filter, no cuckoo filter, no sketch, no probabilistic membership structure of any kind. Its cache is `Yiling-J/theine-go`, a W-TinyLFU exact-answer cache. (Its internal count-min sketch governs eviction, not authorization, so it is invisible to a caller.)

`checkQueryCache` does cache the boolean, so a repeated denial is served without touching the datastore. What it cannot help is a first-time `(subscriber, object)` pair, and on a CDC stream every row carries a fresh primary key, so first-time pairs are the common case. `checkIteratorCache` absorbs the expensive shared graph work behind those checks, which may well make the residual cost small enough that nothing further is needed. Measure before assuming otherwise.

If measurement does show a problem, the smallest correct addition is a local negative filter in connetto: a probabilistic set of allowed pairs consulted before calling out, skipping the call on "definitely not allowed" and falling through on "maybe". It is safe in exactly one direction, since a bloom filter has false positives but no false negatives, so it can only cause a redundant check, never a wrongful grant. It would be maintained from OpenFGA's `ReadChanges` changelog, the same stream `cacheController` already polls. This is far smaller than the rasterization struck above.

Trigger for revisiting: a measured CDC dispatch throughput below the deployment's requirement with `BatchCheck` and both caches enabled. Not before.

## The rule that governs claims about external systems

**Never assume an external system's capabilities, API, or performance characteristics. Read the protobuf, the config schema, the vendor documentation, or the installed source first.** This matters most when the claim is being used to argue against a decision already taken, because an unverified assumption then reopens settled ground.

The concrete failure that produced the rule: the case against putting OpenFGA on the read path rested on it costing N network calls per event. `BatchCheck` has always existed, and one look at the service definition would have shown it. On the strength of that assumption an entire rasterization requirement was invented and two unusable systems were proposed.

A second claim failed the same way: that RLS on the change path is a set-shaped read filter. On that path it is used point-shaped, one row at a time, which is the worst combination available.

## The seven questions, all answered

Answers are recorded under "The seven answers" below, and normatively in `docs/architecture/12-identity-session-capability.md`. Kept in struck form so nobody re-derives the list and asks again.

- ~~The resolution rule's wire shape.~~ Answered: no field at all.
- ~~How a revocation is noticed.~~ Answered: the Postgres change log, and decision 13 was wrong to name OpenFGA's changelog.
- ~~How the CDC path obtains the OLD row image.~~ Answered: `REPLICA IDENTITY FULL`, checked at startup.
- ~~What names an application-defined anonymous session.~~ Answered: nothing, it has no file.
- ~~Whether the adoption primitive is offered natively.~~ Answered: it is not built at all.
- ~~What happens to `AuthContext.tenant_id`, `.roles`, `.claims`.~~ Answered: deleted.
- ~~Whether `FatalErrorReason::SessionRevoked` gets wired.~~ Answered: yes, in R2.

### Closed by a decision, do not re-open

- What `Credential` and `Principal` become: **decision 9**, a list of grants resolved independently.
- Whether a failed grant is fatal: **decision 9**, reported and not fatal.
- Whether the snapshot path leaves RLS: **decision 10**, it stays, permanently and by design.
- Whether `RlsAuth` survives: **decision 11**, it does, as half the design rather than a stand-in.
- Whether CDC checks old and new: **decision 12**, it does, and the current single check is a leak.
- What revocation latency is promised: **decision 13**, strict on writes, cached on CDC, teardown on revocation.
- What an anonymous caller may do: **decision 7**, whatever its grant authorizes.
- Whether anonymous callers are throttled harder: already decided in the PARENT plan under E7, "request throttling, tiered by whether the caller has an identity". The only part still open there is what coarse key the anonymous tier uses, which E7 already records as its own question.


## The status-marker discipline

Documenting a design ahead of building it is how `session_token` came to look authoritative for the life of the repository while never existing. The discipline that prevents a repeat: **every normative statement carries a status marker**, one of `Built`, `Built, defective`, or `Decided (RN)`, and a chapter may not claim a mechanism exists without naming the phase that builds it. The convention is defined at the top of `docs/architecture/12-identity-session-capability.md` and repeated in `docs/architecture/08-authorization.md`.

`docs/architecture/12-identity-session-capability.md` is the canonical chapter for the identity model, and it governs where other chapters disagree with it.

## Bearing on uncommitted E6 work

`Credential::{Anonymous, Token}`, `Principal`, `AuthPolicy` and `SnapshotSource` over `&Principal`, `SessionConfig::allow_anonymous`, and the anonymous refusals are written, green, and uncommitted. They are the right vocabulary and should survive, but `Principal` must be reshaped to carry a capability before it is committed, per decision 3. The `Credential::Token("token")` placeholder restored in `boot_db_worker` is a scar of the defect and disappears with decision 2.

One defect E6 step one produced and then reverted, worth remembering: wiring `boot_db_worker` to declare `Credential::Anonymous` when `auth` is `None` broke every demo write, because the placeholder string is what the trusting verifier turns into the watermark identity. Compiling and the whole native suite stayed green. `examples/wasm-smoke/tests/topology.rs` hanging on its tab write in a real browser is what caught it.

---

# The rework: phases live in the master plan

**Phase definitions, their order, their blockers, their steps and their acceptance are in `plans/master-implementation-plan.md` and nowhere else.** They were duplicated here and the copy drifted: it covered R1 to R9 only, so it silently omitted R11 and R12 and disagreed with the master plan about what blocks R3, R5a and R7.

Two documents defining the same phases is the failure this removal exists to prevent, because a reader has no way to tell which copy is current.

What stays here is what the master plan does not carry: the defect and how it arose, the map of affected code, the decisions and the seven answers, and the bearing on the uncommitted tree.

---

# The seven answers

| Question | Answer |
|---|---|
| 1. The resolution rule's wire shape | No field on `HandshakeAck`, no reason, and not which grant. Refusals go to the structured log only. Supersedes half of decision 9 |
| 2. How a revocation is noticed | The Postgres change log connetto already reads, with `rls2fga` naming the authorization-relevant tables. Nothing polls the authorization service. The response is a per-subscription resync, never a synthesized deletion. Corrects decision 13 |
| 3. How the change path obtains the previous row | From the change log, requiring `REPLICA IDENTITY FULL`, checked at startup with a refusal. A server-side row cache was rejected as a second copy of the customer's data |
| 4. Whether `SessionRevoked` gets wired | Yes, in R2, with `Outbound::Fatal` and a connection registry keyed on the durable session handle |
| 5. The three `AuthContext` fields | Deleted. Both plausible futures already put tenant and role in the authorization model |
| 6. What names an unidentified session | Nothing. Its copy is in memory, always, using the `Replica::Ephemeral` variant that already exists. Consequence: such a session is online-only |
| 7. Whether adoption is offered natively | It is not built at all. In-memory removed the need for it. A flush before the switch and a server-side re-keying seam replace it |

---

# Facts verified against source

Every item below was read out of the source rather than asserted. Several contradicted what the plan had assumed, which is why they are recorded here rather than left implicit.

**External facts the plan had wrong or assumed.**

1. `BatchCheck` is capped at 50 questions per call by default, and 50 evaluated concurrently. "One call covers every subscriber of one row" is false past 25 subscribers under the two-check form.
2. All three OpenFGA caches default to **disabled**, each with a 10s TTL. Cache invalidation from recent writes is triggered by incoming questions, not by a background poller, so an idle store does not invalidate itself.
3. `read_changes` is a unary paged call with a default maximum page size of 100. There is no streaming changelog: `streamed_list_objects` exists, `streamed_read_changes` does not. Watching OpenFGA would mean polling, which is why it is not the notice source.
4. `changelogHorizonOffset` defaults to 0, so `ReadChanges` is not artificially delayed. Recorded because it is the kind of thing that gets assumed the other way.
5. Postgres `REPLICA IDENTITY DEFAULT` records nothing at all when a table has no primary key, not just the key columns.
6. `rls2fga` emits whole-table loading queries and no per-row mapping, does not translate attribute conditions at all, and requires the deployment to load records mapping users to Postgres roles. The first blocks R5b, the second creates the snapshot-versus-change-path divergence R5 must gate on, and the third settles what happens to `AuthContext.roles`.

**Defects and inconsistencies not previously named.**

7. `docs/architecture/08-authorization.md` (`### The two-check form does not handle a policy change`) claimed the two-check table handles an authorization change rather than a data change. It cannot: with no data change there is no event on which to run either check. Two disjoint mechanisms were being described as one. Fixed.
8. The audit table was defined as `auth_log` in `08-authorization.md` while `docs/architecture/11-authentication.md` (`**Audit.**` in `## Deployment shape`) and `docs/architecture/open-questions.md` (Q8.6) both call it `auth_events` and the first cites `08` as the definition. `auth_events` is the name. Fixed.
9. The unconditional tombstone replay is an existence leak in its own right, disclosing the primary key, timing, and for sequential keys the row count of rows the subscriber could never see. The leak is two-way, not one-way.
10. R6 is hard-blocked on R5b rather than cost-blocked, because RLS cannot evaluate visibility against a row that is no longer in the table. `AuthPolicy::can_read` also cannot express which version is meant, so the trait signature changes. This is also why R5b is a correctness prerequisite rather than a performance option: no measurement can veto it, only decide whether it is sufficient.
11. The catchup path carries the same two-check obligation as the live path and reads connetto's own oplog, so the oplog must carry what the checks need or the leak moves to reconnect.
12. The session handle must persist outside the local replica, which falls out of the shopping-cart case: an unidentified session's replica is in memory, so a handle kept inside it would not survive a reload.
13. An ephemeral replica with a file local tier produces a durable unencrypted database, the exact variant E5 deleted, because the tier inherits the replica's key and an ephemeral replica has none.
14. `Oplog::prune` is called from both implementations' own `append`, so it is not dead. It is an implementation detail exposed as a public trait method, where a caller would race with `append`. Remove it from the trait rather than finding it a caller.
15. The architecture diagram labels the OpenFGA integration as living in connetto-server's materializer, which the R5a and R5b decisions make stale.
16. `subql` already ships previous-versus-current transition detection per subscriber for the subscription predicate (`docs/architecture/subql.md`, `### UPDATE transition detection`). Decision 12 is the authorization instance of a mechanism that exists one layer down, so R6 follows its shape rather than inventing one.

**Resolved after the six doubts were worked.**

17. ~~The local tier's scope.~~ **Decided: it stays keyed to the replica**, so durable never-syncing data needs an account and an unidentified session gets an in-memory one. Recorded with both sides: the motivating case is an application letting somebody write before creating an account, and the reason it is not obvious is that a device-scoped file is readable by everyone who uses the machine, which is wrong for a draft. Note that my earlier framing merged two different things: the local tier is a separately attached database whose tables never sync, whereas owner-less **synced** data duplicated once per identity lives in the replica and is a different question, now item 22.
18. ~~The shape of `rls2fga`'s per-row mapping.~~ **Decided: it emits structure rather than SQL text**, marking which patterns are pure. See R5b. Also corrected: only one of eight emitted shapes joins, not the general case.
19. ~~What the oplog must carry.~~ **Answered: nothing.** It already serializes the whole change event. See R6.

**Newly identified, and both are outside this refactor.**

20. **`open-questions.md` Q1.3 and Q9.1 required a `SharedWorker` that connetto never used and cannot use.** `createSyncAccessHandle` is `[Exposed=DedicatedWorker]` in the WHATWG File System IDL, and Chrome does not expose the `Worker` constructor inside a `SharedWorker`, so there is no nested-worker route either (the second verified by probing Chrome 150). The shipped topology is a dedicated worker with a Web Locks election (`spawn_db_worker` in `crates/connetto-web/src/workers.rs`), and `crates/connetto-web/src/broadcast.rs` records why. Nothing in the repository constructs a `SharedWorker`. **Resolved.** The support table now gates on the APIs connetto actually uses, and it was wrong in both directions: Chrome desktop and Edge rise from 86 to 102, because the old floor came from the OPFS root rather than from `createSyncAccessHandle`, which is the API that actually gates the design.
21. **Chapter question lists can drift from the index that answers them.** Ten chapters had. Roughly 45 entries, one of them (`02-protocol.md`, the serialization format) contradicted by shipped code in `connetto-core/src/codec.rs`. Swept. `07-file-sync.md` is marked deferred to a future phase after the current work rather than permanently out of scope, per the maintainer.
22. **Owner-less synced data is duplicated once per identity.** A public catalogue, map tiles, or a dictionary lives in the replica, which is named from the identity, so three signed-in users on one device hold three copies. Sharing a store across identities is exactly the boundary Phase 4 established, so this is not a small change and it carries a disclosure dimension. Not decided.

---

# Bearing on the uncommitted tree, restated

62 modified source files plus one new test file are the E6 step-one work, and the tree is untouched. **R3 supersedes its central type.** The vocabulary survives. `Credential::{Anonymous, Token}` does not, because it cannot express a grant that authorizes without identifying, and because a caller must be able to present a list.
