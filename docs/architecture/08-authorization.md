# 08: Authorization

**Status**: normative. Statement-level markers follow the convention in `12-identity-session-capability.md`, which is the canonical model for what a session, an identity, and a capability are. Where this chapter disagrees with chapter 12, chapter 12 governs.

| Marker | Meaning |
|---|---|
| **Built** | In the tree and exercised by a test. |
| **Built, defective** | In the tree and wrong. The defect and its fixing phase are named. |
| **Decided (RN)** | Settled, not built. `RN` is the phase in `plans/identity-session-capability-refactor.md`. |

---

## Purpose

Define how permissions are enforced on reads (snapshot delivery and change delivery), on writes, and on file access. Authorization is on the hot path of every delivery, so it must be correct, auditable, and fast, in that order.

---

## Principles

1. **Every row delivered has been authorized.** There is no client-trusted filtering.
2. **One policy, one source.** Postgres RLS policy text is the source language. Two executors run it and neither is allowed to diverge from the other, which is a property of the compiler between them rather than of either executor.
3. **Authorization is evaluated server-side.** A client never receives rows it may not see, even partially.
4. **Read denials are silent, and silence includes existence.** A row that fails a check is omitted rather than reported. Disclosing that a row exists is itself a disclosure, which is why a deletion the caller could never see must not be forwarded either.
5. **A withdrawal is as much a delivery obligation as a grant.** A caller who loses access must have the rows withdrawn from its local copy. Nothing about "the client stops receiving updates" removes what it already holds.

---

## The caller

**Built (R3).** Every check takes a `Principal`, which carries an optional identity plus whatever capability subjects resolved from the grants the caller presented, on a handle that is never absent. Three of the four arrival cases have a policy consequence:

| Identity | Capabilities | May read | May write |
|---|---|---|---|
| no | none | whatever the policy shows a caller with no identity | nothing |
| no | some | whatever those capabilities grant | where those capabilities grant it |
| yes | none | whatever the identity grants | where the identity grants it |
| yes | some | the union | the union |

**Fixed (R1, R2, R3, R4).** The caller used to be an `AuthContext` with a mandatory user id, so a caller with no identity was impossible to express and one was invented from the client's own handshake string. The visibility policy, `SnapshotSource` and the write target all take a `Principal` now. Every row of the table above is load-bearing: R3 carries the accepted subjects and R4 binds them into the read, the write and the change path, so a caller with no identity and one share key reads and writes exactly what that key's relations allow.

**Decided (R8).** An identity carries a user id and nothing else. `tenant_id`, `roles`, and `claims` are deleted, because they were written and never read, and because tenant and role both belong in the authorization model rather than on the session. `open-questions.md:283` decided the first and `rls2fga` requires the second, emitting a `pg_role` type with a `member` relation and stating that the deployment must load records mapping users to Postgres roles.

An authorization change does not require a new session. Permissions resolve per question rather than being cached at connect time, so there is no in-session re-authentication mechanism to build.

---

## Policy source and executors

**Decided, and already recorded at `open-questions.md:262`.** Postgres RLS policy text is the source of truth. [`rls2fga`](https://github.com/LucaCappelletti94/rls2fga) parses it, classifies each `USING` and `WITH CHECK` expression into one of ten canonical patterns, and generates an OpenFGA authorization model plus SQL that populates the corresponding relationship records. At runtime, point-shaped visibility questions go to OpenFGA rather than to direct SQL evaluation or to an in-process compilation of RLS.

Two executors, split by the shape of the question and not by convenience:

| Path | Question shape | Volume | Executor | Status |
|---|---|---|---|---|
| Snapshot | set filter | one query, many rows | Postgres RLS, inline in the query | **Built** |
| Change delivery | point check, twice per row per subscriber | rows times subscribers, hot path | OpenFGA | **Decided (R5b, R6)** |
| Write | point check, once per operation | one per operation | OpenFGA | **Decided (R5b)** |

### Why the snapshot stays on RLS, permanently

Not interim. A snapshot is a set filter, and RLS answers it in one round trip using the planner's own indexes with no result cap. OpenFGA's enumeration direction measurably cannot stand in: `listObjectsMaxResults` defaults to 1000 and `listObjectsDeadline` to 3 seconds, and enumerating everything a subject may see is the expensive direction in this family of systems. A truncated snapshot would be silent data loss rather than an error.

So the split is deliberate: **RLS answers set-shaped questions at snapshot time, and OpenFGA answers point-shaped questions on the change and write paths.**

### Why two executors is safe, and what makes it unsafe

It is safe only because `rls2fga` compiles both from one source. That makes the compilation load-bearing rather than a convenience, and it must be tested as such.

**It is unsafe where the compilation is incomplete.** `rls2fga` grades each policy by confidence and does not translate attribute conditions at all: `status = 'published'` and `priority >= 3` are emitted as review items rather than as model relations, and an attribute guard beside a relationship check is only partially translated. A dropped permissive clause grants nothing, so the compiled model is **narrower** than the policy it came from. Narrower means a row the policy allows would be returned by the snapshot, which runs real RLS, and then denied on the change path, which runs the compiled model. The client would see the row once and never see it change again.

**Decided (R5b): every policy translates, or the deployment supplied a mapping, or startup refuses.** No degradation path and no tolerated divergence, because a divergence between the two executors is the one thing the single policy source exists to prevent.

**Decided (R5b): and a policy reading a table the publication does not carry also refuses startup.** A second refusal on the same path, and it exists because the change-path executor learns about permission changes only from the replication stream. A policy that joins a grants table the deployment did not replicate therefore never hears that a grant was given or taken away, so the store goes stale and then answers confidently and wrongly, which is silent rather than loud. `rls2fga` reports the complete set of tables each policy reads and the publication is known, so this is a set comparison that can name the missing table. Routing such a policy to the supplied-mapping seam instead was rejected: the crate classifies these policies perfectly well, and the seam exists for what it cannot classify.

That rule is only satisfiable because the gaps are closable rather than inherent. **OpenFGA is not the limit.** It has first-class conditions, `Condition { name, expression, parameters }` where the expression is a Google CEL string, and `RelationshipCondition` attachable to any tuple, so attribute predicates are expressible in the model. And the row-attribute cases look like a generalisation of the boolean-flag pattern `rls2fga` already emits, which qualifies rows with a `WHERE` on the tuple query, rather than a new mechanism. So three tiers upstream: generalise the row-attribute handling, use conditions where the predicate is not row data, and expose a generic plus trait seam so a downstream user supplies a mapping for anything left unclassified.

**An earlier draft of this chapter had connetto degrade instead**, marking a table not subscribable when its policy graded below confidence B. That treated a gap in one crate's coverage as a permanent property of the authorization service, and built connetto to survive it rather than closing it. Recorded because the error is the instructive part.

The direction of the failure is what makes the rule absolute rather than advisory. Dropping **narrows**: a dropped permissive clause grants nothing and a dropped restrictive clause becomes `no_access`. So a below-threshold model denies what the policy allows, which is fail-safe for security and unsafe for correctness. A client would see a row in its snapshot, taken under real RLS, and then have it withdrawn on the first change because the compiled model calls it invisible. Rows would **vanish** rather than leak, and refusing to start prevents a deployment discovering that by watching data disappear.

### Where the check lives

**Decided (R5a).** The visibility trait is defined in `subql`, which holds the replication connection and already computes previous-versus-current transitions per subscriber. connetto's `AuthPolicy` (`crates/connetto-core/src/traits.rs`) is superseded by it. **R5a lands the trait and nothing behind it:** `subql` is `no_std`-capable, so an authorization-service client is a network dependency it does not take on for a seam relocation, and the implementation R5a puts behind the trait uses Postgres row-level security and lives here, because binding a caller into a database session is deployment-specific identity policy. **Decided (R5b):** the OpenFGA-backed implementation `subql` ships arrives with the executor swap, not with the seam. An earlier version of this paragraph attributed it to R5a, which contradicted R5a's own step 3.

**Decided (R5a).** The seam relocation is a separate phase from the executor swap (R5b). It is blocked on nothing, and the implementation behind the trait initially still uses Postgres RLS, so the phase changes no behaviour. It goes first because the measurement (R0) instruments a seam that must not then relocate, and because relocating first reduces R5b to substituting an implementation rather than restructuring a call path.

**And the measurement must count the round trip, not the seam.** The trait is answered once per changed row for every watcher at once rather than once per watcher, so from R5a onward one entry to the seam is not one question to the backend: the RLS implementation behind it still opens one transaction per watcher inside its own loop. A counter left at the seam would read one per event from the day R5a ships, and R5b's entire acceptance criterion, that the counter stops growing with subscriber count, would then be satisfied by a phase that removed no round trips at all. This is the concrete form of the sentence above about instrumenting a seam that must not relocate, and it is easier to get wrong than that sentence suggests.

That direction is chosen because the trait has callers on both sides, and there are four rather than three. On the change path, `SessionManager::dispatch_event` asks one question naming every watcher of the event. On the catchup path, `SessionManager::catch_up_row` asks about one watcher per replayed record. On the write path, the per-op loop in `SessionManager::handle_mutation` asks the write question. And the minting path, `CapabilityIssuer::issue`, asks the read question about the row it is being asked to share. All four are in `crates/connetto-server`. Defining the trait low and consuming it upward serves them all, and it follows an idiom subql already uses twice: query re-execution works by subql asking the caller through a `Connector`, because the query and its retry belong to the caller (`subql.md:13`).

**Built (R5a, 2026-08-04).** The trait is `subql::visibility::VisibilityPolicy`, with `may_see` over many watchers and `may_write` over one, and the row arriving as a `RowView` bound to one version. connetto's `AuthPolicy` is deleted. `RlsAuth` implements the trait as the row-level-security answer and is what R5b dissolves, so the earlier reading that R5a itself dissolves it was wrong: RLS survives either way, and `RlsAuth` survives until the executor changes. RLS also continues to filter the snapshot through `PgSnapshotSource` and to gate the write through `PgWriteTarget`, both of which bind the caller directly and never go through the trait.

**A failure denies one watcher, not the event.** The caller pre-fills the verdict buffer with denials, and `RlsAuth::may_see` writes only the grants, carrying on past a watcher whose round trip failed rather than returning. It returns an error only for what is identical for every watcher, a key cell that will not decode or a key type it cannot bind. That reproduces exactly the granularity the per-subscriber check had, which is what makes the relocation behaviour-preserving.

**The architecture diagram is stale on this point.** It labels the OpenFGA integration as living in connetto-server's materializer.

---

## Read authorization

### At snapshot time

**Built.** The snapshot query runs with `app.user_id` bound for the session, on a pool whose role is subject to RLS, so only rows that pass the policy are included in the `SnapshotPatch`. This is the natural behaviour of executing the query as the caller.

**Fixed (R1).** The reference binary refuses to start without `CONNETTO_READER_URL`, so snapshots, read authorization, and mutation applies never run on the owner pool, where RLS is bypassed entirely because Postgres does not apply policies to a superuser or to the table owner.

A caller with no identity leaves `app.user_id` unset for the whole transaction rather than binding an empty string. That is deliberate and it is what makes the policy answer correctly with no policy change: `current_setting('app.user_id', true)` is NULL, so an owner comparison is NULL rather than true and the row is hidden, while a public predicate still returns its own rows. An empty string would be a real identity that happens to be blank, and a policy comparing against it could match.

### At change time

**Decided (R6).** For each candidate subscription, authorization is checked against **both** versions of the row, and the pair decides what is delivered:

| Previous visible | Current visible | Delivered |
|---|---|---|
| no | no | nothing |
| no | yes | insert, the row became visible |
| yes | no | delete, the row became invisible |
| yes | yes | update, or insert plus delete if the row identity changed |

**The second check is conditional, not unconditional.** The previous version only decides between the two rows where the current version is invisible, so the order is: check the current version, deliver and stop if it is visible, and only then check the previous one. A deletion has no current version, so it always falls through to the previous-version check, which is exactly what filters a tombstone. An insertion has no previous version, so an invisible insertion delivers nothing. The cost is therefore one check per subscriber plus one more for each subscriber who cannot see the current version, not two per subscriber.

**Built, defective, and it is a leak in both directions.** `dispatch_event` (`crates/connetto-server/src/session.rs`) checks once and forwards every tombstone unconditionally.

Forwarding every tombstone is what actually withdraws deleted rows, so the withdrawal path R6 needs already exists and the client side needs nothing new. But it forwards the primary key of a deleted row to every subscriber of the table, including those who could never see it, which discloses the existence, the identifier, and the timing of private rows, and for sequential identifiers the row count as well. Principle 4 forbids it in writing.

The other direction is the worse one. An update whose current version is invisible is silently dropped, so **a caller who loses access to a row keeps the last version it saw, in its local copy, forever.** Nothing withdraws it. That is a leak rather than a missing feature, and it is why R6 is not merely a documentation mismatch.

**The previous version has to come from somewhere, and RLS cannot supply the answer at all.** `RlsAuth::may_see` runs `SELECT EXISTS(SELECT 1 FROM tbl WHERE pk = ..)` against the live table (`crates/connetto-server/src/auth.rs`), so for an update it can only answer about the current version, and for a deletion the row is gone and it answers false for everyone. R6 is therefore hard-blocked on R5b rather than merely expensive without it. The trait itself does name the version, since R5a: a question is asked about whichever `RowView` the caller hands over, and `EventRow::previous` builds the one bound to the pre-image. What is missing is a backend that can answer about it.

**Decided (R6).** The previous version comes from the change log, which requires `REPLICA IDENTITY FULL` on every replicated table. `DEFAULT` records only the primary key columns and records nothing at all when a table has no primary key. This becomes a deployment requirement checked at startup in R6, with a refusal to start when a replicated table lacks it. Every existing test fixture already sets it (`cdc_ingest_reconnects_after_walsender_drop` in `crates/connetto-server/tests/cdc_reconnect.rs`, `reset_fixture` and `e2e_rls_write_enforced_owned_lands_foreign_refused` in `crates/connetto-server/tests/e2e.rs`, and `Fixture::start_replication` in `crates/connetto-test-harness/src/lib.rs`) and nothing checks it, so the change is turning an accident into a requirement. The alternative, keeping a server-side copy of every replicated row, trades a schema requirement for a second copy of the customer's data and is rejected.

**The catchup path has the same obligation.** Reconnect catchup re-filters per client from connetto's own oplog (`SessionManager::catch_up_row` in `crates/connetto-server/src/session.rs`) rather than from the change stream, and today it skips the check for tombstones exactly as the live path does. So the oplog must carry whatever the two checks need, or the leak simply moves to reconnect.

### The two-check form does not handle a policy change

**Correction to this chapter's earlier text**, which claimed the table above handles a case where an authorization change rather than a data change makes a row appear or disappear. It cannot. With no data change there is no change event on which to run either check. The two forms cover disjoint cases: the table above covers data changes, and the section below covers authorization changes.

---

## When an authorization change arrives

Two tiers, matching `open-questions.md:266-269`.

### A rules change

**Decided.** The policy text itself is altered, `rls2fga` re-translates, and the model is replaced. This is a deploy-time event. Every active session is invalidated and clients re-subscribe from scratch. Rare by nature, and the server is being redeployed around it anyway.

### A grant change

**Decided (R7).** A row appears or disappears that grants somebody access under unchanged rules. This is the runtime case.

**What notices it is the Postgres change log connetto already reads.** A grant is a Postgres row, so withdrawing one is a row change on the stream connetto is already consuming end to end. `rls2fga` names which tables carry authorization meaning, because reading the policies is the only thing it does. Nothing polls OpenFGA, and OpenFGA is never a notice source: every permission is backed by a Postgres row, and a permission existing only in OpenFGA would make it a second source of truth, which is the divergence `rls2fga` exists to prevent. (OpenFGA could not be watched cheaply in any case. `ReadChanges` is a unary paged call with a default maximum page size of 100 and there is no streaming changelog, so watching it would mean polling.)

**What happens is a per-subscription resync, and never a synthesized deletion.** The changed row names its grantee, so that grantee's affected subscriptions receive `FullResyncRequired`, the client discards what it holds for those subscriptions, and the fresh snapshot recomputes the whole visible set under RLS. The machinery is **Built** end to end: the message exists (`crates/connetto-core/src/messages/reconnect.rs`), the server sends it (`SessionManager::subscribe_row` in `crates/connetto-server/src/session.rs`), and the client already clears the subscription's rows before applying the snapshot as a replacement rather than a merge (`ConnettoConnection::handle_control` in `crates/connetto-client/src/lib.rs`). `FullResyncReason` gains a variant for this cause, which is itself a wire change because that enum has no fallback for an unknown value.

Manufacturing a tombstone per affected row was considered and rejected. The changed grant row names the grantee but not the objects, so finding the affected rows means asking which objects the subject can see, which is the capped enumeration direction. A truncated withdrawal does not announce itself as truncated, so it would leave rows behind while reporting success. Resync avoids the question entirely, because a replacement is complete by construction where a diff is not. This is the reason the teardown was chosen, and it is stronger than the reason previously recorded.

Note that finding the objects is not needed, only the grantee. Removing somebody from a team that could see five hundred documents names that person in the changed row, and resyncing their subscriptions recomputes all five hundred correctly.

**Residual case.** A nested group model, where the changed row joins one group to another and names no person. The affected callers are then one join away in Postgres, which connetto can follow, because it is a Postgres row like any other. Worth stating and not worth a mechanism.

### The promise a deployment can rely on

**Decided (R7).** An authorization change takes effect immediately for writes, within the read cache TTL for reads, and immediately for both when it triggers a teardown.

Writes use the strict consistency preference, because they are low volume and a write accepted against a just-withdrawn capability is the case that must never slip through, which is exactly the moment a leaked key is being revoked. Reads on the change path keep the fast preference and its caches, because that is what makes the fan-out affordable at all, so a caller who has lost access may see at most one further patch within the TTL.

Two constraints, both verified. The preference is chosen per request and not per item inside a batch, so a strict question cannot travel in the same batch as cached ones. And there is no way to express "this read must reflect that specific write", only the coarse two-level preference, which bounds how precise a revocation promise connetto can make.

`FatalErrorReason::SessionRevoked` (`crates/connetto-core/src/messages/error.rs`) is **Built, defective**: it exists on the wire and is never constructed, so a session revoked mid-connection is simply never told. R2 wires it, because it keys on the durable session identity R2 builds and there is nowhere earlier it can live.

---

## Write authorization

**Built, defective.** `VisibilityPolicy::may_write` returns allowed while ignoring every argument, in both production implementations (`PermissiveAuth` and `RlsAuth` in `crates/connetto-server/src/auth.rs`). The call path is live: the per-op loop in `SessionManager::handle_mutation` calls it once per operation, and a test policy that denies proves a denial yields `Unauthorized`. So it is a wired, tested hook with no policy behind it.

**It is not vestigial and must not be deleted.** It is the seam OpenFGA attaches to, and R5b is what puts a policy behind it.

**Built.** Separately from that seam, a mutation applied through `PgWriteTarget` runs inside a transaction that binds `app.user_id` first, so Postgres RLS gates the write itself: a policy's `USING` clause doubles as `WITH CHECK`, an insert or update violating it is a hard error, and an update or delete of an invisible row shows up as a zero-row shortfall. That is a second, independent enforcement point and it is the one carrying weight today.

A rejection returns a reason code and nothing about why beyond it.

---

## Capabilities

**Built (R4).** A capability is a connetto-signed token asserting one thing: that the bearer is a named subject, for example `key:abc123`. It says nothing about what that subject may do. The permission is a relation on that subject, `document:readme#viewer@key:abc123`, derived from a Postgres row the application owns, exactly like every other permission.

**So a capability and a login token are one mechanism with two kinds of subject.** The login token authenticates `user:alice`, the capability authenticates `key:abc123`, and this chapter answers what each may do in exactly the same way. That is why authorization needs no capability-specific path.

**The permission must not travel inside the token.** A permission carried in the token would split authorization between the token's contents and the model, which is the divergence a single policy source exists to prevent. It is the same objection that rules out a Postgres setting, and it applies with more force to a token, because a token is also a thing the holder keeps.

**Withdrawal therefore needs nothing new from this chapter.** Revoking a capability is deleting the relation, which is a Postgres row change, which is the notice the grant-change path above already watches for. The token stays cryptographically valid and names a subject with no relations left, so no liveness table is needed and nothing is consulted at use time beyond the signature. A capability also carries an expiry, as a second bound beside withdrawal.

**Minting is a library call and this chapter authorizes it.** Creating a capability over a resource is itself an action needing authorization, because a caller must not share what it cannot read, and that check goes through the same trait as every other question here rather than being reimplemented by each application. Chapter 12 covers the wire shape, the grant list, and what the reply says about a refusal.

**Decided (R5a, 2026-08-04): the mint call reads the row, as the caller.** The question is about a row and the caller names only its key, so `CapabilityIssuer::issue` reads the row through a `RowSource` before asking, and hands the values over as the view. Two things follow, and the second is why the choice is not free. Values supplied by the caller are refused outright, because a caller that can state the row's contents can get an answer about a row that does not exist. And the read runs as the caller rather than through a role that sees everything, because otherwise a hidden row and an absent row are two different code paths, one running one query and the other two, which separates them by timing and turns minting into a probe for rows. The cost is that on this one path the fetch enforces the read and the question behind it can only agree, so the seam earns its place there at R5b rather than today.

**How the subject reaches a policy, on all four paths.** A policy compares against values the transaction bound, so the caller's identity and the keys it holds are bound as its first statement, by one shared `CallerBinding` (`crates/connetto-server/src/capability.rs`) that `PgSnapshotSource::snapshot`, `PgSnapshotSource::read_row`, `PgWriteTarget::commit` and `RlsAuth::may_see` all go through. One binding rather than four is the point: the snapshot and the change path are different executors and a caller bound in one but not the other would see a shared row once and never see it update, which is exactly the divergence "Why two executors is safe" warns about. The identity goes under one setting, `app.user_id` by default, and the keys travel as one packed value under a second, `app.subjects` by default, named and packed by the deployment's own key type through `CapabilityKey`. Chapter 12 has the shape and the reasoning.

**Both settings are named by the application, since 2026-08-06.** The keys have been its choice since R4, through `CapabilityKey::SETTING`. The identity was fixed in connetto's source until now, for no reason beyond the key setting having a configuration object to live on and this one not, which is a fact about how the code grew rather than a decision. It is `DEFAULT_USER_SETTING`, still `app.user_id`, with `with_user_setting` on each of the three types that bind: `RlsAuth`, `PgSnapshotSource` and `PgWriteTarget`. An application fitting connetto into rules that already name things its own way can now rename either.

`a_policy_may_name_its_own_identity_setting` pins it, and the half that earns its place is the negative: a policy reading its own name sees nothing when the binding is left at the default, because connetto would be setting a name the policy never reads. Without that, the test would pass even if renaming did nothing.

**The row that grants a capability is authorized like any other row.** Connetto checks the caller may read the resource the mint call names, but the application writes the permission row itself, on its own connection, so what stops that row naming a different resource is a `WITH CHECK` on the sharing table requiring the shared row to be visible to the sharer. That is one policy source deciding both halves, which is this chapter's first principle rather than an extra mechanism.

---

## File authorization

File metadata is authorized as an ordinary row on the files table.

File content authorization uses a short-lived signed token so that fetching a chunk needs no database lookup: the server checks the metadata row once, issues a token naming the file, the content hash, and an expiry, embeds it in the manifest, and validates signature and expiry per chunk. A revoked session can still use an issued token until it expires, and the expiry window is what bounds that.

**Out of scope.** File sync is handled by a separate stack per `open-questions.md:254`, and every design decision here is deferred to it. The token model above is recorded as the intent and not as a commitment.

---

## Cost on the change path

**Built, defective, and this is the current scalability wall.** The row-level-security implementation still runs one round trip per watcher, inside its own loop behind one question per event (`SessionManager::dispatch_event` and `SessionManager::catch_up_row` in `crates/connetto-server/src/session.rs`), and each one takes a pooled connection, opens a transaction, runs `set_config`, runs a `SELECT EXISTS`, and commits, awaited one after another.

**The quantity that is most wrong is network round trips, but it is not the only one.** Authorization is currently K four-statement Postgres transactions, sequential, on the shared ingestion path, and that is the dominant term by three orders of magnitude. Delivery is K in-process channel sends, which is inherent. **What R16 part A established is that the work attached to those K sends is not.** Today each one carries a payload clone, a MessagePack re-serialization of that payload, and a second copy into the outgoing frame, so three full copies of the compressed patch per subscriber per event. Those scale with patch size as well as with K, which the round-trip comparison hides: at K=500 and a one megabyte patch they are three 500 MB passes against the 190 ms attributed to authorization. Both terms are worth fixing, and R16 part B chooses the shape for the second.

**No throughput figure has ever been measured for this project.** The quoted ten events per second at a hundred subscribers is arithmetic: a hundred subscribers times one optimistically-assumed millisecond. The millisecond is generous for a four-statement transaction. For a published reference point in the same shape, PowerSync's replication path does 2,000 to 4,000 operations per second for small rows, where an operation is one row change written into one set, and their figure does not vary with how many clients are watching, because set membership is computed from the row.

**Decided (R5b): round trips per event must not grow with subscriber count.** Batching does not achieve that. `BatchCheck` carries many questions in one call and each item carries a correlation identifier, so the previous-version and current-version answers for one row are distinguishable in one response, but the default limit is **50 questions per call** and 50 evaluated concurrently, so K questions become K over 50 calls and the shape stays linear.

What achieves it is asking a different question. Compute the changed row's records locally, which the structured mapping below is what enables, and read off which groups or roles that row grants to. Then ask **once per distinct group or role**, not once per subscriber, and decide each subscriber by a local set-membership test that touches no network. Where a row grants directly to a user the test is a local intersection and costs nothing. The number of round trips per event is then bounded by how many distinct groups that row's records reference, which is small and has nothing to do with how many clients are watching.

Caching then matters for the group questions rather than the per-row ones. A question cache maps a question to a boolean and an iterator cache holds the underlying datastore reads, for example which groups a subject belongs to. **All of these default to disabled**, each with a ten second TTL, and invalidation from recent record writes is triggered by incoming questions rather than by a background poller, so an idle store does not invalidate itself. Every one has to be turned on deliberately. Group membership changes rarely and the notice stream says exactly when, so these answers cache well, which is the opposite of a per-row question where every changed row carries a fresh primary key.

**Precomputing a materialised permission set is not part of this design.** OpenFGA does not offer it, the two systems that do are unavailable to an open-source project (one is internal to its author and the other is a commercial early-access product), and demand-driven caching with changelog invalidation is a different and sufficient mechanism. If measurement ever shows a problem, the smallest correct addition is a local negative filter consulted before calling out, safe in exactly one direction because a probabilistic set has false positives and no false negatives, so it can only cause a redundant question and never a wrongful grant. Recorded as a contingency with a trigger: a measured change-path throughput below the deployment's requirement with batching and both caches enabled. Not before.

**R5b is a correctness prerequisite, not a performance option.** `RlsAuth::may_see` runs `SELECT EXISTS` against the live table and can only answer about the row as it is now, while R6 needs an answer about the row as it was. No measurement can veto the swap, only decide whether R5b is sufficient.

### An open dependency that blocks R5b

`rls2fga` generates whole-table queries that load every permission record from scratch and nothing that produces the change for one row. So keeping OpenFGA current row by row is unbuilt, and without it no answer on the change path has a stated freshness.

**Decided.** That upkeep lives in `subql`, driven from the change stream, because subql holds the replication connection and is the only place that sees every change with both row versions in hand, and removing a record requires knowing the value it was built from. `rls2fga` supplies the per-row mapping, which is upstream work it does not have today. R5b is blocked on it.

## The per-client floor

**Established by R16 part A**, from primary sources rather than from reasoning outward from this implementation. This section exists because the sentence it replaces was asserted and never checked, and two other phases optimise inside the constraint it claimed.

Per-event, per-client cost separates into six layers. Five of them have been eliminated by at least one system that ships.

| Layer | Eliminated by | Mechanism |
|---|---|---|
| Deciding who is affected | Convex, PowerSync, ElectricSQL | Convex probes an interval map over subscriber read sets at `O((k+1) log n)` in the number *affected*, not the number connected. PowerSync computes a changed row's bucket ids from the row alone. |
| Deciding who is allowed | ElectricSQL, Zero, PowerSync, Convex | Four different hoists off the per-row path: a proxy that fixes the shape, a compiler pass that binds claims into the predicate, a set intersection between the row's buckets and the token's, and a runtime observation of whether the query read the identity at all. |
| Computing the content | everyone, connetto included | One patch per event, not per subscriber. |
| Serializing a frame | Phoenix, Supabase Broadcast, ElectricSQL | Encode cached per distinct frame content, or performed once at log-append time and never repeated. |
| Copying the payload | the Erlang runtime | Reference-counted binaries above 64 bytes are shared between processes, not copied. |
| Writing to the socket | nobody | ElectricSQL relocates the writes to a CDN. They are still K writes. |

**The decisive evidence is a controlled experiment inside one codebase.** Supabase Realtime contains two fan-out dispatchers. Postgres Changes caches its encoded frame on the whole message, which contains the client's own binding ids, and therefore pays a serialization per distinct client. Broadcast caches on `{serializer, topic}`, with no per-client component, and pays one serialization for the entire fan-out. Supabase publishes the consequence: with row-level security on, a large instance sustains 40 changes per second at 500 clients, 10 at 2,000 and 5 at 4,000, against a roughly constant 32,000 to 50,000 total messages per second with it off. Their documentation states "Postgres Changes authorizes every event against each subscriber... so throughput scales with the number of subscribers, not the write rate", and recommends Broadcast instead above roughly 3,000 subscribers because it "sends each change once and fans it out to all subscribers".

**Which protocol properties move the floor**, ordered by leverage:

1. **No per-client identifier in the frame.** The single largest lever, and the one the Supabase pair isolates. Phoenix's broadcast frame deliberately omits the reference fields its reply frame carries, and that omission is what makes one encoding valid for every socket.
2. **A position named by a value derived from the stream, not by per-connection state.** When the resume point is a value the client supplies, the response becomes a pure function of resource and offset, hence identical across clients and collapsible by generic infrastructure. This is the whole basis of ElectricSQL's fan-out.
3. **Subscription identity derived from the question, not the asker.** ElectricSQL hashes the shape definition, Zero hashes the query after permissions are compiled in and claims are bound. Two clients asking the same authorized question become indistinguishable below that point.
4. **Authorization expressed as a partition over subscribers rather than a question per row per subscriber.** This is what R5b already decides, corroborated here from four independent directions. It is also the precondition for property 3 to pay anything, because two clients on the same query who may see different rows cannot share an artifact however it is shaped.
5. **Payload carried by shared reference rather than by value.**

**Where connetto stands against that.** Matching is already at the state of the art and needs nothing: `subql` interns predicates by a hash of normalized SQL and refcounts them, evaluates each candidate predicate once, and resolves matched consumers from a bitmap, so two clients issuing the same SELECT already share one evaluation. Content computation is already once per event. Authorization is where Supabase Postgres Changes is, which R5b addresses. The remaining gaps are properties 1, 3 and 5, and one finding with no counterpart in any studied system: reconnect catchup rebuilds each missed patch per client per subscription rather than reading a stored one.

**R16 part B chooses the shape.** It is gated on R0 so that it targets a measured cost. The scheduling coupling to R3 that part A discovered is dissolved: the bulk frame decision is settled (recorded under R16's inputs in the master plan) and `PROTOCOL_VERSION` stays frozen until the first release (see `02-protocol.md`).

---

## When the authorization service is unreachable

**Decided (R5b): fail closed.** No patch is delivered and no mutation is accepted while the answer is unknown. A patch delivered to a caller who may not be allowed to see it cannot be recalled, whereas a stall can be recovered from, and every other decision in this chapter has preferred a loud stall to a quiet leak.

This is a failure mode R5b introduces. Today the change path asks Postgres, which connetto already depends on for everything, so there is no separate service to lose.

**Two things must reach the client, and the second is a correctness matter rather than a nicety.**

A caller must be able to tell that delivery is **paused** rather than that nothing is changing. Without a signal those are identical, and a client waits indefinitely while believing itself current.

And a refused write must **not** be reported as unauthorized. Rejecting it that way says the caller lacks permission when the truth is that the server cannot tell, and a client that believes itself unauthorized stops retrying and may discard the mutation, turning a transient outage into permanent data loss. This needs a distinct reason meaning cannot determine, retry.

**One asymmetry, correct but surprising.** Snapshots keep working throughout, because they run on Postgres RLS permanently and by design. So an outage stops live delivery and writes while a fresh connection can still read. Document it, because nobody will predict it.

---

## Audit

**Decided.** High-volume operational events (denials, connection events, per-row visibility questions) go to structured logging on stdout, and the aggregator is a deployment choice. Phase R12 part A built it: the facade is `tracing`, every crate emits through it, a native program installs `connetto_core::logging::init_stdout` and a browser program installs `connetto_web::logging::init_console`, because a browser has no stdout. Browser events stay on the device and are never shipped to the server. R3 is blocked on part A because a refused grant is silent on the wire and the log line is what makes it loud, and part B carries that assertion. State changes that matter (permission changes, session invalidations, model changes) are persisted to an `auth_events` table for application-level querying. OpenFGA's own audit log covers model and record changes on the authorization side.

**The values an event carries.** Every event carries what happened, and that is the only value required of it. Work serving one caller runs inside a named context opened once the handshake succeeds, carrying the durable session handle, the caller's identity, and the connection number, so every event emitted while serving that caller picks them up without the writing site naming them. An event outside any such context, which is where the server spends most of its life (startup, shutdown, the change stream, and every handshake refusal, since no session exists until a handshake succeeds), simply carries none of the three. **An absent value means absent, never a placeholder**: a stand-in handle on an event that belongs to no session is a fiction, and one this codebase has already paid to delete once. An event that has an outcome carries it.

**Naming correction.** An earlier version of this chapter defined the table as `auth_log` while the Audit paragraph under "Deployment shape" in `11-authentication.md` and `open-questions.md` Q8.6 both call it `auth_events` and the first of them cites this chapter as the definition. `auth_events` is the name. The shape, following the conventions the two built contracts in `11-authentication.md` already established:

```sql
CREATE TYPE connetto_auth_op AS ENUM (
    -- a login ended, and why matters more than the fact
    'logged_out', 'session_revoked', 'token_replayed',
    -- authorization
    'capability_minted', 'permission_change', 'model_change',
    -- abuse response
    'banned', 'ban_lifted'
);

CREATE TABLE auth_events (
    at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    session    UUID NOT NULL,
    user_id    <IdSqlType>,
    op         connetto_auth_op NOT NULL,
    table_name TEXT,
    pk         <RowKeySqlType>
);
```

**Every column type here is a correction, and the reasons are worth keeping.** An earlier version of this block gave eight columns of which five were `TEXT`, including the two that hold closed sets. That was a sketch written before there was code to check it against, and it disagreed with the two contracts it says to sit beside.

`session` is `UUID`, because the durable session handle is a `SessionId` and both tables that already store one declare it `UUID`. As `TEXT` it would need a cast to join against either of them.

`user_id` is the deployment's own `<IdSqlType>`, the same placeholder `connetto_sessions` uses, because the identity type has been the deployment's choice since R8 and a second opinion about it here would be a second contract. Nullable, because a caller may have no identity.

`op` is a Postgres enum type rather than text with the legal values written in a comment. The values are a closed set, connetto's own side is a Rust enum, and the point of a typed contract is that a value outside the set cannot be written by either end. A comment enumerating the legal values is a check nothing performs.

**A login ending is three values, not one, decided 2026-08-05.** An earlier version had a single `session_revoked`, and the code has three quite different reasons a login dies: `logged_out` is the caller ending it themselves through the logout endpoint, `session_revoked` is the embedding application calling `AuthService::revoke` for its own reasons, and `token_replayed` is the theft defence in `rotate_refresh` noticing a rotated-out refresh token being presented and killing the session. Collapsed into one value the table cannot tell an ordinary logout from a stolen credential, which is the single most interesting thing it could report. The information exists at the moment the row is written and was simply being discarded. A closed set of causes belongs in the type rather than in prose, the same call this project made for the oplog verb.

**`capability_minted` was added 2026-08-05** for the successful share mint R13 records. It had no value to write itself as: the mint is connetto's own act of issuing a key, whereas `permission_change` belongs to the grant-change watcher in R7, and collapsing them would have erased the distinction and left one value meaning two things produced by two phases. `table_name` and `pk` name the shared row, which is what those two nullable columns are for.

**`banned` and `ban_lifted` were added on 2026-08-05**, for R36, which bans an identity when a caller repeatedly names something and is told no. A ban is a rare change to who can reach what, which is this table's definition, and it belongs here rather than only in R36's own ban table because that table holds current state with an expiry while this one is the append-only history, so an expired or lifted ban would otherwise leave no trace. **This is not a denial arriving after all**: the refusals that led to the ban still go to the log, one per attempt, and what is recorded here is the single durable decision they produced.

**`allowed` is deleted, decided 2026-08-05.** It was `BOOLEAN NOT NULL`, itself already a correction of a `decision TEXT` holding one of two words. Every value in `op` names something that happened, denials never reach this table by the split above, and imposing or lifting a ban are both changes that occurred, so the column read `true` on every row forever. A column written and never read is noise, and worse, its presence implied refusals were recorded here, which is the exact misreading the split exists to prevent.

**`reason` is deleted too, later the same day**, and an earlier version of this paragraph ended by saying it stayed and carried what varies. It carried nothing. Splitting a login ending into three values means the `op` already names the cause, so a note beside it would only restate the column next to it. The only value that would genuinely vary is which limit a ban crossed, and banning does not exist yet, so the column went back out on the same argument that removed `allowed`: nothing writes it. R36 adds it when it has something to put there.

`table_name` stays text, because a table name in an audit row is read by a person, so the catalog id it corresponds to would be both unreadable and unstable across a catalog change. `pk` is `<RowKeySqlType>`, a placeholder the application fills exactly as it fills `<IdSqlType>` beside it, and in practice a distributed id such as a UUID. Both are nullable, because only a share mint names a row.

**`pk` was `BYTEA` and that was wrong.** It held a MessagePack encoding of the key values, which is what connetto uses internally for routing and for the oplog, where connetto is also the reader. Here the reader is a person or the application's SQL, and a blob is neither readable nor joinable back to the row it names, in a table whose neighbouring column is text for precisely that reason. The key is not opaque either: connetto reads it as typed values. So the values now travel untouched to `ConnettoAuditSchema::row_key`, which the application implements, and the column is whatever type it actually keys on.

**A rejected grant goes to structured logging, not to this table.** It is a denial, and denials are high-volume by the split above, because a caller probing keys generates one per attempt. R3 makes the wire say nothing about a failed grant, so the log line is the only place the failure is visible and is therefore what makes it loud. An earlier version of this chapter listed `grant_rejected` in the column above, which contradicted the split in the same section. The split wins: it was a decision, the column list was a sketch.

**A refused subscription goes the same way. Built (R38, 2026-08-06).** The subscribe path was the outlier against principle 4: a refusal carried the backend's own error text, and subql's `RegisterError` renders `Unknown table`, `Unknown column` and `AggregatorOnRlsTable`, so a socket enumerated the schema and mapped which tables carry RLS. Every refusal now carries the one fixed detail (`SUBSCRIPTION_REFUSED` in `connetto-core`), on the server and through the relay, and no frame precedes it: `SnapshotBegin` and the resync notice both ride behind the successful read, because a frame sequence that varied with the cause disclosed exactly what the fixed text stopped disclosing. The cause is logged at `warn` inside the connection context. Byte identity across causes, fresh and resuming, is asserted by mutation-checked tests in `snapshot_nonfatal.rs`.

**Built (R13, 2026-08-06).** The table is a deployment-facing schema contract, since connetto emits no server DDL on any path an application runs, so it is a schema trait and a convenience macro alongside `ConnettoStoreSchema` and `ConnettoWatermarkSchema`: `ConnettoAuditSchema` and `connetto_audit_table!` in `crates/connetto-server/src/audit.rs`. It spans authentication and authorization events, which is why it got a phase of its own rather than being grown one producer at a time.

**The trait is the whole contract, and nothing checks the table by name.** `audit_insert` builds a real diesel statement against the application's own declaration with its own column types, so the compiler settles whether they agree. An earlier version of this work added a boot-time check that read Postgres's catalogue and refused a table whose columns did not match a hardcoded list. It was deleted: hardcoding connetto's default column names while being generic over the trait would have refused exactly the application-owned table the trait exists to permit. The equivalent check on the watermark table was deleted with it, on the same reasoning and because the shapes it caught fail loudly on the first write anyway.

**Four of the eight kinds have a producer today**: `logged_out` from the logout endpoint, `session_revoked` from the application calling `AuthService::revoke`, `token_replayed` from the theft defence, and `capability_minted` from `CapabilityIssuer`. `permission_change` waits on R7, `model_change` on R5b, and the two ban values on R36.

**Recording is off unless asked for**, with `CONNETTO_AUDIT=database` in the reference binary, because the table belongs to the application and connetto creates nothing.

Audit writing is off the synchronous hot path: the sink is fired synchronously and the supplied Postgres implementation spawns the write, so a slow or failing sink never delays the caller and never fails the logout, revocation or mint that produced it.

---

## Open Questions

The measurement is phase R0 in the plan. R0 comprises a CI-gating counter test asserting that round trips per change event do not grow with subscriber count, a fixed-duration load harness reporting events per second, and later a criterion benchmark. Counters rather than timings answer the scaling question.

R0 also prices two costs nobody has priced: the materializer mutex taken once per subscriber per event inside the fan-out loop (three acquisitions in `SessionManager::dispatch_event` in `crates/connetto-server/src/session.rs`, the third being inside the per-subscriber loop), and the per-subscriber `Route` clone (`SessionManager::dispatch_event` in `crates/connetto-server/src/session.rs`). If either dominates, R5b can succeed at its own job while the throughput does not move, and only a measurement taken before R5b can distinguish those outcomes.

No benchmark infrastructure exists in the workspace: no `benches` directory, no `[[bench]]` target, no criterion.

---

## Decisions

- **Postgres RLS policy text is the source language, and there are two executors.** RLS answers set-shaped questions at snapshot time, permanently and by design. OpenFGA answers point-shaped questions on the change and write paths. `rls2fga` compiles both from one source, which is what makes two executors safe and makes the compilation load-bearing.
- **Every policy translates, or the deployment supplied a mapping, or startup refuses.** No degradation and no tolerated divergence. `rls2fga` closes its coverage gaps upstream and exposes a seam for what it cannot classify. Dropping narrows rather than widens, so what this prevents is rows vanishing, not rows leaking.
- **The visibility trait is defined in `subql`**, which ships an OpenFGA-backed implementation while leaving the trait open to downstream implementations. connetto's `AuthPolicy` is gone (R5a). `RlsAuth` dissolves with the executor swap, RLS does not.
- **Change-time authorization checks both versions of the row**, with the previous-version check conditional on the current version being absent or invisible. The current single check leaks in both directions.
- **The previous version comes from the change log**, so `REPLICA IDENTITY FULL` is a startup-checked deployment requirement.
- **And every table a policy reads must be in the publication**, startup-checked for the same reason: a permission change the stream does not carry is one the change-path executor never hears about, so it would answer from a store that quietly stopped being current.
- **The write question survives** as the attachment point despite being inert today.
- **Capabilities are model relations, not a Postgres setting**, and are backed by Postgres rows like every other permission.
- **A grant change is noticed on the Postgres change log** and answered with a per-subscription resync, never a synthesized deletion. Nothing polls the authorization service and it is never a notice source.
- **Round trips per change event must not grow with subscriber count.** Authorization must not be K network round trips, so the question is asked once per distinct group or role the changed row grants to, cached with invalidation from the notice stream, and each subscriber is then decided locally. Batching alone does not satisfy this, because a cap of 50 turns K round trips into K over 50 and stays linear.
- **Deliveries are K for K subscribers, but K deliveries are not K units of work.** Established by R16 part A, which read the primary sources rather than assuming. Bytes must reach every client and no comparable system escapes that, including the one that pushes the writes onto a CDN. What is not inherent, and what comparable systems do not pay, is K computations, K authorization questions, K frame serializations, or K payload copies. Each has been eliminated by at least one shipping system, and the mechanism is always the same: remove the per-client identifier from the artifact, so that clients asking the same authorized question become indistinguishable to the layer below. The genuine floor is one socket write per client, of bytes that need not be distinct, need not be copied, and need not be computed. See "The per-client floor" below.
- **Nothing asks the authorization model about the past.** A row leaving a client's set is computed from the row's own two versions, and losing access resyncs the subscription. This is the split PowerSync uses. The one engine offering a point-in-time read restricts it to a garbage-collection window and recommends it only for pagination, so it is not an option even where it exists.
- **`rls2fga` must never emit an exclusion that subtracts something derived from the object's own row.** Its only exclusion today subtracts role membership, which is subject-side. The catchup reasoning depends on this and would break silently without it, so it is asserted and tested upstream rather than assumed.
- **The revocation promise**: immediate for writes, within the read cache TTL for reads, immediate for both on teardown.
- **Precomputation is out.** Demand-driven caching with changelog invalidation is the mechanism, and a local negative filter is a contingency with a measured trigger.
- **Audit table is `auth_events`, and it holds state changes, not denials.** A rejected grant is a denial and goes to structured logging, which is the only place it is visible because the wire says nothing about it. **Built (R13, 2026-08-06)**: a schema trait and macro beside the other two, eight event kinds of which four have a producer, and recording off unless `CONNETTO_AUDIT` asks for it.
- **A refusal on the subscribe path discloses nothing, and silence includes frame ordering.** Built (R38, 2026-08-06): one fixed refusal text on the server and the relay, no frame ahead of a refusal (`SnapshotBegin` and `FullResyncRequired` follow the successful read), the cause to the structured log. A side effect worth having on its own: the client no longer discards its rows on a resync notice whose snapshot then fails.
- **The measurement is phase R0, with acceptance assertions rather than a number to be interpreted.** The subscriber-independence requirement is expressed as a CI-gating test rather than a benchmark figure, because a figure nobody compares drifts.

---

## Notes

- The tension this chapter used to describe, between correct-but-slow SQL evaluation and fast-but-must-match in-process compilation, is resolved rather than balanced. Neither side of it is the answer. The answer is one policy source with two executors compiled from it, and the risk moved from "the two might diverge" to "the compiler might not cover the policy", which is a smaller and a checkable risk.
- The per-row RLS check on the change path is the clearest instance in this repository of an interim mechanism being mistaken for the design because it is what the code does. It was a patch from the first day it existed.
