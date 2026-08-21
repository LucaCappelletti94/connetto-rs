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

**Decided, and already recorded at `open-questions.md:262`.** Postgres RLS policy text is the source of truth. [`rls2fga`](https://github.com/LucaCappelletti94/rls2fga) parses it, classifies each `USING` and `WITH CHECK` expression into its canonical patterns (`PatternClass` in `rls2fga` is the only correct statement of how many), and generates an OpenFGA authorization model plus SQL that populates the corresponding relationship records. At runtime, point-shaped visibility questions go to OpenFGA rather than to direct SQL evaluation or to an in-process compilation of the policy, and connetto never evaluates policy text itself.

Two executors, split by the shape of the question and not by convenience:

| Path | Question shape | Volume | Executor | Status |
|---|---|---|---|---|
| Snapshot | set filter | one query, many rows | Postgres RLS, inline in the query | **Built** |
| Change delivery | point check, twice per row per subscriber | rows times subscribers, hot path | OpenFGA | **Built (R5b, 2026-08-12)**, and the two-check form **built (R6, 2026-08-16)** |
| Write | point check, once per operation | one per operation | OpenFGA | **Built (R5b, 2026-08-12)** |

**What is asked and what is not, stated once so no row above is read as more than it is.** The executor exists and is proven against its own two claims: `FgaAuth` in `crates/connetto-server/src/openfga.rs` composes `subql`'s `RowPolicy` over `OpenFgaPolicy` behind one shared index, and unit tests hold that connetto's own policy shape is answered with no round trip while a policy reading another table is not answered locally. **The server binary serves through it as of 2026-08-12**: `build_authorization` translates the deployment's policies, refuses a policy the translator cannot read, checks that every table a policy reads is in the publication, puts the rules on the authorization service, loads the facts behind them when the rules are new, and hands `FgaAuth` to `SessionManager`. What is still missing is the per-row upkeep, so the store is correct as of the boot that loaded it and does not yet follow the change stream.

### Why the snapshot stays on RLS, permanently

Not interim. A snapshot is a set filter, and RLS answers it in one round trip using the planner's own indexes with no result cap. OpenFGA's enumeration direction measurably cannot stand in: `listObjectsMaxResults` defaults to 1000 and `listObjectsDeadline` to 3 seconds, and enumerating everything a subject may see is the expensive direction in this family of systems. A truncated snapshot would be silent data loss rather than an error.

So the split is deliberate: **RLS answers set-shaped questions at snapshot time, and OpenFGA answers point-shaped questions on the change and write paths.**

### Why two executors is safe, and what makes it unsafe

It is safe only because `rls2fga` compiles both from one source. That makes the compilation load-bearing rather than a convenience, and it must be tested as such.

**It is unsafe where the compilation is incomplete.** `rls2fga` grades each policy by confidence, and what it leaves ungraded is what makes two executors dangerous. A dropped permissive clause grants nothing, so the compiled model is **narrower** than the policy it came from. Narrower means a row the policy allows would be returned by the snapshot, which runs real RLS, and then denied on the change path, which runs the compiled model. The client would see the row once and never see it change again. **The specific gap this paragraph used to name is closed, 2026-08-07.** It said attribute conditions were not translated at all, with `status = 'published'` and `priority >= 3` emitted as review items. Upstream now grades a standalone attribute condition B rather than C whenever it carries a row predicate or a request predicate, so what remains at C is the residue the analysis cannot read, and what remains unclassified surfaces through `Translation::unhandled()`. The rule below is therefore about a smaller set than when it was written, and it is unchanged, because a smaller set is not an empty one.

**Built (R5b, 2026-08-12): every policy translates, or the deployment supplied a mapping, or startup refuses.** No degradation path and no tolerated divergence, because a divergence between the two executors is the one thing the single policy source exists to prevent.

**The membership term shares this split (R27, built 2026-08-18).** A subscription narrowing through a membership is one SQL text with the same two executors: its subquery runs inside the snapshot read under row-level security, and `subql`'s compiled term, classified through the same `rls2fga` translator the policies go through, answers the per-row question on the change path, seeded at registration from the membership table read as the caller so the two agree by construction. The term expresses interest and the policy expresses permission, and the two only ever intersect: every row a membership move delivers is read as the caller or asked through the visibility question first, and a membership exit withdraws only the keys the change-path executor now denies, only when the same event moved a grant reaching the subscribed table.

**Built (R5b, 2026-08-12): and a policy reading a table the publication does not carry also refuses startup.** A second refusal on the same path, and it exists because the change-path executor learns about permission changes only from the replication stream. A policy that joins a grants table the deployment did not replicate therefore never hears that a grant was given or taken away, so the store goes stale and then answers confidently and wrongly, which is silent rather than loud. `rls2fga` reports the complete set of tables each policy reads and the publication is known, so this is a set comparison that can name the missing table. Routing such a policy to the supplied-mapping seam instead was rejected: the crate classifies these policies perfectly well, and the seam exists for what it cannot classify.

That rule is only satisfiable because the gaps are closable rather than inherent, and all three tiers have since been built upstream. **OpenFGA is not the limit.** It has first-class conditions, `Condition { name, expression, parameters }` where the expression is a Google CEL string, and `RelationshipCondition` attachable to any tuple, so attribute predicates are expressible in the model. The row-attribute cases were a generalisation of the boolean-flag pattern `rls2fga` already emits, which qualifies rows with a `WHERE` on the tuple query, rather than a new mechanism. The three tiers, all landed: the row-attribute handling generalised, conditions used where the predicate is not row data (emitted as `ConditionSpec` and rendered into the model DSL), and a generic plus trait seam, `TranslatorBuilder::with_registry`, so a downstream user supplies a mapping for anything left unclassified.

**An earlier draft of this chapter had connetto degrade instead**, marking a table not subscribable when its policy graded below confidence B. That treated a gap in one crate's coverage as a permanent property of the authorization service, and built connetto to survive it rather than closing it. Recorded because the error is the instructive part.

The direction of the failure is what makes the rule absolute rather than advisory. Dropping **narrows**: a dropped permissive clause grants nothing and a dropped restrictive clause becomes `no_access`. So a below-threshold model denies what the policy allows, which is fail-safe for security and unsafe for correctness. A client would see a row in its snapshot, taken under real RLS, and then have it withdrawn on the first change because the compiled model calls it invisible. Rows would **vanish** rather than leak, and refusing to start prevents a deployment discovering that by watching data disappear.

### Where the check lives

**Built (R5a, 2026-08-04).** The visibility trait is defined in `subql`, which holds the replication connection and already computes previous-versus-current transitions per subscriber. connetto's `AuthPolicy` (`crates/connetto-core/src/traits.rs`) is superseded by it. **R5a lands the trait and nothing behind it:** `subql` is `no_std`-capable, so an authorization-service client is a network dependency it does not take on for a seam relocation, and the implementation R5a puts behind the trait uses Postgres row-level security and lives here, because binding a caller into a database session is deployment-specific identity policy. \*\*Built (R5b, 2026-08-12):\*\* the OpenFGA-backed implementation (`FgaAuth` in `crates/connetto-server/src/openfga.rs`) arrived with the executor swap, not with the seam. An earlier version of this paragraph attributed it to R5a, which contradicted R5a's own step 3.

**Built (R5a, 2026-08-04).** The seam relocation was a separate phase from the executor swap (R5b). It is blocked on nothing, and the implementation behind the trait initially still uses Postgres RLS, so the phase changes no behaviour. It goes first because the measurement (R0) instruments a seam that must not then relocate, and because relocating first reduces R5b to substituting an implementation rather than restructuring a call path.

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

**Built (R6).** For each candidate subscription, authorization is checked against **both** versions of the row, and the pair decides what is delivered:

| Previous visible | Current visible | Delivered |
|---|---|---|
| no | no | nothing |
| no | yes | insert, the row became visible |
| yes | no | delete, the row became invisible |
| yes | yes | update, or insert plus delete if the row identity changed |

**The second check is conditional, not unconditional.** The previous version only decides between the two rows where the current version is invisible, so the order is: check the current version, deliver and stop if it is visible, and only then check the previous one. A deletion has no current version, so it always falls through to the previous-version check, which is exactly what filters a tombstone. An insertion has no previous version, so an invisible insertion delivers nothing. The cost is therefore one check per subscriber plus one more for each subscriber who cannot see the current version, not two per subscriber.

**The form itself is subql's, and connetto consumes it.** `subql::visibility::transition::transitions` asks the current version first, returns early when every watcher is allowed, and consults the previous version only otherwise, writing one of `Nothing`, `Deliver` or `Withdraw` per watcher. `Withdraw` is the `Default` and the buffer is pre-filled with it, so a call that fails partway leaves every watcher it did not reach withdrawing rather than leaking. `SessionManager::dispatch_event` and `SessionManager::catch_up_row` both route through it as of R6.

**A withdrawal is a plain unmarked delete carrying the key alone**, built like R44's departure notice but without the marking, never the event's own patch (which for an update carries the new row values the caller has just lost). The client already applies a plain delete unconditionally, so nothing on the wire or the client changed. **The caller cannot tell a withdrawal from a deletion, and that is the point**: a frame that said which would disclose that the row still exists for somebody else. A delete's own patch already is exactly that shape, so only an update pays for a second fold.

**Was defective in both directions until R6, and both were demonstrated before either was fixed.** `dispatch_event` checked once and forwarded every tombstone unconditionally. It forwarded the primary key of a deleted row to every subscriber of the table including those who could never see it, disclosing the existence, the identifier and the timing of private rows, which principle 4 forbids in writing. The other direction was worse: an update whose current version is invisible was silently dropped, so a caller who lost access kept the last version it saw, in its local copy, for ever.

**RLS cannot supply the previous-version answer at all**, which is why this was hard-blocked on R5b rather than merely expensive without it. `RlsAuth::may_see` runs `SELECT EXISTS(SELECT 1 FROM tbl WHERE pk = ..)` against the live table (`crates/connetto-server/src/auth.rs`), so for an update it can only answer about the current version, and for a deletion the row is gone and it answers false for everyone. The trait itself does name the version, since R5a: a question is asked about whichever `RowView` the caller hands over, and `EventRow::previous` builds the one bound to the pre-image. What was missing was a backend that could answer about it.

**Built (R6).** The previous version comes from the change log, which requires `REPLICA IDENTITY FULL` on the tables the publication carries. `DEFAULT` records only the primary key columns and records nothing at all when a table has no primary key. `preflight::Artifact::PreviousImages` checks it at startup and names every table to fix. **Scoped to the publication rather than the database**, because connetto keeps its own bookkeeping tables in the same database and replicates none of them, so the database-wide reading subql ships (`REPLICA_IDENTITY_AUDIT_SQL`) refuses a deployment that is configured correctly. That contrast is asserted by a test rather than argued.

**A table altered after startup refuses to serve.** The condition is permanent for that table, so the change path does not hold the event and retry: `SessionError::ChangeStreamUnusable` escapes the reconnect loop, every connection is closed and the process exits, and the restart meets the startup refusal naming the table. Serving on would mean choosing between leaving a row on a device its owner may no longer see and handing its key to somebody who never could.

**The catchup path carries the same obligation and meets it the same way.** Reconnect catchup re-answers per client from connetto's own oplog (`SessionManager::catch_up_row`) rather than from the change stream. The oplog needed nothing added, because it stores the whole change event as JSON, and that the previous image survives the round trip is asserted by a test rather than assumed. That catching up leaves the same rows as staying connected is proven by comparing two replicas over one event sequence.

### The two-check form does not handle a policy change

**Correction to this chapter's earlier text**, which claimed the table above handles a case where an authorization change rather than a data change makes a row appear or disappear. It cannot. With no data change there is no change event on which to run either check. The two forms cover disjoint cases: the table above covers data changes, and the section below covers authorization changes.

---

## When an authorization change arrives

Two tiers, matching `open-questions.md:266-269`.

### A rules change

**Decided.** The policy text itself is altered, `rls2fga` re-translates, and the model is replaced. This is a deploy-time event. Every active session is invalidated and clients re-subscribe from scratch. Rare by nature, and the server is being redeployed around it anyway.

### A grant change

**Built (R7, 2026-08-16).** A row appears or disappears that grants somebody access under unchanged rules. This is the runtime case.

**What notices it is the Postgres change log connetto already reads.** A grant is a Postgres row, so withdrawing one is a row change on the stream connetto is already consuming end to end. `rls2fga` names which tables carry authorization meaning, because reading the policies is the only thing it does. Nothing polls OpenFGA, and OpenFGA is never a notice source: every permission is backed by a Postgres row, and a permission existing only in OpenFGA would make it a second source of truth, which is the divergence `rls2fga` exists to prevent. (OpenFGA could not be watched cheaply in any case. `ReadChanges` is a unary paged call with a default maximum page size of 100 and there is no streaming changelog, so watching it would mean polling.)

**What happens is a per-subscription resync, and never a synthesized deletion.** `StoreUpkeep::keep_current` already sees every authorization-bearing row before it is dispatched, so it reports what moved: the tables whose read answer depends on the moved fact, and who the fact named. `SessionManager::announce_grant_moves` matches that against the live routes, each of which records the table its subscription reads, and drops an instruction on the owning session's own queue. That session's task, which is the only holder of the transport, re-reads the subscription and sends `FullResyncRequired` with the replacement behind it, in that order, so a failed read discards nothing. The client clears the subscription's rows on the notice and applies the replacement rather than merging it (`ConnettoConnection::handle_control` in `crates/connetto-client/src/lib.rs`), and `FullResyncReason::AuthorizationChange` names the cause on the wire so the browser relay tells a tab the truth rather than restating it as a stale cursor. **Only where the affected table differs from the table the change arrived on**: a grant that lives in the guarded row's own column moves with a row event, and R6's two-check form already takes that one row away precisely.

Manufacturing a tombstone per affected row was considered and rejected. The changed grant row names the grantee but not the objects, so finding the affected rows means asking which objects the subject can see, which is the capped enumeration direction. A truncated withdrawal does not announce itself as truncated, so it would leave rows behind while reporting success. Resync avoids the question entirely, because a replacement is complete by construction where a diff is not. This is the reason the teardown was chosen, and it is stronger than the reason previously recorded.

Note that finding the objects is not needed, only the grantee. Removing somebody from a team that could see five hundred documents names that person in the changed row, and resyncing their subscriptions recomputes all five hundred correctly.

A withdrawal reaching one caller and not another is silent in both directions, so both are proved against real replicas rather than frames: `a_withdrawn_grant_takes_the_rows_off_the_device` (`crates/connetto-client/tests/revocation.rs`) withdraws one member's grant and reads the rows back off the real client's replica, while a second member of the same team receives nothing at all and keeps its copy.

**Residual case, half of it built.** The half that needed a mechanism is the object side, and it is not residual at all: `rls2fga` renders an ordinary membership policy as a nested model, so the fact that moves hangs on the membership's own type while the rows that vanish are in the guarded table, and only the generated rules connect them. `GrantReach` (`crates/connetto-server/src/reach.rs`) walks those rules once at startup and inverts them, which is what makes a membership withdrawal reach the members subscribed to the guarded table. The half that remains a paragraph is the subject side, a fact whose subject names a group rather than a person: every subject `rls2fga` renders is a person or the wildcard, so nothing produces one today.

### The promise a deployment can rely on

**Built (R7, 2026-08-16), and measured.** An authorization change takes effect immediately for writes, within the read cache lifetime for reads, and immediately for both when it triggers a teardown.

Writes use the strict consistency preference, because they are low volume and a write accepted against a just-withdrawn capability is the case that must never slip through, which is exactly the moment a leaked key is being revoked. Reads on the change path keep the fast preference and its caches, because that is what makes the fan-out affordable at all, so a caller who has lost access may see at most one further patch within the lifetime.

**The read clause is slack under the shipped settings, and a deployment should know which setting makes it bite.** OpenFGA ships with all three caches disabled, so a read reflects a withdrawal as soon as the store holds it. `a_withdrawn_grant_is_refused_at_once_for_both_questions` (`crates/connetto-server/tests/openfga_live.rs`) takes both questions with no wait between the store write and the question: measured on 2026-08-16, the read refused after 284 microseconds and the write after 295. Enabling `OPENFGA_CHECK_QUERY_CACHE_ENABLED` is what puts a lifetime between the two, `OPENFGA_CHECK_QUERY_CACHE_TTL` (default 10 seconds) is how long it then lasts, and that is the window in which a caller who has lost access may still receive one further patch.

Two constraints, both verified. The preference is chosen per request and not per item inside a batch, so a strict question cannot travel in the same batch as cached ones. And there is no way to express "this read must reflect that specific write", only the coarse two-level preference, which bounds how precise a revocation promise connetto can make.

`FatalErrorReason::SessionRevoked` (`crates/connetto-core/src/messages/error.rs`) is **Built**: it is constructed at `crates/connetto-server/src/bin/connetto-server.rs:597` and in `AuthService::revoke` (`crates/connetto-server/src/authn/service.rs:376-379`), which is R2's wiring landing as the sentence here predicted.

---

## Write authorization

**Built (R5b, 2026-08-12).** `VisibilityPolicy::may_write` now has a real policy behind it. The call path has two callers since R34: the per-op loop in `SessionManager::handle_mutation` calls it once per operation, and `CapabilityIssuer::issue` calls it once per verb a share certifies. `FgaAuth` (`crates/connetto-server/src/openfga.rs`) implements `may_write` by delegating to `RowPolicy`, which answers locally from the row's own values wherever the schema decides, and asks OpenFGA for the rest. `RlsAuth` keeps its unconditional allow and is no longer what the binary constructs.

**The seam is no longer inert.** A test policy that denies still proves the first caller yields `Unauthorized` and the second yields `ShareError::NotWritable`. What changes is that a real policy can now refuse rather than the hook always allowing.

**Built.** Separately from that seam, a mutation applied through `PgWriteTarget` runs inside a transaction that binds `app.user_id` first, so Postgres RLS gates the write itself: a policy's `USING` clause doubles as `WITH CHECK`, an insert or update violating it is a hard error, and an update or delete of an invisible row shows up as a zero-row shortfall. That is a second, independent enforcement point and it is the one carrying weight today.

**`RlsAuth`'s unconditional allow is a false answer, and the mint path is where it costs something. Recorded 2026-08-16, phased as R50.** The reasoning behind the pass is written on the type: a mutation applies under the same row-level-security context, so the database refuses a violation and the seam need not. That holds for the mutation path, where the second enforcement point above catches it, and it fails for `CapabilityIssuer::issue`, which asks the same question once per verb a share certifies with **no database write behind it**. Through `RlsAuth` a caller can therefore mint a write-level share over a row it cannot write, which is R34's seam answering falsely. A shipped deployment is unaffected because the binary constructs `FgaAuth`, which answers properly, but `RlsAuth` is public API and is what the test suite installs. The fix cannot be total: a delete, and the half of an update that asks whether the caller may touch the existing row, are exactly the visibility question `RlsAuth` already runs, while an insert and the `WITH CHECK` half have no row to ask about and would need the policy expression evaluated against the proposed row, which is `rls2fga`'s work rather than this type's.

**Built (R50, 2026-08-18). `RlsAuth` answers the write question now, for the two verbs a share can certify.** Both carry an existing row, which is what makes them answerable: Postgres applies a table's update rule to a locking read, so `SELECT true FROM tbl WHERE pk = .. FOR UPDATE` inside the caller-bound transaction returns the row when the caller may change it and nothing when it may not. The transaction commits at once, releasing the lock, and bounds its wait first, because a mint holds a pooled connection while it waits. An insert and the resulting-row half of an update carry no existing row and keep the documented pass-through, since their only caller applies the write to Postgres immediately afterwards and answering them here would be a second evaluator that can disagree with the database. A verb the type does not recognise refuses.

**The delete verb refuses rather than borrowing the update verb's answer, where a table writes any rule for a single command.** A locking read speaks for the update rule alone, so it answers a delete only when one rule governs every command, which is what connetto's own translation generates. The dangerous case is not only a stricter delete rule: a table carrying an update rule and no delete rule permits no delete at all while the locking read still says yes. So the answerer asks `pg_policies` whether the table writes any command-specific rule and refuses when it does, per question rather than cached, because a cached answer goes stale exactly when a deployment tightens a rule.

**Two consequences a deployment can see.** The pool `RlsAuth` holds must carry `UPDATE` on the tables it certifies writes over, because Postgres refuses a locking read to a role holding only `SELECT`, and every shipped `roles.sql` already grants it since that pool applies client mutations too. And a question that cannot be answered refuses the mint through its own reason, `ShareError::WriteUndecidable`, rather than `NotWritable`, because telling an operator a row is unwritable when the truth is that nothing knew names the wrong cause. Proven against a real policy in `crates/connetto-server/tests/rls_write_question.rs`, which failed first.

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

**A share names the verbs it certifies, and reading is not one of them. Built (R34, 2026-08-09).** Reading is checked for every share, as it always was. Beyond that the caller names which of insert, update and delete the permission row it is about to write will grant, and the mint asks the write question above once per named verb, about the row as it stands, refusing the whole share if any is denied. The application is the only party that knows what its own relation means, which is why it names the verbs rather than connetto inferring them from a two-valued level. `ShareLevel` (`crates/connetto-server/src/capability.rs`) is that set, `ShareError::NotWritable` is the refusal, and `IssuedCapability::level` reports back exactly what was certified.

**Against `RlsAuth` the write half could not refuse, and that is what changed.** The binary now serves through `FgaAuth`, so a write share is certified against a policy that can say no. Against `RlsAuth`, which survives in tests, a write share is certified on the read check alone and the guarantee reads: connetto did not certify more than the policy behind the seam says the caller holds. That was accepted with the maintainer over the alternative of teaching `RlsAuth` to answer, which was tried on paper and rejected: Postgres can be asked whether a caller may update a row without updating it, by reading it under a row lock, but the same probe answers **allow** for a row a separate delete rule forbids deleting, cannot speak to creation at all, and would fire on every operation of every client. `FgaAuth.may_write`, which delegates to `RowPolicy`, does not have this limitation.

**The level does not enter the token, and this is the same rule as everywhere else in this chapter.** A permission inside the token splits authorization between the token's contents and the model. So two shares of different levels are indistinguishable to the server, and what makes the level binding is the deployment's own `WITH CHECK` on its sharing table, exactly as it is for the read half above. `no_minted_token_carries_a_permission` pins the claim set, so a later attempt to smuggle a level into the token fails there.

---

## File authorization

File metadata is authorized as an ordinary row on the files table.

File content authorization uses a short-lived signed token so that fetching a chunk needs no database lookup: the server checks the metadata row once, issues a token naming the file, the content hash, and an expiry, embeds it in the manifest, and validates signature and expiry per chunk. A revoked session can still use an issued token until it expires, and the expiry window is what bounds that.

**Out of scope.** File sync is handled by a separate stack per `open-questions.md:254`, and every design decision here is deferred to it. The token model above is recorded as the intent and not as a commitment.

---

## Cost on the change path

**This was the scalability wall until R5b removed it, 2026-08-12, and it is kept because the measurement below is taken against it.** The row-level-security implementation ran one round trip per watcher, inside its own loop behind one question per event (`SessionManager::dispatch_event` and `SessionManager::catch_up_row` in `crates/connetto-server/src/session.rs`), and each one takes a pooled connection, opens a transaction, runs `set_config`, runs a `SELECT EXISTS`, and commits, awaited one after another.

**The quantity that was most wrong is network round trips, but it was not the only one.** Authorization was K four-statement Postgres transactions, sequential, on the shared ingestion path, the dominant term by three orders of magnitude. Delivery is K in-process channel sends, which is inherent. **What R16 part A established is that the work attached to those K sends is not.** Today each one carries a payload clone, a MessagePack re-serialization of that payload, and a second copy into the outgoing frame, so three full copies of the compressed patch per subscriber per event. Those scale with patch size as well as with K, which the round-trip comparison hides: at K=500 and a one megabyte patch they are three 500 MB passes against the 190 ms attributed to authorization. Both terms are worth fixing, and R16 part B chooses the shape for the second.

**Measured (R0 part B, 2026-08-07). The first throughput figure this project has: 170 events per second at ten subscribers, and 17.0 at a hundred.** The quoted ten per second at a hundred was arithmetic (a hundred subscribers times one optimistically-assumed millisecond) and it was pessimistic by 1.7 times, not wrong in shape. What the measurement adds is the invariant underneath: **deliveries per second are 1,700 at both subscriber counts**, identical across a tenfold change in K, so the ceiling is one number, the rate at which sequential visibility round trips complete, at roughly 590 microseconds each. Per-event throughput is that number divided by K, which is the wall stated as a measurement rather than as an estimate. **The materializer mutex, which the same runs took 12 and 102 times per event, cost zero nanoseconds of waiting in both**, so the per-subscriber lock take is free and is not part of this wall. Per-subscriber copying is likewise negligible here at roughly 39 bytes per subscriber per event, though that figure is a two-column row and scales with patch size as the paragraph above says. Conditions and the full counter table are in the R0 section of `plans/master-implementation-plan.md`. For a published reference point in the same shape, PowerSync's replication path does 2,000 to 4,000 operations per second for small rows, where an operation is one row change written into one set, and their figure does not vary with how many clients are watching, because set membership is computed from the row.

**Remeasured (R14 step zero, 2026-08-16), and the wall above is gone.** With R5b as the shipped executor the same rig reads 399.3 events per second at ten subscribers and 380.5 at a hundred, and deliveries per second scale from 3,993 to 38,050 instead of staying flat, so no single sequential quantity is the ceiling any more. Throughput now sits on a per-event floor of 2.5 ms, and everything paid per subscriber together is 1.38 microseconds at that two-column row and 1.65 microseconds at a 5,451-byte patch, read off the slope between the two subscriber counts. That is 6% of the event budget at a hundred subscribers, which is why R14 was dropped rather than performed. The conditions, the wide-row arm and the five readings that would reopen it are in the R14 section of `plans/master-implementation-plan.md`.

**Built (R5b, 2026-08-12): two tiers, not three.** The criterion is that round trips per event are bounded by the watchers the row does not settle locally, divided by the batch cap, and do not grow with total subscriber count where the schema decides the relation.

`RowPolicy` in `subql` answers the first tier entirely from the row's own values: a direct identity comparison (`Leaf`) finds the named subjects in the row and returns allow or deny for each watcher with no network call, and a held-key comparison (`RequestGated`) compares the watcher's own request values against the row's values and also returns locally. `FgaAuth` (`crates/connetto-server/src/openfga.rs`) composes `RowPolicy` over `OpenFgaPolicy`: every question `RowPolicy` settles locally costs zero round trips, and the rest go to `OpenFgaPolicy`, which packs one question per watcher into `BatchCheck` calls capped at `OpenFgaPolicy::max_checks_per_batch` (default 50, matching OpenFGA's own `MaxChecksPerBatchCheck`).

**A shape bounded by the row rather than by the audience was sought and ruled out.** `ListUsers` issues one call at any audience size but its result limit and its deadline are server-side with no page token, so a truncated answer is indistinguishable from a complete one and reads as a wrong refusal. `Expand` on the row names the usersets granting the relation with a real continuation token, so truncation is detectable, but one paginated `Read` per userset returns only directly stored tuples without evaluating the model, and these models put conditions on membership (generated from RLS policies by `rls2fga`), so it omits members without knowing it. The `ListUsers`-per-userset form evaluates the model correctly but restores the truncation. So `BatchCheck` per watcher is the shape that is correct today, and this paragraph is here so the next reader inherits the finding rather than repeating the search.

**Every policy connetto writes falls entirely in the local half.** A connetto table carries one permissive policy whose `USING` is the caller's identity `OR` the keys the caller holds. `rls2fga` classifies the identity arm as a `Leaf` relation and the held-key arm as `RequestGated`, both answered by `RowPolicy` locally with no round trip. The honest claim is therefore zero round trips at any audience size for connetto's own policy shape. A policy that reads another table is the linear case, bounded by watchers not settled locally divided by 50.

**Precomputing a materialised permission set is not part of this design.** OpenFGA does not offer it, the two systems that do are unavailable to an open-source project (one is internal to its author and the other is a commercial early-access product), and the local tier is already zero-cost for connetto's own policies. If measurement ever shows a problem on a cross-table policy, the smallest correct addition is a local negative filter consulted before calling out, safe in exactly one direction because a probabilistic set has false positives and no false negatives. Recorded as a contingency with a measured trigger.

**R5b was a correctness prerequisite, not a performance option.** `RlsAuth::may_see` runs `SELECT EXISTS` against the live table and can only answer about the row as it is now, while R6 needs an answer about the row as it was. No measurement could veto the swap, only decide whether R5b was sufficient.

### The dependency that blocked R5b has landed

`rls2fga` supplies the per-row mapping (`RecordDescription` with `records_from_row`, landed in full at `main` `d8f5dd7`). The `subql` half that consumes it from the change stream landed too: `RowPolicy` calls `records_from_row` on the current row to derive which subjects the row grants before asking `OpenFgaPolicy` for the rest, and `OpenFgaPolicy` terminates the composition against a server.

**connetto depends on `rls2fga` directly, and that changed with R5b.** An earlier version of this paragraph said the opposite, that the crate was absent from this workspace and would stay that way, reaching the build only through `subql`'s optional `visibility-records` feature. That stopped being true the moment connetto had to build the index itself: `Shapes::new` takes `&[RelationShapes]`, which only a `Translation` produces, and `subql` takes `rls2fga` with default features off and re-exports none of the translator, which is std-only. So connetto names it, on `branch = "main"` with the `client` feature, and `subql` still takes it the `no_std` way, which is why insisting on that constraint upstream was worth it even though this consumer no longer needs it.

**Both startup refusals are built (R5b, 2026-08-12).** A policy the translator cannot read stops the server, on `NoteSeverity::diverges_from_database` rather than on the narrower unhandled report, and a policy reading a table the publication does not carry stops it through `Artifact::PublishedTable`. Both read the same catalog the server already parses.

### The replica enforces policy too, and that is three executors

**Built (R40, 2026-08-15).** The client's local SQLite replica carries the row-level-security policy, translated from the same Postgres policy text by `pg2sqlite`, which turns each policy-bearing table into a backing table, a view carrying the logical name, three `INSTEAD OF` triggers, an audit table, two `AFTER` monitor triggers on the backing table, and a second view named `<physical>_violations`. This is why substantial translation work went into that crate rather than the policies being dropped on the way to the client.

**Be exact about what it defends, because "safety net" invites the wrong expectation.** It is not a boundary against the person holding the device. Triggers in a SQLite file protect nothing from whoever owns the file, and `14-at-rest-encryption.md` already concedes the unlocked machine. What it buys is three other things. A write the server would reject is refused locally before it is queued, so the client fails fast instead of round-tripping into a rejection it must reconcile. A row that reached the replica through a server-side defect does not surface to the application. And the same query returns the same rows locally and remotely, which for a local-first layer is close to a core promise and is otherwise simply untrue.

**The accepted cost is a third executor.** This chapter argues that two executors are safe only because one source compiles both. A third extends that argument rather than breaking it, since `pg2sqlite` compiles from the same policy text, but it widens the surface on which they can disagree, and it does so into a database with no roles and no `current_setting`, which the translation emulates.

**One build-time coupling follows, and it is the good kind.** A policy naming the caller cannot translate until the deployment says what the caller means locally, so `pg2sqlite` refuses with `SessionVariableMappingNotFound`, naming the pattern, and points at `with_session_variable()` and `with_session_user()`. That is a loud build failure rather than a trigger that silently evaluates the caller as nothing and admits every row. **No policy is rejected for being too complex.** The RLS translator raises exactly two errors, `SessionVariableMappingNotFound` and `RlsAuditTableNameRequired`, and the second whenever a policy-bearing table is translated, because translation always emits an audit table and the name must be supplied through `with_rls_audit_table_name`. Checked at both the revision the examples pin, `d0247132`, and upstream `main` at `a6f46dc`. An `UnsupportedPolicyPattern` variant existed at the pin, never constructed by anything, and has since been removed upstream. So the only gate is that every way a policy names the caller has a declared local meaning. The demo satisfies both: `examples/wasm-smoke/build.rs` maps `current_setting('app.user_id')` to `current_app_user` through `with_session_variable` and names `rls_audit` as the audit table, and `examples/wasm-smoke/policies.sql` carries the policy that exercised both.

**The pin moved, and the chain that held it is worth keeping because it explains the shape of the manifests.** The examples pinned pg2sqlite by revision at `d0247132` while `main` carried real row-level-security semantics fixes: permissive policies ORed and restrictive ANDed as PostgreSQL does, `WITH CHECK` defaulting to `USING`, and a policy-bearing view denying every row when no policy applies to `SELECT`. A bump attempted on 2026-08-07 was reverted, because pg2sqlite `main` needed a newer `sql-traits`, that newer `sql-traits` changed accessor signatures, and the change broke the `subql` revision pinned at the time. The adaptation shipped in subql's 2026-08-09 merge, and R5b moved all of it: `sql-traits` to `981b57f`, `sqlparser` to `30d0836`, and pg2sqlite off its revision pin entirely.

**And the cargo hazard this chapter warns about is closed, having fired once for real.** A revision pin here and `branch = "main"` in `subql` are two sources to cargo, so the graph carried **two copies** of pg2sqlite, the stale one still compiling and still failing. Harmless only while neither passes pg2sqlite types to the other. Both manifests now track `branch = "main"`, so there is one copy. The general rule stands and is the reason `rls2fga` is taken by branch rather than by revision.

**Sync must write underneath the policy, and this is forced rather than chosen.** Translating a policy turns the table into a backing table plus a view of the original name plus `INSTEAD OF` triggers, and the server's patches name the plain table because they were built from the Postgres catalog, so applying one is an apply against a view. **This is already characterized**, in `crates/connetto-client/tests/rls_name_mapping.rs`, which is the authority here and is more precise than a first look suggests. The failure is **silent**: `sqlite3changeset_apply` resolves the view through `PRAGMA table_xinfo`, synthesizes an implicit rowid key because a view declares no primary key, passes its shape checks, and then fails every row as a per-row `Constraint` conflict, which the client's `server_wins` policy maps to Omit. Apply reports success and delivers nothing. A hand-built view shape produces a louder `ApplyFailed` instead, which is why the real translator output is the thing to test against.

That settles what would otherwise look like a design choice. Server-authored rows go to the backing table, under the triggers, because the alternative does not merely risk divergence, it loses data without saying so. It is also the right semantics independently: the server is the authority on what this client may hold, so the replica's copy of the policy gets no vote on data the server already decided to send. The net belongs between the application and its data, not between the server and the replica.

**R40 is built, 2026-08-15.** `PolicyTables` in `crates/connetto-client/src/lib.rs` holds the logical-to-physical map and the full set of views the translation emitted. `ClientConfig::with_policy_tables` carries it into the connection. `ClientConfig::with_caller(function, identity)` registers the SQLite function a translated policy calls for the caller's identity before any DDL or insert, marking it deterministic so SQLite hoists it out of the per-row predicate. Opening a replica whose views disagree with the configured map fails with `ClientError::PolicyTablesStale` rather than proceeding silently.

The wiring reaches every boundary where names cross. `ConnettoConnection::to_physical` rewrites the wire's logical name onto the backing table before `apply_patch` applies the payload. `to_logical` rewrites the backing table's name in an outbound capture back to the Postgres name before `send_mutation` uploads it. `take_changed` maps the physical name the SQLite update hook reports back to the logical one, because the update hook never fires for a view, so a write through the `INSTEAD OF` triggers and a server patch applied underneath them both report the backing table, and a live query naming the view would never refresh. `clear_subscription_rows` targets the backing table rather than the view: the `INSTEAD OF` delete trigger only ever sees rows the local policy admits, so clearing through the view strands every hidden row where nothing later removes it, and the predicates name plain columns that the backing table carries unchanged. `still_covered` queries the backing table for the same reason. Five production-path proofs are in `crates/connetto-client/tests/rls_sync_path.rs`.

The full view list is wider than the logical names because a split also emits a `<physical>_violations` view, and reading the actual views from the throwaway validation database keeps connetto ignorant of upstream naming conventions. `pg2sqlite` applies the `current_setting`-to-function mapping only inside policy expressions, not in column defaults, so `orders.owner_id` has no default and every write names it explicitly. The two-argument form `current_setting('app.user_id', true)` matches because the pattern is extracted from the first argument only. SQLite resolves a function name when a statement is prepared, not when a view or trigger is created, so the throwaway validation database applies the DDL with no registered function and accepts it cleanly.

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
4. **Authorization expressed as a partition over subscribers rather than a question per row per subscriber.** This is what R5b builds, corroborated here from four independent directions. It is also the precondition for property 3 to pay anything, because two clients on the same query who may see different rows cannot share an artifact however it is shaped.
5. **Payload carried by shared reference rather than by value.**

**Where connetto stands against that.** Matching is already at the state of the art and needs nothing: `subql` interns predicates by a hash of normalized SQL and refcounts them, evaluates each candidate predicate once, and resolves matched consumers from a bitmap, so two clients issuing the same SELECT already share one evaluation. Content computation is already once per event. Authorization is where Supabase Postgres Changes was, which R5b addressed: for connetto's own policy shape, `RowPolicy` answers every watcher locally and the round-trip count is zero. The remaining gaps are properties 1, 3 and 5, and one finding with no counterpart in any studied system: reconnect catchup rebuilds each missed patch per client per subscription rather than reading a stored one.

**R16 part B chose the shape, and it is `17-fan-out.md`.** The unit of computation is one change event, the socket write is the only work charged per subscriber, and the three remaining gaps above are each answered there: property 1 by a subscription handle derived from the question rather than a name the client chose, property 3 by the `predicate_hash` `subql` already returns and connetto already discards, and property 5 by one shared payload. The catchup finding is answered by the oplog storing the prepared patch. Nothing on the delivery side needs an upstream change. **This chapter's part in it is that R5b settled whether sharing pays**: R5a fixed the shape and R5b made the verdict cheap enough for sharing to matter.

---

## When the authorization service is unreachable

**Built (R5b, 2026-08-12) and proven in five parts: fail closed.** No patch is delivered and no mutation is accepted while the answer is unknown, the client is told delivery is paused and told why, a fresh connection still takes a snapshot, and delivery resumes on the same connection when the service comes back. `crates/connetto-test-harness/tests/outage.rs`. A patch delivered to a caller who may not be allowed to see it cannot be recalled, whereas a stall can be recovered from, and every other decision in this chapter has preferred a loud stall to a quiet leak.

This is a failure mode R5b introduced. The change path previously asked Postgres, which connetto already depends on for everything, so there was no separate service to lose.

**Two things reach the client, both in the tree, and the second is a correctness matter rather than a nicety.**

A caller must be able to tell that delivery is **paused** rather than that nothing is changing. `ControlMessage::DeliveryPaused { cause: PauseCause }` and `ControlMessage::DeliveryResumed` carry this signal (`crates/connetto-core/src/messages/control.rs`). `PauseCause::AuthServiceUnreachable` distinguishes the OpenFGA outage from `PauseCause::ChangeStreamStalled`.

And a refused write must **not** be reported as unauthorized. Rejecting it that way says the caller lacks permission when the truth is that the server cannot tell, and a client that believes itself unauthorized stops retrying and may discard the mutation, turning a transient outage into permanent data loss. `MutationRejectReason::Indeterminate` (`crates/connetto-core/src/messages/mutation.rs`) is the built variant: its doc comment states that a client receiving it MUST retry rather than retire its pending record.

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

**`capability_minted` was added 2026-08-05** for the successful share mint R13 records. It had no value to write itself as: the mint is connetto's own act of issuing a key, whereas `permission_change` belongs to the grant-change watcher (**built in R7**), and collapsing them would have erased the distinction and left one value meaning two things produced by two phases. `table_name` and `pk` name the shared row for a mint, and the grant row that moved for a permission change, which is what those two nullable columns are for.

**`banned` and `ban_lifted` were added on 2026-08-05**, for R36, which bans an identity when a caller repeatedly names something and is told no. A ban is a rare change to who can reach what, which is this table's definition, and it belongs here rather than only in R36's own ban table because that table holds current state with an expiry while this one is the append-only history, so an expired or lifted ban would otherwise leave no trace. **This is not a denial arriving after all**: the refusals that led to the ban still go to the log, one per attempt, and what is recorded here is the single durable decision they produced.

**`allowed` is deleted, decided 2026-08-05.** It was `BOOLEAN NOT NULL`, itself already a correction of a `decision TEXT` holding one of two words. Every value in `op` names something that happened, denials never reach this table by the split above, and imposing or lifting a ban are both changes that occurred, so the column read `true` on every row forever. A column written and never read is noise, and worse, its presence implied refusals were recorded here, which is the exact misreading the split exists to prevent.

**`reason` is deleted too, later the same day**, and an earlier version of this paragraph ended by saying it stayed and carried what varies. It carried nothing. Splitting a login ending into three values means the `op` already names the cause, so a note beside it would only restate the column next to it. The only value that would genuinely vary is which limit a ban crossed, and banning does not exist yet, so the column went back out on the same argument that removed `allowed`: nothing writes it. **This paragraph used to end by saying R36 adds it back, and that is withdrawn. Decided 2026-08-06, the column stays out.** Adding it would change a deployment-facing contract landed two days earlier, obliging every application that implements this table to grow a column, and the argument that removed it did not weaken. The reason a ban was imposed lives on the ban record itself while the ban is in force. **The accepted cost is stated rather than hidden**: once a ban ends its row is gone, so the lasting history says who was banned and when, and not which limit they crossed.

`table_name` stays text, because a table name in an audit row is read by a person, so the catalog id it corresponds to would be both unreadable and unstable across a catalog change. `pk` is `<RowKeySqlType>`, a placeholder the application fills exactly as it fills `<IdSqlType>` beside it, and in practice a distributed id such as a UUID. Both are nullable, because only a share mint names a row.

**`pk` was `BYTEA` and that was wrong.** It held a MessagePack encoding of the key values, which is what connetto uses internally for routing and for the oplog, where connetto is also the reader. Here the reader is a person or the application's SQL, and a blob is neither readable nor joinable back to the row it names, in a table whose neighbouring column is text for precisely that reason. The key is not opaque either: connetto reads it as typed values. So the values now travel untouched to `ConnettoAuditSchema::row_key`, which the application implements, and the column is whatever type it actually keys on.

**A rejected grant goes to structured logging, not to this table.** It is a denial, and denials are high-volume by the split above, because a caller probing keys generates one per attempt. R3 makes the wire say nothing about a failed grant, so the log line is the only place the failure is visible and is therefore what makes it loud. An earlier version of this chapter listed `grant_rejected` in the column above, which contradicted the split in the same section. The split wins: it was a decision, the column list was a sketch.

**A refused subscription goes the same way. Built (R38, 2026-08-06).** The subscribe path was the outlier against principle 4: a refusal carried the backend's own error text, and subql's `RegisterError` renders `Unknown table`, `Unknown column` and `AggregatorOnRlsTable`, so a socket enumerated the schema and mapped which tables carry RLS. Every refusal now carries the one fixed detail (`SUBSCRIPTION_REFUSED` in `connetto-core`), on the server and through the relay, and no frame precedes it: `SnapshotBegin` and the resync notice both ride behind the successful read, because a frame sequence that varied with the cause disclosed exactly what the fixed text stopped disclosing. The cause is logged at `warn` inside the connection context. Byte identity across causes, fresh and resuming, is asserted by mutation-checked tests in `snapshot_nonfatal.rs`.

**Built (R13, 2026-08-06).** The table is a deployment-facing schema contract, since connetto emits no server DDL on any path an application runs, so it is a schema trait and a convenience macro alongside `ConnettoStoreSchema` and `ConnettoWatermarkSchema`: `ConnettoAuditSchema` and `connetto_audit_table!` in `crates/connetto-server/src/audit.rs`. It spans authentication and authorization events, which is why it got a phase of its own rather than being grown one producer at a time.

**The trait is the whole contract, and nothing checks the table by name.** `audit_insert` builds a real diesel statement against the application's own declaration with its own column types, so the compiler settles whether they agree. An earlier version of this work added a boot-time check that read Postgres's catalogue and refused a table whose columns did not match a hardcoded list. It was deleted: hardcoding connetto's default column names while being generic over the trait would have refused exactly the application-owned table the trait exists to permit. The equivalent check on the watermark table was deleted with it, on the same reasoning and because the shapes it caught fail loudly on the first write anyway.

**Seven of the eight kinds have a producer today**: `logged_out` from the logout endpoint, `session_revoked` from the application calling `AuthService::revoke`, `token_replayed` from the theft defence, `capability_minted` from `CapabilityIssuer`, `banned` from the abuse detector and `ban_lifted` from `BanStore::lift` since R36, and, since R7, `permission_change` from the grant-change watcher: one row per connection told to replace a subscription, naming that session, the caller's identity when it has one, and the grant row that moved. A permission change while nobody is connected writes none, because what is recorded is connetto's own act, on the same argument that records a mint rather than the grant landing. `model_change` has a producer to attach to now that the startup path applies a model, and nothing emits it yet.

**The sink for the two ban values sits on `RequestGuard`, not on `SessionManager`. Built (R36, 2026-08-06).** R36 planned a hook on the session manager, because that is where a bad share key, an unresolvable subscription and a rejected write occur. What the phase built instead is one object owning every counter connetto keeps about a caller, injected into both the session manager and the auth service, because the fourth signal (a failed session renewal) fires in the latter and the two share no other state. A ban is detected in that object rather than in either host, so the sink lives there and one hook serves both. The reference binary points it at the same `pg_audit_hook` the auth service uses.

**A ban's own row lives in `connetto_bans`, a fifth schema contract. Built (R36).** Current state with a nullable expiry, one row per banned identity, beside the append-only history here. It carries the session the crossing happened on, because this table's `session` column is `NOT NULL` and a lift performed months later has no run of its own to name.

**Recording is off unless asked for**, with `CONNETTO_AUDIT=database` in the reference binary, because the table belongs to the application and connetto creates nothing.

Audit writing is off the synchronous hot path: the sink is fired synchronously and the supplied Postgres implementation spawns the write, so a slow or failing sink never delays the caller and never fails the logout, revocation or mint that produced it.

---

## Open Questions

The measurement was phase R0 in the plan, and it is **done**. The counter test asserting how round trips per change event vary with subscriber count is in the gate, and the fixed-duration load harness reporting events per second runs on demand (`crates/connetto-test-harness/tests/fanout_load.rs`, which needs `CONNETTO_LOAD_RUN` so a throughput figure is never taken while the rest of the sweep is loading the same database). Counters rather than timings answer the scaling question, with one exception argued in the R0 section: the lock wait, which is a share of a run rather than a throughput claim. A criterion benchmark of `RowPolicy`'s local record computation would confirm the zero-round-trip claim under load, but no criterion infrastructure exists in the workspace (no `benches` directory, no `[[bench]]` target), so the claim rests on the counter evidence and the design.

**R0 priced the two costs nobody had priced, and neither dominates.** The materializer mutex, taken 12 times per event at ten subscribers and 102 at a hundred with the third acquisition inside the per-subscriber loop (`SessionManager::dispatch_event` in `crates/connetto-server/src/session.rs`), waited **zero nanoseconds** in both runs: only the single change-ingest task takes that lock while delivery is running, so an alarming count is an uncontended one. The per-subscriber `Route` clone and payload copy came to roughly 39 bytes per subscriber per event on a two-column row. So R5b is not at risk of succeeding at its own job while throughput fails to move, which is what this paragraph existed to guard against. **R14 was then dropped on 2026-08-16**, once both halves of its trigger had been read against the shipped executor: the lock wait is still zero, and everything paid per subscriber is 6% of the event budget at a hundred subscribers even at a patch a hundred times wider.

No benchmark infrastructure exists in the workspace: no `benches` directory, no `[[bench]]` target, no criterion.

---

## Decisions

- **Postgres RLS policy text is the source language, and there are two executors.** RLS answers set-shaped questions at snapshot time, permanently and by design. OpenFGA answers point-shaped questions on the change and write paths. `rls2fga` compiles both from one source, which is what makes two executors safe and makes the compilation load-bearing.
- **Every policy translates, or the deployment supplied a mapping, or startup refuses.** No degradation and no tolerated divergence. `rls2fga` closes its coverage gaps upstream and exposes a seam for what it cannot classify. Dropping narrows rather than widens, so what this prevents is rows vanishing, not rows leaking.
- **The visibility trait is defined in `subql`**, which ships an OpenFGA-backed implementation while leaving the trait open to downstream implementations. connetto's `AuthPolicy` is gone (R5a). `RlsAuth` dissolves with the executor swap, RLS does not.
- **Change-time authorization checks both versions of the row**, with the previous-version check conditional on the current version being absent or invisible. Built in R6, which closed a leak in both directions: a tombstone reached callers who could never see the row, and a row that left a caller's reach stayed on their device for ever.
- **The previous version comes from the change log**, so `REPLICA IDENTITY FULL` on the tables the publication carries is a startup-checked deployment requirement. A table altered after startup makes the server refuse to serve rather than choose between the two leaks.
- **And every table a policy reads must be in the publication**, startup-checked for the same reason: a permission change the stream does not carry is one the change-path executor never hears about, so it would answer from a store that quietly stopped being current.
- **The write question is no longer inert.** `FgaAuth` provides a real `may_write` through `RowPolicy`. Since R34 the mint asks it too, once per verb a share certifies. The binary serves through `FgaAuth` as of 2026-08-12, so the seam carries a real policy.
- **Capabilities are model relations, not a Postgres setting**, and are backed by Postgres rows like every other permission. A share names the verbs it certifies and reports them back to the application, and that level travels in the reply and never in the token, for the same reason a permission never does.
- **A grant change is noticed on the Postgres change log** and answered with a per-subscription resync, never a synthesized deletion. Nothing polls the authorization service and it is never a notice source.
- **Round trips per change event are bounded by the watchers the row does not settle locally, divided by the batch cap.** `RowPolicy` answers from the row's own values locally with no round trip. `OpenFgaPolicy` batches the rest into calls capped at 50. For connetto's own policy shape both arms are local, so the count is zero at any audience size. A shape that must read another table is linear in watchers-not-settled-locally divided by 50. A group-membership tier between the two was sought and ruled out: `ListUsers` silently truncates, and `Expand` plus paginated `Read` omits members without knowing it because `Read` returns only stored tuples and the models carry conditions on membership. The "cost on the change path" section carries the full finding.
- **Deliveries are K for K subscribers, but K deliveries are not K units of work.** Established by R16 part A, which read the primary sources rather than assuming. Bytes must reach every client and no comparable system escapes that, including the one that pushes the writes onto a CDN. What is not inherent, and what comparable systems do not pay, is K computations, K authorization questions, K frame serializations, or K payload copies. Each has been eliminated by at least one shipping system, and the mechanism is always the same: remove the per-client identifier from the artifact, so that clients asking the same authorized question become indistinguishable to the layer below. The genuine floor is one socket write per client, of bytes that need not be distinct, need not be copied, and need not be computed. See "The per-client floor" below.
- **Nothing asks the authorization model about the past.** A row leaving a client's set is computed from the row's own two versions, and losing access resyncs the subscription. This is the split PowerSync uses. The one engine offering a point-in-time read restricts it to a garbage-collection window and recommends it only for pagination, so it is not an option even where it exists.
- **`rls2fga` must never emit an exclusion that subtracts something derived from the object's own row.** Its only exclusion today subtracts role membership, which is subject-side. The catchup reasoning depends on this and would break silently without it, so it is asserted and tested upstream rather than assumed.
- **A translated attribute condition may only earn a wildcard subject when the value it compares against is a literal.** A standalone column-versus-literal predicate means "visible to everyone while it holds", so the wildcard is correct. A pattern admitting a caller-derived right-hand side under the same emission would hand everyone access to rows scoped to one caller, which is the one way the compilation can widen rather than narrow. Like the exclusion invariant above, it is asserted and tested upstream (`only_a_literal_constant_earns_the_attribute_wildcard`) rather than assumed here. Recorded because it arrived with the 2026-08-07 coverage work and is the only new way a translated policy can leak.
- **The revocation promise**: immediate for writes, within the read cache TTL for reads, immediate for both on teardown.
- **Precomputation is out.** Demand-driven caching with changelog invalidation is the mechanism, and a local negative filter is a contingency with a measured trigger.
- **Audit table is `auth_events`, and it holds state changes, not denials.** A rejected grant is a denial and goes to structured logging, which is the only place it is visible because the wire says nothing about it. **Built (R13, 2026-08-06)**: a schema trait and macro beside the other two, eight event kinds of which six now have a producer, and recording off unless `CONNETTO_AUDIT` asks for it.
- **An identity that keeps naming something and being told no is banned, and connetto asks the application what that costs.** Built (R36, 2026-08-06): four signals, tallied per person over a day and per connection within one socket, with a fifth deployment-facing schema contract (`connetto_bans`) holding current state and a nullable expiry. Reads drive no counter, by principle 4 and because their volume measures the database rather than anyone's behaviour. A banned caller is told nothing, at the handshake or mid-connection. The check reads on the owner pool and fails closed, since on the reader pool an invisible row is zero rows rather than an error and the ban would silently not apply.
- **A refusal on the subscribe path discloses nothing, and silence includes frame ordering.** Built (R38, 2026-08-06): one fixed refusal text on the server and the relay, no frame ahead of a refusal (`SnapshotBegin` and `FullResyncRequired` follow the successful read), the cause to the structured log. A side effect worth having on its own: the client no longer discards its rows on a resync notice whose snapshot then fails.
- **The measurement is phase R0, with acceptance assertions rather than a number to be interpreted.** The subscriber-independence requirement is expressed as a CI-gating test rather than a benchmark figure, because a figure nobody compares drifts.

---

## Notes

- The tension this chapter used to describe, between correct-but-slow SQL evaluation and fast-but-must-match in-process compilation, is resolved rather than balanced. Neither side of it is the answer. The answer is one policy source with two executors compiled from it, and the risk moved from "the two might diverge" to "the compiler might not cover the policy", which is a smaller and a checkable risk.
- The per-row RLS check on the change path is the clearest instance in this repository of an interim mechanism being mistaken for the design because it is what the code does. It was a patch from the first day it existed.
