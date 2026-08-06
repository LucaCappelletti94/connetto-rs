# 12: Identity, session, and capability

**Status**: normative. This chapter is the canonical model for the three things it names. Where any other chapter disagrees with it, this one is right and that one is stale.

---

## Status markers

Every normative statement in this chapter and in the chapters it governs carries one of three markers. A chapter may not claim a mechanism exists without naming the phase that builds it.

| Marker | Meaning |
|---|---|
| **Built** | In the tree and exercised by a test. |
| **Built, defective** | In the tree and wrong. The defect is named and the phase that fixes it is cited. |
| **Decided (RN)** | Settled by a decision, not built. `RN` is the phase in `plans/identity-session-capability-refactor.md`. |

The markers exist because this repository already shipped a design that was documented in its first commit, never built, and looked authoritative for the life of the project. `session_token` is that design. A doc with no status marker is how that happened.

---

**Table cells carry markers too.** A row of a table is a normative statement like any other, and the marker discipline was applied only to prose until it let four cells assert unbuilt behaviour in the present tense, including that an authorization-service outage cannot leak rows when no such service is wired. If a cell claims a mechanism exists or behaves a certain way, it names its status.

**A decision block describes the target state.** Inside a `Decided (RN)` block, present tense means the end state that phase RN produces, not the state today. So "the field is deleted" under a `Decided (R8)` marker reads as the decision, and no rewriting into the future tense is wanted.

**The exception, which is the case that actually misleads.** When a sentence names something a reader can go and find still present, say so in the same sentence. "`PermissiveProvider` goes, and it is present in `provider.rs` until that phase runs" costs a clause and removes the only reading that does real harm.

## Purpose

A session, an identity, and a capability are three separate things. connetto has conflated them since its first commit and the conflation is a security defect, not an untidiness. This chapter separates them, says what each one keys, and says what a caller who has one of them but not the others may do.

---

## The defect this chapter closes

**Built, defective.** `AuthContext<Id>.user_id` is non-optional (`crates/connetto-core/src/auth.rs`) and has been since the bootstrap commit, so connetto has no way to represent "nobody is signed in". Three mechanisms demand an identity: the Postgres setting the read and write paths bind, and the exactly-once mutation watermark keyed on `(user_id, session_id)`. Running with no authentication was therefore made to work by inventing an identity. The stand-in verifier of the day took the string the client put on its own handshake, used it verbatim as the `user_id`, and hashed it into a session id (deleted in R2, so a reader will not find it). So "no authentication" does not mean anonymous. It means every caller is authenticated as whoever they claim to be, and it is the default installed by `SessionManager::with_oplog` (`crates/connetto-server/src/session.rs`).

Nobody made a wrong decision. The mandatory `user_id` predates all authentication work, where the server simply did `AuthContext::new(handshake.client_id)`, which is reasonable for a sync prototype with no authentication. Authentication arrived later as a seam over that assumption rather than a replacement of it. The prototype assumption was never deleted, only renamed and documented as dangerous, and left as the default. A security review looked straight at it and accepted the documentation as the mitigation (`docs/review-oauth-authentication.md:130`). A doc comment is not a guard, and that is the transferable lesson: a dangerous default is not made safe by describing it.

Fixed by **R1** (delete the permissive defaults) and **R2** (give the session layer its own identity so the stand-in is no longer needed).

---

## The three things

| | What it is | Minted by | Survives | Keys |
|---|---|---|---|---|
| **Session** | An opaque durable handle for one client's operational state | Server, at handshake | Reconnects, restarts, leader failover | The exactly-once watermark, subscription cursors, the pending buffer |
| **Identity** | A verified statement of who the caller is | Identity provider, mapped at login | Its refresh window | The Postgres setting the read and write paths bind, and the local replica's name |
| **Capability. Built (R4)** | A connetto-signed token asserting the bearer is a named subject | connetto, on an authenticated request | Its expiry, or until its relation is withdrawn | Nothing. The model decides what its subject may do |

A session always exists. An identity may or may not. A capability may be held zero or many times, with or without an identity. All four arrival cases are real, and the fourth is the one a single-credential shape cannot express: a signed-in user holding a key to somebody else's resource.

### Session

**Decided (R2).** The server mints an opaque handle at handshake. The client persists it and presents it on the next connection. This is the design recorded in the first commit and never built: `session_token` exists on the wire (`crates/connetto-core/src/messages/handshake.rs`), the server never reads the client's value back, and no client stores it. `11-authentication.md:154` already says correctly that this handle does a different job from the authentication credential. R2 makes the code match a doc that has been right and unimplemented for the life of the repo.

Three distinct things are called a session today and none of them is this one.

| Name | Minted | Lifetime | Survives reconnect | Durable |
|---|---|---|---|---|
| `connection_num` | atomic counter at handshake | one connection | no | no |
| `SessionId` | UUIDv4 at login, in the token's `sid` claim | one login | yes | yes, it is the watermark key |
| `session_token` | `format!("token-{connection_num}")` | one connection | no | no |

The auth layer did not take the session concept over. The session layer never had a durable identity, so when authentication needed one it built its own. A gap was filled once, on the wrong side of a boundary.

**The session token persists independently of the local replica.** For a caller with no identity the replica is in memory (see below), so a token kept inside it would not survive a reload and the session would be lost on every page load. The refresh token already gets this treatment, worker-only in OPFS (`11-authentication.md:170`), and the session token needs the same for a different reason.

**A handle covers one unbroken run of one caller, and any change of caller mints a new one.** **Decided (R2).** Signing in ends the unidentified run and starts an identified one, and signing out ends that one, so nothing is ever inherited. Four things key on the handle (the write watermark, the subscription set, each subscription's cursor, and the buffer the server accumulates while the client is away), and a handle that outlived a change of caller would hand all four to the next person to use the device. The apparent cost, discarding subscriptions and cursors at sign-in, is zero: the local copy is changing from in-memory to identity-named at that same moment, so a fresh snapshot happens regardless. The sign-in seam already receives both the outgoing handle and the incoming identity, so it already bridges the discontinuity.

The write watermark needs no protection beyond this, and the mechanism is already built: `HandshakeAck.last_applied_seq` exists, and `ConnettoConnection::reconcile_pending` in `crates/connetto-client/src/lib.rs` raises the client's counter to the server's watermark plus one, so a client whose in-memory copy lost its counter repairs it from the server on reconnect. **Built.**

### Identity

**Decided (R3).** Optional. `Principal` carries an identity or does not, alongside whatever capabilities resolved. An identity is the only thing that binds the Postgres setting the read and write paths use, and the only thing that names a durable local replica.

**Decided (R8).** An identity carries a user id and nothing else. `AuthContext.tenant_id`, `.roles`, and `.claims` are deleted. Traced end to end they are written and never read: set from the provider response (`GenericOidcProvider::verify_claims` in `crates/connetto-server/src/authn/provider_oidc.rs`, where `roles` is initialised empty and never filled), copied into the context (`ResolvedIdentity::into_context` in `crates/connetto-server/src/authn/store.rs`), signed into the token (`TokenAuthority::mint_access` in `crates/connetto-server/src/authn/token.rs`), verified back out (`TokenAuthority::verify_access` in `crates/connetto-server/src/authn/token.rs`), stored as a JSON blob on the session row (`SessionAttrs` in `crates/connetto-server/src/authn/store.rs`), read back on rotation (`context_from_attrs` in `crates/connetto-server/src/authn/store.rs`), and re-signed. The only authorization that runs reads `user_id` alone (`RlsAuth::can_read` in `crates/connetto-server/src/auth.rs`). Both plausible futures are already decided against them: `open-questions.md:283` puts tenant isolation in the authorization model, and `rls2fga` requires the same for roles, emitting a `pg_role` type with a `member` relation and stating that the deployment must load records mapping users to Postgres roles. An attribute rule that ever needs a claim takes it as a per-question argument naming the attribute, not as a bag carried for the life of every session.

### Capability

**Built (R3, R4).** A capability is a token connetto minted and signed, asserting one thing: that the bearer is a named subject, for example `key:abc123`. It says nothing about what that subject may do.

That is the whole design, and it makes a capability and a login token the same mechanism with different kinds of subject:

| Grant | What the signature proves | Who decides what it may do |
|---|---|---|
| Login token | the bearer is `user:alice` | the authorization model |
| Share key | the bearer is `key:abc123` | the authorization model |

**A capability must not carry its own permission.** The reason is the one that rules out a Postgres setting: a permission living inside the token splits authorization between the token's contents and the model, which is the divergence the single policy source exists to prevent. So the permission is a relation on the subject, `document:readme#viewer@key:abc123`, derived from a Postgres row the application owns, exactly like every other permission.

**Three consequences, all of them simplifications.**

Withdrawal is immediate and needs no new machinery. Revoking a share key means deleting the relation, which is a Postgres row change, which is the notice, which is the refresh path `08-authorization.md` already defines. The token stays cryptographically valid and names a subject with no permissions left. Nothing needs a liveness table, unlike a session, because there is nothing to keep alive.

Verification is arithmetic. Every grant on a handshake is a connetto-signed token checked against connetto's own public key, with no database lookup, no probing surface for an unrecognised string, and no routing metadata on the wire. One verifier reads the subject out of the token.

A share key still needs an expiry, as a second bound beside withdrawal, because a bearer token that never expires is a permanent secret. **Built (R4).** `AuthConfig` carries `capability_ttl` beside the four lifetimes it already held, and a `capability_max_ttl` ceiling. A mint asking for longer than the ceiling is refused rather than quietly shortened, which is what keeps an application's own statement of when a link dies from being a lie.

**Minting is a library call, and the model authorizes the sharing.** **Built (R4).** connetto exposes minting as a function the application calls from its own handler, so the application keeps its own routing, request shape, and rate limits, and connetto gains no sixth endpoint beside the five on `auth_router` in `crates/connetto-server/src/authn/http.rs`. Creating a share key is itself an action needing authorization, because a caller must not be able to share what it cannot read, and that check goes through the same trait that answers every other authorization question rather than being reimplemented per application. The call returns the subject id it minted, and the application writes the row that grants the relation to that subject, so the two agree on the name by construction.

connetto never sees how the application delivers the token afterwards. A URL parameter, a header, a cookie, and a field in a form are all the application's business, and connetto receives only whatever the application extracted and put on the handshake.

**The subject is the deployment's own type, not a string. Built (R4).** `CapabilitySubject<Key = String>` mirrors `AuthContext<Id>`: the key's serde encoding is what the signed token's `sub` claim carries and its `Display` rendering is what a policy compares against, so text lives at those two edges and nowhere in between. The type implements `CapabilityKey` (`crates/connetto-server/src/capability.rs`), which is also where the deployment says how a fresh key is minted, which Postgres setting the held keys are bound to, and how a held set is packed into that one value. `String` implements it, minting `key:` plus a version 4 UUID, and is the default.

**How a held key reaches a policy. Built (R4).** A policy can only compare against a value the transaction bound, and a caller may hold several keys, so the set travels as one text value under a second setting beside `app.user_id`, `app.subjects` by default, which a policy unpacks:

```sql
viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
```

The identity is deliberately **not** in that list. It stays bound once, at `app.user_id`, so no existing policy changes and there is no second place the identity could disagree with itself. This follows from the key being typed rather than being a separate choice: a list of the deployment's key type cannot also hold a user id of another type. A caller holding no key leaves the setting unbound, so `current_setting` yields NULL and a comparison against it is NULL rather than true, which is what makes an absent capability fail closed. Connetto refuses to sign a key whose rendering contains the separator, which is the one way a delimited list could grant a neighbouring key's access.

**What connetto does not close, and what does. Built (R4).** Connetto checks the caller may read the resource the mint call names, and the application then writes the permission row on its own connection, which connetto never sees. Nothing in connetto stops that row naming a different resource. What stops it is the deployment's own policy on the sharing table: a `WITH CHECK` requiring the shared row to be visible, evaluated by Postgres as the sharer, refuses a grant over a row the sharer cannot read. That keeps the rule in the one place every other authorization rule lives. Connetto writing the row instead was considered and rejected, because it would make connetto own the shape of the sharing model, and because a connetto-owned generic table could only name a row by the `pk` encoding, which is `MessagePack` over subql's `Value` enum and which no policy can compute.

---

## The grant list

**Built (R3).** The handshake carries zero or more grants, opaque to the client. Each is checked independently and yields a subject, or is refused. `Principal` then holds an optional identity plus whichever accepted subjects were capabilities, and what those subjects may do is answered per question by the authorization model rather than resolved at connect time.

**Naming, because it matters here.** The thing that checks a grant is a generalization of the old `SessionVerifier`, which took one credential and produced a verified session. It takes one grant and produces a `Subject`, one implementation reads either kind, and the server folds what resolved into one `Principal`. It is **not** a resolver: `IdentityResolver` (`crates/connetto-server/src/authn/identity.rs`) already exists and means something else entirely, namely mapping the claims a provider asserted to a typed user id in the deployment's own users table, verifying nothing and never seeing a token. The trait is `HandshakeAuthority` (`crates/connetto-core/src/traits.rs`), which also signs the resume credential below, because both halves are the server's own signature under one key and no deployment would supply one without the other.

**Every grant is checked by arithmetic.** Because a capability is a connetto-signed token like a login token, no grant needs a database lookup to be recognised, nothing sniffs the shape of a string, no ordering of checks is load-bearing, and an unrecognised string costs a signature check and nothing more. The grant list carries no routing metadata and needs none. Which kind of subject a grant names is a claim inside the signed payload, so reading it is reading a checked claim rather than guessing from the outside, and one decode handles both kinds. `11-authentication.md` reconciles this with the liveness check that survives beside it.

Chosen over a fixed pair of optional fields deliberately. Fixing the arity at two means a third kind of grant later forces another wire change, which is the bolt-on pattern this refactor exists to stop.

**Two logins on one handshake leave the caller unidentified.** A run has one identity, and taking whichever grant happened to be checked first would make the order of checks decide the caller, which the arithmetic rule above forbids. Both are dropped and both are logged, so the outcome is the same whichever order they arrived in and it fails closed.

**Supersedes the discarded E6 work.** `Credential::{Anonymous, Token}` assumed a credential either identifies you or does not exist, and could not express something that identifies nobody and authorizes plenty. The vocabulary survives and the shape does not. Note that this chapter used to place that type in `crates/connetto-core/src/messages/handshake.rs`, which was never true after the 62-file E6 tree was reset: no such symbol was in the code when R3 began, so there was nothing to delete.

### Resolution rule

**Decided (R3).** A grant that fails to check does not end the connection. The handshake succeeds on whatever was accepted, and a caller who presented an expired key beside a valid login is signed in and sees less. An expired key beside a valid login is the ordinary case, not an edge case.

**The reply says nothing about the failure.** No reason, and not which grant it was. Not allowed, no longer allowed, and never existed are indistinguishable, on the same reasoning that a service does not distinguish an authorization failure from a missing resource. A caller who could tell a withdrawn key from a guessed one would hold an oracle over other people's keys.

The consequence is stated rather than discovered later: an application cannot tell a user whether to retry or to obtain a new key, only that it is seeing less than it asked for. That reaches further than share keys, and R3 confirmed it: a login token that expired or whose run was revoked is refused the same silent way, so a returning user is quietly unidentified rather than told to sign in again. What tells the client is its own silent refresh failing, which is a client-side signal needing no wire disclosure, and `FatalErrorReason::AuthenticationFailed` is deleted because nothing can send it any more.

**Revocation of a share is quieter still, and this is the sentence a reader most needs. Stated 2026-08-06.** A capability is withdrawn by deleting the relation that grants it, and the grant check makes no store call, so a revoked key **is not refused at all**. It resolves, the subject enters the `Principal`, and the rows simply stop matching the policy, so the documents vanish and nothing anywhere says why. That is intended (R7 tears down the live subscriptions), and it is why no wire signal can report revocation: there is no refusal to report. A `HandshakeAck` boolean meaning "some grant failed" was added and removed on 2026-08-06 for exactly this reason, recorded in `02-protocol.md` so the reasoning is not repeated.

This supersedes the half of the earlier decision that had the reply name each failed grant.

**"`HandshakeAck` gains no field" is a rule about the refusal, not a freeze on the message.** R3 added `resume_token` beside `session_token`, and the rule holds because neither says anything about a grant. The two are different things and collapsing them is what made `session_token` confusing in the first place: `session_token` is the run's handle in the clear, an identifier the application has to read because a synced row written before anybody signed in is attributed to it, while `resume_token` is a bearer secret proving that handle is this caller's. Presenting the handle alone buys nothing.

---

## A caller with no identity

**Built (R3, R4).** A caller with no identity reads whatever the deployment's policy shows a caller with no identity, and writes when a capability authorizes it and not otherwise. Authorization for an unidentified caller is a capability question, never an identity question and never a watermark question.

**Its local copy is in memory. Always, with no opt-in. Built (R3).** `Replica::in_memory()` is SQLite's own `:memory:` and carries no key, because there is nothing at rest to key (`crates/connetto-client/src/replica.rs`). The type's own doc comment says a caller with something at rest says `encrypted_file` and a caller with nothing at rest says `in_memory`, and there is no third choice, and phase E5 deleted the durable-plaintext case on that reasoning.

This is the incognito model and it dissolves four problems rather than solving them. There is no name, so there is no naming rule. There is no file, so two callers holding different keys on one shared device cannot read each other's data, which a name-based scheme could not have prevented anyway because the reading happens locally before any connection opens. There is nothing at rest, so there is no key to mint and no purge to sequence. And nothing survives a reload, so there is nothing stale to reconcile.

**A note this chapter used to make, corrected.** It said the desktop demo already had an unidentified mode with an in-memory replica, and cited that as independent confirmation. That mode is gone: R2 removed every unauthenticated path from the demos, and `examples/dioxus-desktop-demo/src/main.rs` now always opens an encrypted file under an acquired session. The decision stands on the `Replica` type's own reasoning, which was always the stronger half.

**One guard follows, and it is in the type. Built (R3).** A durable device-private database beside an in-memory replica would be unencrypted, because it inherits the replica's key and an in-memory replica has none. That is the durable-plaintext case E5 deleted, arriving through the back door. So the replica and that database are described by one value, and the builders that name a file exist only on the encrypted side, which makes the pairing not a program rather than a rejected one. Two doors needed closing and only one was an attach: the browser worker opens its device-private database as a separate connection and encrypted it only when a key happened to exist, so under an unidentified run it would have written a device-wide file in the clear. Both now read the same value.

**What this costs, stated plainly.** A session with no identity is online-only. It has no offline resume, because it has no durable identity to resume as and its keys may have changed by the time it returns.

**And it scopes a principle rather than contradicting it.** `11-authentication.md:31` says authentication gates sync and never local reads, and that the local copy is readable and writable offline with no valid credential. That holds here within a process lifetime, and what it does not promise is durability across a restart. Durability follows from having an identity, because the copy's name and its key both come from the identity. The principle is about an identified caller whose credential expired, not about a caller who never had one.

### Signing in

**Built (R3).** Moving from an unidentified session to an identified one sends any queued writes first and refuses the switch if it cannot. That is the existing unsynced guard applied at the switch rather than at a deletion, and it is `ConnettoConnection::end_run_for_sign_in` (`crates/connetto-client/src/lib.rs`), which pushes, refuses with the sequence numbers still queued, and otherwise hands back the outgoing handle.

**No adoption primitive is built.** Nothing needs carrying. Synced rows are discarded and re-snapshotted under the new identity. Queued writes are already sent, because an online session has sent them and an offline one cannot sign in, sign-in needing the network. The device-private database was never inside the replica: it is named on the replica and opened beside it, and an unidentified run's is in memory like everything else it holds.

**The switch is not a method that mutates a connection, and that follows from the rest.** Signing in changes the local copy from in memory to identity-named, so the caller opens a fresh connection against the identity's own replica. What connetto hands over is the outgoing handle, which is the key the server attributed that run's rows to.

At sign-in the server re-keys that row from the session to the user. **connetto surfaces both keys at the switch and performs no merge.** Only the application knows which of its tables to re-key, what to do when a row already exists for that user, and what a cart even is. connetto makes the merge expressible and stays out of it.

---

## What each thing keys

**Decided (R2).** The exactly-once mutation watermark keys on the session and not on the identity. `_connetto_mutations` is `PRIMARY KEY (user_id, session_id)` today (`11-authentication.md:114-122`) and becomes keyed on the session handle alone. The watermark needs a stable per-client handle, which is what a session is. It does not need to know who the client is.

Routing, flow-control credits, and subscription bookkeeping key on `connection_num` and need neither an identity nor a session. They are per-connection by nature and stay that way.

**There is exactly one durable handle per run, and it is a `SessionId`. Built (R2, R3).** For an authenticated run the auth store's `SessionId` is the handle (R2). For an unidentified run connetto mints one itself at handshake (R3, the phase that first makes an unidentified caller representable). A visit therefore never carries two names, and `Principal::session_id` is non-optional, which closes what would otherwise make an unidentified caller appear to have no session at all.

**How a minted handle comes back, which nothing recorded before R3.** An authenticated run needs no answer: its handle rides inside the login token it presents, so a client cannot claim somebody else's. An unidentified run has no such token, so connetto hands it a resume credential, a short thing connetto signed under the same key as every grant, and refuses one it did not sign. Four things key on the handle, and the newer connection on a handle evicts the older, so a caller able to invent one could name its own write counter, could create as many counter rows as it liked while unauthenticated, and could take over any visit whose handle it obtained. A signed credential removes all three. Stealing one still works, exactly as stealing a browser cookie does, which is the same exposure an authenticated run already has. A registry of minted handles would give the same unforgeability and was rejected: it costs a lookup on every unidentified handshake, which is the thing the arithmetic rule exists to avoid, and it has to survive a restart, so it becomes another table a deployment creates and connetto checks. **Nothing else is stored for an unidentified run.** Its only durable trace is the write-counter row, written lazily on its first write, because the subscription set, the per-subscription cursor and the buffer accumulated while it is away are all in process, exactly as they are for an authenticated run.

The credential expires, because a bearer token no login backs cannot be endless. The bound is configurable and defaults to a fortnight, which is the life of the case that motivates an unidentified run at all, a shopping cart the visitor comes back to.

**Decided (R2).** One live connection per handle, and the newer connection wins. A handshake presenting a handle that is already live replaces the registry entry, and the old socket is closed with `FatalErrorReason::ConnectionSuperseded`. Two connections must not share a handle, because the handle keys the per-subscription cursor and the pending buffer, and two readers would each consume the other's changes. Last-wins makes a reconnect racing its own half-dead socket self-heal, at the cost that two deliberately concurrent processes on one stored token evict each other.

**Three things exist and each has one job**, which is worth stating because two of them are currently misnamed in the code. `connection_num` is one socket, used for routing and credits, and it dies with the socket. The `SessionId` handle is one unbroken run of one caller, used for resume, the per-subscription cursor, the exactly-once watermark and the revocation registry, and it survives a reconnect. The auth store's session record is the authenticated run's own state, holding whether it is live and its retained provider token.

**Built, defective: the code calls the connection counter a session in two places.** Its field is `next_session: AtomicU64`, and the handshake reply sends `session_token` derived from `connection_num`. Worse than naming, `Materializer::advance_cursor` takes a parameter named `session_id` and is passed `connection_num`, so the cursor that must survive a reconnect is keyed on a value that does not. R2 fixes the keying, and the names follow.

The local replica's name is derived from the identity before any transport opens (`replica_db_name` in `crates/connetto-client/src/replica.rs`). Deriving before connecting is what makes resuming under the wrong identity unrepresentable rather than merely detected. **Built**, and it is the one part of this area that is already right.

### Public tables may be shared across identities, and that leaks access patterns

**Decided (R11).** Because the replica is named from the identity, data visible to everybody is stored once per identity on the same device. For a schema with large shared vocabularies that copy can dominate the replica, so an additional database holding public tables, attached alongside each identity's replica, is worth having.

**It is demand-driven, and that is a deliberate accepted cost.** A shared store populated only by what somebody subscribed to leaks the fact that somebody on this device wanted a given row. The data is public, the interest in it is not, and the harm is concrete: on a shared device, one user can learn what another looked up, which for some subject matter is dangerous rather than merely rude.

The alternative, sharing only tables synced in full, removes the leak because presence of a row would then reveal nothing. It was **rejected as infeasible**: a genuinely large public table cannot be downloaded whole, so that rule would permit nothing useful. Demand-driven sharing with the leak disclosed is therefore the only version that earns its place.

**Which tables are shareable is declared, never derived.** Not from a table lacking a policy, not from a relation being universally visible, not from anything connetto can compute. Every such signal reports that the *data* is public and none reports that *interest* in it is, so letting one stand in for the other is exactly how this hazard would come back. The deployment writes the list, and writing it is where a developer weighs each table's access pattern.

**The leak requires two or more identities on one device.** A single-identity device has nothing to leak, which is the common case and the reason the default below is defensible.

**Controlled by a plain bool on the client configuration, defaulting to on, and the application turns it off.** Not a cargo feature: features multiply the configurations CI must cover, while a bool keeps both paths in one binary where a single test run covers both. Not a const generic either: that would let the shared-store code be eliminated from the wasm bundle, but it is viral through a connection type that already carries a typed id, and the code it would drop is an attach plus read routing.

**Disclosure is a signal, not a doc comment.** A developer who never sets the field never reads its documentation, so a default-on privacy cost cannot be disclosed by documentation alone. Since the leak exists only with a second identity present, connetto emits a one-time signal when it sees a second identity's replica on a device with sharing enabled. That fires exactly when the risk becomes real and is silent otherwise.

### What at-rest encryption does not cover

A boundary worth stating outright, because "encrypted at rest" is read more broadly than it holds. `14-at-rest-encryption.md` owns the mechanism, this section owns what it does not reach.

**The threat model, which bounds all of this. Decided.** Several accounts on one device are understood to belong to **one person**, the way a browser holds several mail accounts for the same human. Separation between **different people** is the operating system's user account boundary, not connetto's. That boundary is real and stronger than anything built here: a per-login keychain on macOS, a per-user credential store on Windows, a per-session kernel keyring on Linux, and separate browser profiles with separate origin storage.

So connetto does **not** isolate one account from another under a single OS login, and is not trying to. The per-identity replica and its per-identity key are not an isolation mechanism, and reading them as one is the mistake this paragraph exists to prevent. They exist so that crypto-shredding one account on logout leaves the other readable, which the code states directly in `KeyringKeyStore` (`crates/connetto-client/src/auth.rs`).

**The consequence, stated plainly so nobody has to derive it.** Under one OS login, whichever account is running can obtain another account's replica key by asking for it by name. Nothing checks that the caller is that account. This is correct under the model above and would be a defect under any model where two people share one OS login, so a deployment serving that case must separate them at the OS or profile level rather than expecting connetto to.

**Requiring user verification for account separation was considered and is not needed.** Gating key release behind a fingerprint or face check would answer "prove you are this account before opening its replica", which is only a question worth asking if two people share one OS login. Under the model above they do not. Recording it here so the idea is not re-derived.

**The cost claim that used to accompany that decision was wrong, and it is corrected here because it foreclosed a mechanism a different threat needs.** It read that gating "would also not be free, since the `keyring` crate this depends on exposes no access-control API, and the browser has no equivalent for origin storage at all". The first half is true and now verified: `keyring` 3.6.3 has no access-control surface anywhere in its source, and its Apple backends store secrets with a plain password call. **The second half is false.** WebAuthn's `prf` extension derives a key from a platform authenticator and, per the specification, forces user verification whether or not the caller asks for it, so the browser has a stronger equivalent than the native crate does. One layer below `keyring`, `security-framework-sys` already in connetto's tree defines `kSecAccessControlBiometryAny`, `kSecAccessControlBiometryCurrentSet` and `kSecAccessControlDevicePasscode`, so Apple can express it too.

**So user verification is not needed for account separation, and is adopted for a different threat.** `14-at-rest-encryption.md` specifies it as the gate on locally stored secrets against someone holding the device or the browser profile, which is a threat this chapter's model does not cover and which the per-identity key was never intended to address.

The replica file is named `prefix-sha256(canonical(user_id))` truncated to 128 bits (the hashing step inside `replica_db_name` in `crates/connetto-client/src/replica.rs`), unsalted and identical on every device. Anyone with live filesystem access can therefore **confirm** that a suspected account used this device by hashing a guessed id and testing for the file. It does not permit enumeration, but confirmation is enough when the account name is already known, and the same name correlates one account across devices.

Determinism here is the feature, not an oversight: it is what lets a resumed session find its own replica and its own cursor, and what makes resuming under the wrong identity unrepresentable. Salting would not help against this attacker, who reads the salt too, and neither does encryption under a device-stored key, which the same attacker also reads. **Hiding which identities used a device requires a secret the user supplies and the device never stores.** Nothing in the current design aims there.

**Note that the two leaks pull in opposite directions.** Per-identity replicas leak *which identities* used the device through their filenames. A shared store leaks *what was accessed* through its contents. So turning sharing off does not buy access-pattern privacy against a local attacker, it only removes one of two disclosures. An application that genuinely needs privacy against someone holding the device needs a user-supplied secret, and that is a different design from either switch position.

---

## Where authorization happens

This chapter stops at the boundary. `08-authorization.md` owns which caller may see which row, and the split it records in short:

- A snapshot is a set-shaped question and Postgres RLS answers it, permanently and by design.
- A change or a write is a point-shaped question and the authorization service answers it.
- Both are compiled from one source by `rls2fga`, which is what makes two executors safe and makes that compilation load-bearing rather than a convenience.

---

## Answers recorded

The seven questions this chapter was written to close.

| Question | Answer |
|---|---|
| The wire shape of the resolution rule | No field on the reply, no reason, and not which grant. The grant list |
| How a revocation is noticed | A Postgres row change on the change log connetto already reads. See `08-authorization.md` |
| How the change path gets the previous row | From the change log, requiring `REPLICA IDENTITY FULL`, refusing to start without it. See `08-authorization.md` |
| Whether `FatalErrorReason::SessionRevoked` is wired | Yes, in R2, which is where the durable session identity it keys on is built |
| `AuthContext.tenant_id`, `.roles`, `.claims` | Deleted |
| What names an unidentified session | Nothing. It has no file |
| Whether adoption is offered natively | It is not built at all. In-memory removed the need for it |

Six further doubts, worked after the seven and settled the same day.

| Doubt | Answer |
|---|---|
| When a session handle ends | It covers one unbroken run of one caller. Any change of caller mints a new one, so nothing is inherited |
| What a share key physically is | A connetto-signed token naming a subject. The model holds the permission. This dissolved the question of how a grant is routed to a checker, because every grant is then checked by arithmetic |
| Whether R1 breaks the demos | No. No demo constructs a server. R1 changes one test file and the demo schemas need a non-owner role |
| Who enforces the schema changes R2 and R8 make | connetto checks the shape at startup and refuses, the same treatment R6 gives `REPLICA IDENTITY`, because an unchecked contract lets a server mis-key its exactly-once records silently |
| How a share key comes into existence | A library call, not a sixth endpoint. The authorization model decides whether the caller may share, through the same trait as every other question |
| `FatalErrorReason::ServerShuttingDown` | Constructed, in R8, walking the registry R2 builds |

One naming correction belongs here because it caused real confusion. The thing that checks a grant is a generalization of the old single-credential verifier, and it is **not** a resolver. `IdentityResolver` already exists and means mapping a provider's asserted claims to a typed user id in the deployment's own users table.

## No open decisions

Nothing in this chapter's scope is an open decision. One measurement is pending, named and sequenced in `plans/master-implementation-plan.md`.

**The change-path measurement awaits phase R0.** It is blocked only on R5a, the seam relocation, and it runs while `rls2fga` gains the mapping R5b needs, so it costs no schedule. Three artifacts: an integration test asserting that round trips per change event do not grow with subscriber count, which gates CI, a fixed-duration load harness reporting events per second, and later a criterion benchmark of the local record computation R5b introduces. Counters rather than timings answer the scaling question, because the quantity is a count and a count can be asserted.

**It also prices two costs nobody has priced**, both on the same path and both independent of authorization: the materializer mutex, which `dispatch_event` takes three times per event with the third **inside** the per-subscriber loop, and the per-subscriber `Route` clone in the fan-out. If either dominates, R5b can succeed at exactly its own job while throughput does not move, and only a measurement taken before R5b can tell those two outcomes apart. See `08-authorization.md`.

### Decided, and recorded here because the reasoning is easy to lose

**The never-syncing attached database stays keyed to the identity. Decided (R17), and the code does not do it yet:** `frontend_db_name` is a device-wide `&'static str` while the key is per identity. So durable device-private data needs an account, and an unidentified session gets an in-memory one alongside its in-memory replica. The case that wants otherwise is an application letting somebody write before creating an account. The reason it is not obvious is that a device-scoped file is readable by everyone who uses the machine, which is right for a catalogue and wrong for a draft.

**Nested group revocation follows the join.** A permission row joining one group to another names no person, so the affected callers are one join away in Postgres, and connetto can follow it because it is a Postgres row like any other. A paragraph in `08-authorization.md`, not a mechanism.

### Outside this chapter, and recorded so nobody rediscovers them

Both are in `plans/identity-session-capability-refactor.md` with their evidence.

**Owner-less synced data duplicated per identity is now decided**, in "Public tables may be shared across identities" above. In short: an attached store holding public tables, demand-driven, controlled by a bool on the client configuration that defaults to on, with the access-pattern leak disclosed by a signal rather than by documentation. The full-table-only rule was considered and rejected as infeasible. Note this remains a different question from the never-syncing attached database above, which does not sync at all.

**Unsynced writes near session expiry is not an open question and was raised in error.** The mechanism exists and is documented: `expiry_warning` (`crates/connetto-client/src/teardown.rs`) takes the expiry, a lead time and the unsynced sequence numbers, and `session_expires_at` already travels on the auth response and is already parsed by the client (`TokenResponse` and `AcquiredSession` in `crates/connetto-client/src/auth.rs`). Queued writes are not perishable, because they live in the identity-keyed replica. What lapses is the refresh token, so the writes end up behind a login prompt rather than being lost, and the only true loss path is `purge_replica` with `force`, which the unsynced guard inside `purge_replica` in `crates/connetto-client/src/teardown.rs` exists to refuse. The caller is deliberately the embedding application, stated in the doc comment of `expiry_warning` in `crates/connetto-client/src/teardown.rs`.

**The `SharedWorker` requirement in `open-questions.md` Q9.1 was never implementable, and the platforms it excluded are capable.** `createSyncAccessHandle` is `[Exposed=DedicatedWorker]` in the WHATWG File System IDL, so it cannot exist in a `SharedWorker` in any conforming browser, and Chrome does not expose the `Worker` constructor there either, so a nested dedicated worker is not a route. Nothing in the repository constructs a `SharedWorker`. Measured on an Android 15 emulator, WebView 124 has every API connetto uses, including a sync access handle that wrote to a real file. Both Q1.3 and Q9.2 are corrected, and **there is no remaining Android exclusion**: Android is supported both on the web and as a native app, the technical reason having been void and the product reason since withdrawn.
