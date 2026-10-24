# 12: Identity, session, and capability

**Status**: normative. This chapter is the canonical model for the three things it names. Where any other chapter disagrees with it, this one is right and that one is stale.

---

## Status markers

Every normative statement in this chapter and in the chapters it governs carries one of three markers. A chapter may not claim a mechanism exists without naming the phase that builds it.

| Marker | Meaning |
|---|---|
| **Built** | In the tree and exercised by a test. |
| **Built, defective** | In the tree and wrong. The defect is named and the phase that fixes it is cited. |
| **Decided (RN)** | Settled by a decision, not built. `RN` is the phase in `plans/master-implementation-plan.md`, the one normative record of phases (corrected 2026-08-21: this cell used to name a process artifact that is never committed). |

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

**The session token persists independently of the local replica.** For a caller with no identity the replica is in memory (see below), so a token kept inside it would not survive a reload and the session would be lost on every page load. **Corrected (R90, 2026-09-22):** this note drew its precedent from the refresh token's worker-only OPFS persistence, and that precedent is deleted, the browser's refresh credential becoming an `HttpOnly` cookie (`11-authentication.md`, **Decided (R90)**). The resume credential is not a login credential and R90 changes nothing about where it lives.

**A handle covers one unbroken run of one caller, and any change of caller mints a new one.** **Decided (R2).** Signing in ends the unidentified run and starts an identified one, and signing out ends that one, so nothing is ever inherited. Four things key on the handle (the write watermark, the subscription set, each subscription's cursor, and the buffer the server accumulates while the client is away), and a handle that outlived a change of caller would hand all four to the next person to use the device. The apparent cost, discarding subscriptions and cursors at sign-in, is zero: the local copy is changing from in-memory to identity-named at that same moment, so a fresh snapshot happens regardless. The sign-in seam already receives both the outgoing handle and the incoming identity, so it already bridges the discontinuity.

The write frontier needs no protection beyond this, and the mechanism is already built: `HandshakeAck.writer` carries the writer number and its stored frontier (R75), and the client reconciles its own sequence against the answered frontier on reconnect, so a connection whose in-memory copy lost its counter repairs it from the server before it writes. **Built.**

### Identity

**Decided (R3).** Optional. `Principal` carries an identity or does not, alongside whatever capabilities resolved. An identity is the only thing that binds the Postgres setting the read and write paths use, and the only thing that names a durable local replica.

**Built (R8, 2026-08-02).** An identity carries a user id and nothing else. `AuthContext.tenant_id`, `.roles`, and `.claims` are gone. **The trace that follows describes the shape before R8 removed it**, so every symbol in it except the last is deleted and a reader should not go looking for them: they were written and never read, set from the provider response (`GenericOidcProvider::verify_claims`, where `roles` was initialised empty and never filled), copied into the context (`ResolvedIdentity::into_context`), signed into the token (`TokenAuthority::mint_access`), verified back out (`TokenAuthority::verify_access`), stored as a JSON blob on the session row (`SessionAttrs`), read back on rotation (`context_from_attrs`), and re-signed. The only authorization that runs reads `user_id` alone, today through `RlsAuth::visible` in `crates/connetto-server/src/auth.rs`, behind the `may_see` seam R5a introduced. Both plausible futures are already decided against them: `open-questions.md:283` puts tenant isolation in the authorization model, and `rls2fga` requires the same for roles, emitting a `pg_role` type with a `member` relation and stating that the deployment must load records mapping users to Postgres roles. An attribute rule that ever needs a claim takes it as a per-question argument naming the attribute, not as a bag carried for the life of every session.

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

A share key still needs an expiry, as a second bound beside withdrawal, because a bearer token that never expires is a permanent secret. **Built (R4).** `AuthConfig` carries `capability_ttl` beside the four lifetimes it already held, and a `capability_max_ttl` ceiling. A mint asking for longer than the ceiling is refused rather than quietly shortened, which is what keeps an application's own statement of when a link dies from being a lie. **Built (R95, 2026-10-18): the expiry holds on an open connection too.** The grant check reports each key's `exp`, and the session drops the key at that second and resends every subscription it reached.

Custom handshake authorities may accept grants without an expiry. A subject named by several accepted grants remains held while any of those grants is valid.

**Minting is a library call, and the model authorizes the sharing.** **Built (R4).** connetto exposes minting as a function the application calls from its own handler, so the application keeps its own routing, request shape, and rate limits, and connetto gains no sixth endpoint beside the five on `auth_router` in `crates/connetto-server/src/authn/http.rs`. Creating a share key is itself an action needing authorization, because a caller must not be able to share what it cannot read, and that check goes through the same trait that answers every other authorization question rather than being reimplemented per application. The call returns the subject id it minted, and the application writes the row that grants the relation to that subject, so the two agree on the name by construction.

connetto never sees how the application delivers the token afterwards. A URL parameter, a header, a cookie, and a field in a form are all the application's business, and connetto receives only whatever the application extracted and put on the handshake.

**The subject is the deployment's own type, not a string. Built (R4).** `CapabilitySubject<Key = String>` mirrors `AuthContext<Id>`: the key's serde encoding is what the signed token's `sub` claim carries and its `Display` rendering is what a policy compares against, so text lives at those two edges and nowhere in between. The type implements `CapabilityKey` (`crates/connetto-core/src/auth.rs`), where the deployment says which Postgres setting the held keys are bound to and how a held set is packed into that one value. Minting is a separate `MintCapabilityKey` beside the issuer (`crates/connetto-server/src/capability.rs`), because a replica needs the packing to answer the policies it holds and has no business making a bearer secret. That split is what lets the replica call one rendering rather than spelling it a second time: the builder's `with_share_keys` packs through the deployment's own key type, so the value the replica answers and the value the server binds cannot disagree. `String` implements both, minting `key:` plus a version 4 UUID, and is the default.

**How a held key reaches a policy. Built (R4).** A policy can only compare against a value the transaction bound, and a caller may hold several keys, so the set travels as one text value under a second setting beside `app.user_id`, `app.subjects` by default, which a policy unpacks:

```sql
viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
```

The identity is deliberately **not** in that list. It stays bound once, at `app.user_id`, so no existing policy changes and there is no second place the identity could disagree with itself. This follows from the key being typed rather than being a separate choice: a list of the deployment's key type cannot also hold a user id of another type. Connetto refuses to sign a key whose rendering contains the separator, which is the one way a delimited list could grant a neighbouring key's access. A caller holding no key binds the absent marker chapter 08 describes rather than leaving the setting unbound, because an unbound custom setting reads as `''` to the next caller on a pooled connection.

**A commit is attributed to each key, not to the packed set. Decided 2026-09-20.** The packed value exists for the one setting a policy reads, and nothing else may treat it as a name: a row owned by the joined list matches no single subject, so its uploader could not see it. When the content path tells the deployment's `connetto_set_content_state` who committed a file, it calls the setter once per key the caller holds, and a deployment storing that value as the owner ends with one row per key, so the caller sees its own upload under any of them. A deployment setter is therefore called more than once for one commit and must be idempotent, which the `ON CONFLICT DO NOTHING` shape the chapter recommends satisfies.

**A replica answers the same membership arm. Built 2026-09-21.** The setting a policy splits is one delimited value, and pg2sqlite translates the whole membership test into a delimiter-surrounded `instr` search over it, so the canonical spelling above reaches the replica unchanged rather than needing a second spelling there. A deployment declares the setting a held set in its translation (`SessionVariableMapping::holding_set`), has its replica answer it through the subjects function every build registers (`with_share_keys` on the native or browser builder), and hands the keys it holds as the signed grant beside the subject it names. Both halves travel because they answer different ends: the grant is what the handshake presents, so the server reads the key into the caller it binds, and the subject is what the replica compares locally. A holder of neither sees the arm admit nothing, on both ends.

**What connetto does not close, and what does. Built (R4).** Connetto checks the caller may read the resource the mint call names, and the application then writes the permission row on its own connection, which connetto never sees. Nothing in connetto stops that row naming a different resource. What stops it is the deployment's own policy on the sharing table: a `WITH CHECK` requiring the shared row to be visible, evaluated by Postgres as the sharer, refuses a grant over a row the sharer cannot read. That keeps the rule in the one place every other authorization rule lives. Connetto writing the row instead was considered and rejected, because it would make connetto own the shape of the sharing model, and because a connetto-owned generic table could only name a row by the `pk` encoding, which is `MessagePack` over subql's `Value` enum and which no policy can compute.

**A share says which verbs it certifies, and reading is always one of them. Built (R34, 2026-08-09).** The paragraph above is why this is needed: connetto checks and the application writes, so the two must be talking about the same thing. Until now connetto checked reading and the application wrote whatever relation it liked, and a relation granting more than reading had never been checked against anything. Now the mint call carries a `ShareLevel`, a set drawn from insert, update and delete, and connetto asks the write question once per named verb about the row as it stands, refusing the whole share if any is denied. `IssuedCapability::level` reports back exactly what was certified, which is the thing the permission row must not exceed.

**The application names the verbs rather than connetto inferring them from a two-valued level.** A share that permits writing could mean updating, or updating and deleting, and only the application knows what its own relation means. A conservative guess of "updating and deleting together" was rejected because it would bar a sharer on an append-only or soft-delete table from ever minting a write share, and "updating alone" was rejected because a bearer handed the right to delete would get it with nothing having checked the sharer held it.

**The level is in the reply and not in the token**, which is the same rule as "a capability must not carry its own permission" above and needs no separate argument. Two shares of different levels are therefore indistinguishable to the server, and what makes the level binding is the deployment's own `WITH CHECK` on the sharing table, exactly as it is for the read half.

**Against the row-level-security policy that ships today, the write question always allows**, because that question is the attachment point for the executor swap and is inert until then (`08-authorization.md`, "Write authorization"). So the refusal is real code on a real seam with nothing behind it yet, and this chapter says so rather than letting a reader assume a write share is checked more tightly than a read one.

### A content ticket is not a capability

**Decided (2026-08-21, R24's conclusion in the master plan), built by R65 and R66 (2026-09-08).** The file channel serves content bytes over plain HTTP, where an `img` tag can present no grant, so connetto answers the visibility question on the websocket (may this session read the file's metadata row) and a deployment-wired signer from the file crates mints a short-lived URL naming one file, one verb and an expiry. That URL deliberately carries its own permission, which a capability must never do, and the contradiction is resolved by classification rather than exception: the ticket is not a grant, is never presented at a handshake, and never enters a `Principal`. It is a transport ticket carrying an already-made decision to a channel that cannot ask, its revocation lag is exactly its TTL, and that is the same bounded staleness this system already accepts from decision caching. The signer, its key and the verifying endpoint all live in the file crates, so no key material and no token vocabulary enter `connetto-core` beyond the seam trait connetto invokes.

### Bots, lists and installations

**Built (R91).** A bot is a program that holds a query, is told when it changed, and writes values back under rights a person granted it. It is built from the three things above and from nothing new, and the rights are a list the deployment's Postgres holds it to, so the enforcement is a policy the database evaluates rather than a check connetto runs after the fact.

| Entity | What it is |
|---|---|
| Bot | the registered program, one row in `connetto_bots` at this deployment. The id connetto mints, the owner, the name, the Ed25519 public key, and the current list version |
| Registration code | a one-use bearer the owner's app mints and stores as a SHA-256 hash in `connetto_registration_codes`. The bot spends it to register, or to re-register and change its list |
| Installation | one owner at this deployment the bot serves. A row in `connetto_installations` naming the bot, the owner, and the list version that owner's admin accepted |

**A bot is a user.** Its login resolves an identity and the session binds `app.user_id` to the bot, so `Tier::of`, the ban list, the audit row and every policy treat it as any identified caller. What distinguishes it is a third bound value. The list the login resolved is bound as its text to `app.bot_list`, and a connection with no login binds the `*` wildcard, so Postgres itself holds the caller to its list on every read and write.

**The list is a set of table and verb pairs.** Each entry names one of the deployment's synced tables and one of read, insert, update or delete, and the optional entries mark the tables an installation need not take. The list travels typed as a `BotList` and is rendered only where a setting binds it, as the `table:verb` entries joined by the one separator a policy splits on.

**The cap is the generated document, and Postgres enforces it.** For every synced table the build writes four `AS RESTRICTIVE` policies, one per verb, each admitting only when the caller's `app.bot_list` names that table for that verb or carries the wildcard. A restrictive policy intersects the deployment's own permissive policies, so a bot is admitted to a row only when the deployment's policy admits it and the list names the table for the verb. A person carrying the wildcard is admitted exactly as the deployment's policies admit a person, so applying the cap changes nothing a person already saw. The file server runs `connetto_visible_files` under the same cap, so a table the list does not name hides its files from the bot.

**The registry is five synced tables under row-level security.** `connetto_bots`, `connetto_registration_codes`, `connetto_bot_lists`, `connetto_installations` and `connetto_installation_optional_tables` are policy-bearing synced tables in the publication with `REPLICA IDENTITY FULL`. The build appends their DDL to the schema document it translates, so the deployment's Postgres and every replica carry them as synced tables and the cap reaches them like any other synced table. Clients write the registration codes, the installations and the optional tables through the ordinary sync path, and the server alone writes `connetto_bots` and `connetto_bot_lists`, at registration.

**Registration spends one code once.** The owner's app mints a base32 code and stores its SHA-256 hash, never the code. The bot presents the code as the first frame of a fresh connection with a name, its Ed25519 public key, the list it asks for, and a signature over the connection's nonce under that key. The server checks the list, that every table is synced and every verb one of the four, then the signature, then the code, and only then touches the database, so a database outage does not spend the bot's only code. A code that names no bot mints one under its creator at list version 1, and a code that names a bot keeps the id and raises the version only when the list differs as a set. Either way the code is spent, and presenting it again, or a copy of it, is refused. The reply names the bot id and nothing else, and a refusal is one frame that says only that it was refused.

**An installation accepts a version of the list.** The admin's app writes a `connetto_installations` row naming the bot, the owner it serves and the list version it accepted, and `connetto_installation_optional_tables` the optional tables it took. The list that installation's session carries is the accepted version's required entries plus the optional entries whose table the installation accepted, which is what lets one bot serve two owners with two different reach.

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

**Revocation of a share is quieter still, and this is the sentence a reader most needs. Stated 2026-08-06.** A capability is withdrawn by deleting the relation that grants it, and the grant check makes no store call, so a revoked key **is not refused at all**. It resolves, the subject enters the `Principal`, and the rows simply stop matching the policy, so the documents vanish and nothing anywhere says why. That is intended, and since R7 (2026-08-16) the vanishing is active rather than incidental: the change log carries the withdrawn grant row, the server works out which subscriptions its rules reach, and each one is replaced from the server side, so the rows leave the device instead of sitting there until something makes the client re-read. It is also why no wire signal can report revocation: there is no refusal to report. A `HandshakeAck` boolean meaning "some grant failed" was added and removed on 2026-08-06 for exactly this reason, recorded in `02-protocol.md` so the reasoning is not repeated.

This supersedes the half of the earlier decision that had the reply name each failed grant.

**"`HandshakeAck` gains no field" is a rule about the refusal, not a freeze on the message.** R3 added `resume_token` beside `session_token`, and the rule holds because neither says anything about a grant. The two are different things and collapsing them is what made `session_token` confusing in the first place: `session_token` is the run's handle in the clear, an identifier the application has to read because a synced row written before anybody signed in is attributed to it, while `resume_token` is a bearer secret proving that handle is this caller's. Presenting the handle alone buys nothing.

---

## A caller with no identity

**Built (R3, R4).** A caller with no identity reads whatever the deployment's policy shows a caller with no identity, and writes when a capability authorizes it and not otherwise. Authorization for an unidentified caller is a capability question, never an identity question and never a watermark question.

**Its local copy is in memory. Always, with no opt-in. Built (R3).** `Replica::in_memory()` is SQLite's own `:memory:` and carries no key, because there is nothing at rest to key (`crates/connetto-client/src/replica.rs`). The type's own doc comment says a caller with something at rest says `encrypted_file` and a caller with nothing at rest says `in_memory`, and there is no third choice, and phase E5 deleted the durable-plaintext case on that reasoning.

This is the incognito model and it dissolves four problems rather than solving them. There is no name, so there is no naming rule. There is no file, so two callers holding different keys on one shared device cannot read each other's data, which a name-based scheme could not have prevented anyway because the reading happens locally before any connection opens. There is nothing at rest, so there is no key to mint and no purge to sequence. And nothing survives a reload, so there is nothing stale to reconcile.

**A note this chapter used to make, corrected.** It said the desktop demo already had an unidentified mode with an in-memory replica, and cited that as independent confirmation. That mode is gone: R2 removed every unauthenticated path from the demos, and `examples/dioxus-demo/src/main.rs` now always opens an encrypted file under an acquired session. The decision stands on the `Replica` type's own reasoning, which was always the stronger half.

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

**Decided (R2), amended R75.** The exactly-once identity keys on a server-issued writer number and not on the session or the identity. `_connetto_writers` is `PRIMARY KEY (writer)` (`11-authentication.md`), and its `user_id` column is nullable, so an anonymous caller writes under a number with no account at all and a numbered writer can outlive the session that first asked for it. The number needs a stable per-writer identity, which the server mints at handshake and the client presents on reconnect. It does not need to know the session, and it does not have to know who the client is.

Routing, flow-control credits, and subscription bookkeeping key on `connection_num` and need neither an identity nor a session. They are per-connection by nature and stay that way.

**There is exactly one durable handle per run, and it is a `SessionId`. Built (R2, R3).** For an authenticated run the auth store's `SessionId` is the handle (R2). For an unidentified run connetto mints one itself at handshake (R3, the phase that first makes an unidentified caller representable). A visit therefore never carries two names, and `Principal::session_id` is non-optional, which closes what would otherwise make an unidentified caller appear to have no session at all.

**How a minted handle comes back, which nothing recorded before R3.** An authenticated run needs no answer: its handle rides inside the login token it presents, so a client cannot claim somebody else's. An unidentified run has no such token, so connetto hands it a resume credential, a short thing connetto signed under the same key as every grant, and refuses one it did not sign. Four things key on the handle, and the newer connection on a handle evicts the older, so a caller able to invent one could name its own write counter, could create as many counter rows as it liked while unauthenticated, and could take over any visit whose handle it obtained. A signed credential removes all three. Stealing one still works, exactly as stealing a browser cookie does, which is the same exposure an authenticated run already has. A registry of minted handles would give the same unforgeability and was rejected: it costs a lookup on every unidentified handshake, which is the thing the arithmetic rule exists to avoid, and it has to survive a restart, so it becomes another table a deployment creates and connetto checks. **Nothing else is stored for an unidentified run.** Its only durable trace is the write-counter row, written lazily on its first write, because the subscription set, the per-subscription cursor and the buffer accumulated while it is away are all in process, exactly as they are for an authenticated run.

The credential expires, because a bearer token no login backs cannot be endless. The bound is configurable and defaults to a fortnight, which is the life of the case that motivates an unidentified run at all, a shopping cart the visitor comes back to.

**Decided (R2).** One live connection per handle, and the newer connection wins. A handshake presenting a handle that is already live replaces the registry entry, and the old socket is closed with `FatalErrorReason::ConnectionSuperseded`. Two connections must not share a handle, because the handle keys the per-subscription cursor and the pending buffer, and two readers would each consume the other's changes. Last-wins makes a reconnect racing its own half-dead socket self-heal, at the cost that two deliberately concurrent processes on one stored token evict each other.

**Three things exist and each has one job**, which is worth stating because two of them are currently misnamed in the code. `connection_num` is one socket, used for routing and credits, and it dies with the socket. The `SessionId` handle is one unbroken run of one caller, used for resume, the per-subscription cursor, the exactly-once watermark and the revocation registry, and it survives a reconnect. The auth store's session record is the authenticated run's own state, holding whether it is live and its retained provider token.

**Built, defective: the code calls the connection counter a session in two places.** Its field is `next_session: AtomicU64`, and the handshake reply sends `session_token` derived from `connection_num`. Worse than naming, `Materializer::advance_cursor` takes a parameter named `session_id` and is passed `connection_num`, so the cursor that must survive a reconnect is keyed on a value that does not. R2 fixes the keying, and the names follow.

The local replica's name is derived from the identity before any transport opens (`replica_db_name` in `crates/connetto-client/src/replica.rs`). Deriving before connecting is what makes resuming under the wrong identity unrepresentable rather than merely detected. **Built**, and it is the one part of this area that is already right.

### Public tables may be shared across identities

**Decided (R11).** Because the replica is named from the identity, data visible to everybody is stored once per identity on the same device. For a schema with large shared vocabularies that copy can dominate the replica, so one store per device, holding the public tables a deployment declares, is attached to every identity's replica connection.

**Sharing exposes nothing across the boundary encryption draws.** The shared store is demand-driven, so its contents show which public rows some identity on the device fetched. Every account under one OS login can already open every other account's replica, as "What at-rest encryption does not cover" below states, so nothing account B learns from the shared store about account A is new to B. Against an offline holder of the disk the store is encrypted under a device-scoped key, as each replica is under its own. No signal announces a second identity, since it would warn about exposure the keychain already allows.

**Sharing only tables synced in full was rejected as infeasible.** A large public table is paged (R58) and never held whole on a device, so that rule would permit nothing useful.

**Which tables are shareable is declared, and the build validates the declaration.** A shared table is correct only when every identity may read every row of it, because an identity's reads see rows any identity on the device fetched. The deployment lists the tables, and the build refuses one whose visibility depends on the caller, which is a table whose row policy reads the caller's identity or the keys it holds. A table with no deployment policy, or with policies naming neither, is accepted. A per-caller policy cannot be shared even though its translated view filters per connection, because a withdrawal reaches the caller as an unmarked delete (chapter 8), and in one shared copy it would remove a row another identity still reads, with no notice to that identity. Deriving the list from the schema was rejected because it shares tables nobody chose to share.

**Built (R11 slice 2).** The application names the list as the last argument of `connetto_schema::emit`, and `connetto_schema::shared_tables` refuses it while the application compiles. A table counts as caller-dependent when a deployment policy on it calls `current_setting` for anything but the bot list, or reads a table that is caller-dependent, since Postgres applies the read table's own policy inside the subquery. The bundle carries the validated list outside its version, so a server that names no list accepts the client.

**Built (R11 slice 3).** The build compiles the shared layout into the bundle as four programs, one for each combination of a fresh or existing account file and a fresh or existing shared file, each keeping the translator's source order. A placed table's backing table lives in `connetto_shared` and its readers are `TEMP` objects every open recreates, so a query joins public and private tables on one connection. The shared file's key is resolved through the same place and key store as the replica's. Server rows for a shared table are replayed into `connetto_shared` inside the transaction of the `main` apply, under the same server-wins rules, because the session extension applies to `main` only. A relay serves a late tab's snapshot of a shared table from the store. Local writes to a shared table, union coverage and teardown are later slices.

**Changing which tables are shared is a schema change**, and so a semver-breaking release, whether the list or the bool changes. A replica is never reopened under the other layout within one major, so no rows move between layouts. Crossing the boundary is R31's update path.

**Controlled by a plain bool beside the list, defaulting to on, and the application turns it off.** Not a cargo feature, since features multiply the configurations CI must cover, while a bool keeps both paths in one binary where a single test run covers both. Not a const generic either. That would let the shared-store code be eliminated from the wasm bundle, but it is viral through a connection type that already carries a typed id, and the code it would drop is an attach plus read routing.

The store's key, its single-connection topology, its coverage and its teardown are decided in the plan's R11 section.

### What at-rest encryption does not cover

A boundary worth stating outright, because "encrypted at rest" is read more broadly than it holds. `14-at-rest-encryption.md` owns the mechanism, this section owns what it does not reach.

**The threat model, which bounds all of this. Decided.** Encryption at rest rests on the operating system's login. Replica keys live in that login's keychain, or in the browser profile's origin storage, so they protect a device's data from whoever lacks the login and do not protect accounts under one login from each other, whether one person or two use them. Separation between **different people** is the operating system's user account boundary, not connetto's. That boundary is real and stronger than anything built here. It is a per-login keychain on macOS, a per-user credential store on Windows, a per-session kernel keyring on Linux, and separate browser profiles with separate origin storage.

So connetto does **not** isolate one account from another under a single OS login, and is not trying to. The per-identity replica and its per-identity key are not an isolation mechanism, and reading them as one is the mistake this paragraph exists to prevent. They exist so that crypto-shredding one account on logout leaves the other readable, which the code states directly in `KeyringKeyStore` (`crates/connetto-client/src/auth.rs`).

**R42 makes this concrete rather than hypothetical. Built (R42).** Several accounts can now be signed in at once, and switching between them needs no interactive login. The accepted consequence, already noted in the plan: a found device can resume any account whose credential is still stored, not only the last one used.

**The consequence, stated plainly so nobody has to derive it.** Under one OS login, whichever account is running can obtain another account's replica key by asking for it by name. Nothing checks that the caller is that account. A deployment whose accounts under one login belong to different people must therefore separate them at the OS or profile level, since connetto does not.

**Requiring user verification for account separation was considered and is not needed.** Gating key release behind a fingerprint or face check would answer "prove you are this account before opening its replica", a question about separating accounts under one login, which connetto leaves to the operating system. Recording it here so the idea is not re-derived.

**The cost claim that used to accompany that decision was wrong, and it is corrected here because it foreclosed a mechanism a different threat needs.** It read that gating "would also not be free, since the `keyring` crate this depends on exposes no access-control API, and the browser has no equivalent for origin storage at all". The first half is true and now verified: `keyring` 3.6.3 has no access-control surface anywhere in its source, and its Apple backends store secrets with a plain password call. **The second half is false.** WebAuthn's `prf` extension derives a key from a platform authenticator and, per the specification, forces user verification whether or not the caller asks for it, so the browser has a stronger equivalent than the native crate does. One layer below `keyring`, `security-framework-sys` already in connetto's tree defines `kSecAccessControlBiometryAny`, `kSecAccessControlBiometryCurrentSet` and `kSecAccessControlDevicePasscode`, so Apple can express it too.

**So user verification is not needed for account separation, and is adopted for a different threat.** `14-at-rest-encryption.md` specifies it as the gate on locally stored secrets against someone holding the device or the browser profile, which is a threat this chapter's model does not cover and which the per-identity key was never intended to address.

The replica file is named `prefix-sha256(canonical(user_id))` truncated to 128 bits (the hashing step inside `replica_db_name` in `crates/connetto-client/src/replica.rs`), unsalted and identical on every device. Anyone with live filesystem access can therefore **confirm** that a suspected account used this device by hashing a guessed id and testing for the file. The file names alone do not permit enumeration. The account list does, and what reaching it costs differs per platform since R90. In the browser the credential is a cookie no file holds, and the plaintext `AccountStore` index names every account this profile has signed into, plaintext by design because an account key is an identifier and not a secret, the standing chapter 14 gives the marker. Reading that list costs the same mere file access as the names do, which is why the index keeps nothing else. Natively `RefreshTokenStore::accounts()` lists the accounts whose refresh tokens live in the OS keychain, reachable by whoever holds the OS account rather than by whoever holds a copied file. Confirmation from a file name is still enough when the account name is already known, and the same name correlates one account across devices.

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

Nothing in this chapter's scope is an open decision, and the one measurement that was pending has been taken.

**The change-path measurement is done (R0, part B on 2026-08-07).** Two of its three artifacts exist: the counter test that gates CI, asserting how round trips per change event vary with subscriber count, and the fixed-duration load harness reporting events per second, which runs on demand rather than in the sweep. The criterion benchmark of the local record computation belongs to R5b, which introduces the computation. Counters rather than timings answer the scaling question, because the quantity is a count and a count can be asserted.

**It also priced the two costs nobody had priced**, both on the same path and both independent of authorization: the materializer mutex, which `dispatch_event` takes three times per event with the third **inside** the per-subscriber loop, and the per-subscriber `Route` clone in the fan-out. **Neither dominates.** The mutex is taken 12 times per event at ten subscribers and 102 at a hundred and waited zero nanoseconds in both, because only the single change-ingest task takes it while delivery runs. The clone and the payload copy came to roughly 39 bytes per subscriber per event. So R5b cannot succeed at its own job while throughput stays put for either of these reasons, which is the outcome this paragraph existed to keep distinguishable. See `08-authorization.md`.

### Decided, and recorded here because the reasoning is easy to lose

**The never-syncing attached database stays keyed to the identity. Built (R17, 2026-08-07):** its file is named from the replica's own file name (`tier_db_name` in `crates/connetto-web/src/storage.rs`), which already carries the identity, so the file and the key it opens under have one scope and the application no longer names it. Durable device-private data therefore needs an account, and an unidentified session gets an in-memory one alongside its in-memory replica. Destroying the replica destroys it too, since it shares the key being shredded and would otherwise outlive it. The case that wants otherwise is an application letting somebody write before creating an account. The reason it is not obvious is that a device-scoped file is readable by everyone who uses the machine, which is right for a catalogue and wrong for a draft.

**Nested group revocation follows the join.** A permission row joining one group to another names no person, so the affected callers are one join away in Postgres, and connetto can follow it because it is a Postgres row like any other. A paragraph in `08-authorization.md`, not a mechanism.

### Outside this chapter, and recorded so nobody rediscovers them

Both are in `plans/master-implementation-plan.md` with their evidence (corrected 2026-08-21, this line used to name a process artifact that is never committed).

**Owner-less synced data duplicated per identity is decided**, in "Public tables may be shared across identities" above. In short, one store per device holds the public tables a deployment declares and the build validates, controlled by a bool that defaults to on, and it exposes nothing an account under the same OS login could not already read. The full-table-only rule was considered and rejected as infeasible. This remains a different question from the never-syncing attached database above, which does not sync at all.

**Unsynced writes near session expiry is not an open question and was raised in error.** The mechanism exists and is documented: `expiry_warning` (`crates/connetto-client/src/teardown.rs`) takes the expiry, a lead time and the unsynced sequence numbers, and `session_expires_at` already travels on the auth response and is already parsed by the client (`TokenResponse` and `AcquiredSession` in `crates/connetto-client/src/auth.rs`). Queued writes are not perishable, because they live in the identity-keyed replica. What lapses is the refresh token, so the writes end up behind a login prompt rather than being lost, and the only true loss path is `purge_replica` with `force`, which the unsynced guard inside `purge_replica` in `crates/connetto-client/src/teardown.rs` exists to refuse. The caller is deliberately the embedding application, stated in the doc comment of `expiry_warning` in `crates/connetto-client/src/teardown.rs`.

**The `SharedWorker` requirement in `open-questions.md` Q9.1 was never implementable, and the platforms it excluded are capable.** `createSyncAccessHandle` is `[Exposed=DedicatedWorker]` in the WHATWG File System IDL, so it cannot exist in a `SharedWorker` in any conforming browser, and Chrome does not expose the `Worker` constructor there either, so a nested dedicated worker is not a route. Nothing in the repository constructs a `SharedWorker`. Measured on an Android 15 emulator, WebView 124 has every API connetto uses, including a sync access handle that wrote to a real file. Both Q1.3 and Q9.2 are corrected, and **there is no remaining Android exclusion**: Android is supported both on the web and as a native app, the technical reason having been void and the product reason since withdrawn.
