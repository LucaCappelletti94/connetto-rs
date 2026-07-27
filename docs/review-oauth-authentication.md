# Review: authentication implementation (OAuth 2.0 / OIDC, phases 1 to 6)

Scope: the authentication surface across `connetto-core`, `connetto-server` (`src/authn/`), `connetto-client`, and `connetto-web`, checked against the contract in `docs/architecture/11-authentication.md`. This is a findings report, not a set of fixes. Every behavioral claim below was verified against the code. Claims that can only be settled by a runtime run are marked as such.

## Baseline reproduced (green)

Confirmed green before reviewing, so findings are about the code and not a stale tree:

- Root `cargo +stable fmt --all -- --check`: clean.
- Root `cargo +nightly clippy --all-targets --all-features -- -D warnings`: no warnings.
- Root `cargo +stable test --release --all-features`: all tests pass, no failures.
- `crates/connetto-web` `cargo +stable fmt --all -- --check`: clean.
- `crates/connetto-web` `cargo +nightly clippy --target wasm32-unknown-unknown --all-targets -- -D warnings`: no warnings.

Tree state: everything is uncommitted on `main`, matching the handoff.

## What is verifiable versus not (weighting)

- Runtime-proven by the passing suite: the in-memory store path (mint, verify, rotate, reuse-is-theft, revoke, liveness), the full HTTP OAuth flow with PKCE against a permissive provider, native acquisition and silent refresh, handshake auth-fatal routing, and replica identity continuity.
- Compile-only (no headless-Chrome run): the entire `connetto-web` worker path. Login broadcast, OPFS refresh persistence, and the account-switch purge and rebuild are unexercised.
- Not re-run this session (Docker-gated): `connetto-server/tests/authn_db.rs`. The `DbAuthStore` reuse-revoke-outside-the-aborted-transaction fix and `session_expires_at` population are compile-checked only.
- Never run against a live IdP: provider verification is tested with locally minted, locally signed tokens and `PermissiveProvider`.

---

# Confirmed defects

## D1. No `redirect_uri` allowlist on the connetto authorization-server endpoints (security, high)

Files and symbols: `connetto-server/src/authn/http.rs` `login_start` (records `query.redirect_uri` into `PendingLogin.client_redirect` with no check) and `callback` (302-redirects a one-time connetto code carrying the just-minted `access_token` and `refresh_token` to that `redirect_uri`); `connetto-server/src/bin/connetto-server.rs` (the only `redirect` env is `CONNETTO_OIDC_REDIRECT_URL`, which is connetto's own provider callback, not the client redirect).

When a login carries `redirect_uri` and `code_challenge`, `callback` issues an `IssuedAuthCode` holding the tokens minted for the identity that just authenticated at the provider, binds that code to the client-supplied `code_challenge`, and redirects the user agent to the client-supplied `redirect_uri`. Nothing validates that `redirect_uri` is a loopback address (RFC 8252) or a registered value, and nothing ties `code_challenge` to a trusted party. An attacker who initiates a flow with `redirect_uri = https://attacker.example` and an attacker-generated `code_challenge`, then drives a victim through the matching provider authorize URL (a login-CSRF / authorization-code-injection chain), receives a one-time code bound to the victim's freshly minted connetto tokens and redeems it at `POST /auth/token` with the attacker's own verifier. PKCE does not defend this because the attacker chose the challenge, so the redirect allowlist is the only defense and it is absent.

Why it matters: this is the exact custody the BFF model exists to protect. The consequence is account takeover of the victim's connetto session.

Exploitation prerequisites (stated honestly): the attacker needs a login-CSRF chain to make the victim complete the provider round-trip under the attacker's pending `state`, and the auth endpoints must be reachable by the attacker. In the default native deployment the auth server binds `127.0.0.1:8081` (loopback), which limits reach, but the browser BFF deployment must expose these endpoints publicly, where the attack is reachable.

Suggested change: validate `redirect_uri` in `login_start`. For the native loopback client, require `http://127.0.0.1:<port>` or `http://[::1]:<port>` or `http://localhost:<port>` per RFC 8252. For any other deployment, require an explicit per-provider or per-deployment allowlist of exact redirect URIs, and reject anything else with `AuthApiError::InvalidGrant` (or a new `InvalidRedirect`). Reject at login start, not at callback, so a bad URI never mints tokens.

## D2. Transient refresh-endpoint faults are conflated with credential rejection and become a terminal re-login (correctness, medium-high)

Files and symbols: `connetto-client/src/auth.rs` `post_json` (maps every failure to `ClientError::Auth`: a `reqwest` send error, any non-2xx status including 500/502/503, and a body decode error), reached through `refresh_access` and `token_source`; `connetto-client/src/lib.rs` `exchange_handshake` (line 666, `source.token().await?` propagates that `Auth`); `connetto-client/src/live.rs` `recover` (line 1387, `Err(ClientError::Auth(_)) => return Recovery::ReauthRequired`, terminal).

The spec's model is that the client refreshes before the handshake and that this is the invisible common case. `recover` correctly treats a genuine credential rejection as terminal, but because `post_json` labels a network blip or a 5xx from `/auth/refresh` as `ClientError::Auth`, a transient refresh fault during reconnect also returns `Recovery::ReauthRequired`, stops the backoff loop, and emits `ClientEvent::AuthenticationRequired`. A recoverable outage thus surfaces to the user as a forced interactive re-login instead of a retry.

Why it matters: it turns any refresh-service hiccup during a reconnect into a user-facing re-login, defeating the "silently refreshes and resumes" intent and degrading availability during exactly the transient conditions reconnect exists to ride out.

Suggested change: in `post_json`, distinguish outcomes. A `reqwest` send error and a 5xx status are retryable and should map to `ClientError::Transport` (which `recover` already routes to `Err(_) => continue`, keeping the backoff). Only a 401 (and a 400 `invalid_grant` if adopted) means the refresh token is truly gone and should stay `ClientError::Auth` and terminal. A decode failure on a 2xx is a protocol fault (`ClientError::Protocol`). No change to `recover` is required once the mapping is fixed.

Note: the browser side has the same conflation. `connetto-web/src/auth.rs` `post_json` returns `AuthError::Request` for a non-ok status or a fetch failure, and `BrowserAuthenticator::acquire` falls through to `Acquired::NeedLogin` on any refresh error, so a transient 5xx forces an interactive login rather than a retry. This path is compile-only and unverified at runtime.

## D3. `boot_db_worker` binds identity after connecting, contradicting the documented contract and doing a doomed cross-identity resume first (correctness, medium)

Files and symbols: `connetto-web/src/workers.rs` `boot_db_worker` (opens the replica with `connect_existing`, runs a full handshake and catchup under the new access token, then calls `worker.bind_identity` at line 396); `connetto-client/src/lib.rs` `bind_identity` doc ("Call it after learning the authenticated `user_id`, before connecting").

On an account switch, the worker resumes the previous identity's replica over the wire under the new user's token before the local identity check runs. The server streams catchup for the new `user_id` (RLS scoped to the new user) into a replica stamped with the old user, and only then does `bind_identity` return `IdentityMismatch`, at which point the code drops the connection, deletes the replica, and rebuilds. No data persists past the delete, so this is not a leak, but it is a wasted and semantically wrong intermediate resume that the documented ordering was written to avoid.

Why it matters: correctness-of-shape and wasted work on every account switch, and the only real caller violates the contract its own doc states.

Suggested change: read the replica's `_connetto_identity` stamp before opening the server connection. That requires a way to open the replica DB and read the stamp without a transport (a small `ConnettoConnection` seam, or a free helper that opens the file and calls `load_identity`). When the stamp differs from the authenticated `user_id`, purge and create a fresh replica before the first `connect`, so no cross-identity resume happens.

## D4. `PendingLogins` and `AuthCodes` claim oldest-entry eviction but drop an arbitrary entry (correctness, low, also maintainability)

Files and symbols: `connetto-server/src/authn/provider.rs` `PendingLogins::insert` (line 345, `map.keys().next().cloned()`), `AuthCodes::issue` (line 414, same), and their doc comments ("the oldest entries are dropped once the cap is reached").

`HashMap` iteration order is unspecified, so `keys().next()` returns an arbitrary entry, not the oldest. Under a flood of abandoned logins or issued codes at the 4096 cap, a legitimate in-flight authorization or an unredeemed valid code can be evicted while stale ones survive.

Why it matters: the bound is real (the map cannot grow without limit), but the eviction policy the doc promises is not implemented, and the arbitrary drop can knock out a legitimate pending login or code under pressure.

Suggested change: either implement true oldest-first eviction (store an insertion counter or use an insertion-ordered structure) and keep the doc, or change the doc to say an arbitrary entry is dropped. Combine with D5 (a TTL sweep makes the cap rarely bind).

## D5. One-time codes and in-flight authorizations have no expiry (security, low-medium)

Files and symbols: `connetto-server/src/authn/provider.rs` `PendingLogins` and `AuthCodes` (entries are only removed on `take` / `redeem` or by cap eviction, never by time).

A `PendingLogin` and an `IssuedAuthCode` live until consumed or pushed out by the cap. RFC 6749 recommends an authorization code lifetime of at most about 10 minutes, and an in-flight authorization should expire similarly. Here a code minted long ago is still redeemable, widening the window for a leaked or intercepted code.

Suggested change: stamp each entry with an issue instant and refuse (and drop) any older than a short TTL (for example 60 seconds for the pending authorization, up to a few minutes for the code). A periodic or lazy sweep on insert keeps both maps small and makes the D4 eviction path effectively unreachable.

---

# Open questions (confirm or refute needs a runtime run, or is a design call)

## Q1. Browser account-switch purge relies on synchronous OPFS handle release on drop (runtime-only)

Files and symbols: `connetto-web/src/workers.rs` `boot_db_worker` (`drop(worker)` then `storage.delete_db`), `WorkerStorage::delete_db` over `sqlite_wasm_vfs::sahpool`.

Correctness depends on `drop(worker)` synchronously calling `sqlite3_close` and the sahpool VFS synchronously returning the sync access handle to its pool before `delete_db` runs. This is plausible from the sahpool design (SyncAccessHandle operations are synchronous inside a worker and `xClose` releases to the pool), but it cannot be confirmed without a headless-Chrome run. If the handle is not released synchronously, `delete_db` can fail or race. Recommend a headless test that logs in as user A, writes, logs in as user B, and asserts the replica is deleted and rebuilt with no residual A rows.

## Q2. Account switch purges only the synced replica, not the local tier or the refresh store (design)

Files and symbols: `connetto-web/src/workers.rs` `boot_db_worker` (deletes only `config.replica_db_name`; leaves `frontend_db_name` and `auth_db_name`).

Leaving the frontend tier is consistent with the tier-generation contract that treats it as device-local, and the refresh store is a single `id = 1` row overwritten by the new session's token before this point, so no stale token survives. The open question is whether the frontend tier ever holds user-specific data. If it does, it leaks across an account switch. Confirm that the local tier is genuinely identity-agnostic by design, and document that account switch deliberately preserves it. This path is runtime-untested.

## Q3. Identity continuity is a client-side hygiene guard, not a server-enforced invariant (design, confirmed advisory)

Files and symbols: `connetto-client/src/lib.rs` `bind_identity`; `connetto-server/src/authn/service.rs` `ConnettoSessionVerifier` (server resolves identity from the token alone).

Verified: the `user_id` the client binds comes from the auth HTTP response (`TokenResponse.user_id`), which the server sets to the same `user_id` it minted into the access token (`TokenPair.user_id = issued.context.user_id`), so a client that binds the response `user_id` and connects with the paired access token is consistent. The server never checks the replica stamp. Therefore continuity is enforced only if the app calls `bind_identity` with the response `user_id` and acts on `IdentityMismatch`. A buggy app that skips `bind_identity` (or binds a `user_id` not from the token it presents) can mix identities in the local replica, though the RLS boundary still holds server-side because writes are gated by the token's `user_id`, not by the stamp. This matches the spec (RLS is the real boundary; the stamp is local data hygiene), but the guard is opt-in. Suggested: document that `bind_identity` is mandatory client responsibility and that the response `user_id` and the handshake token must be paired.

## Q4. `session_is_live` checks only the absolute deadline, while the client is told the idle deadline (correctness, low)

Files and symbols: `connetto-server/src/authn/store.rs` `InMemoryAuthStore::session_is_live` (line 275, `!revoked && now <= absolute_deadline`) and `DbAuthStore::session_is_live` (line 582, same); both report `session_expires_at` to the client as `min(idle, absolute)` which is the idle deadline.

The two stores agree with each other, so this is consistent, not divergent. But a session past its idle window yet within the absolute ceiling still passes the handshake liveness check, so a still-time-valid access token (up to the 15 minute access TTL) can open a handshake even though `rotate_refresh` would refuse a refresh as `Expired` and the client was told the session already lapsed. The blast radius is bounded by the access-token TTL. Confirm whether the handshake liveness check should also refuse a past-idle session; if so, add the idle-deadline check to both `session_is_live` implementations.

## Q5. DB reuse-revoke and `session_expires_at` population are unverified after the phase-6 change (runtime-only)

Files and symbols: `connetto-server/src/authn/store.rs` `DbAuthStore::rotate_refresh` (the revoke-outside-the-aborted-transaction path at lines 651 to 659) and `create_session` / `rotate_refresh` `session_expires_at`.

The logic reads correctly: the reuse case returns `Err(Reuse)` inside the `for_update` transaction (rolling back cleanly with no write), then a separate committed `UPDATE` sets `revoked = true` after the transaction, which is the documented fix for the rollback-undoes-the-revoke trap. But `authn_db.rs` was not re-run this session (Docker-gated). Recommend running it with approval before relying on the DB path.

---

# Verified sound (checked against the contract, no defect)

These are recorded so the review is not read as silence-implies-clean, per the handoff.

- JWT pinning (`token.rs` `verify_access`): `Validation::new(Algorithm::EdDSA)` pins the algorithm to an asymmetric family, so a `none` token (no `jsonwebtoken` variant, and the header alg would not be in the allowlist) and any symmetric or wrong-asymmetric token are refused. `set_issuer`, `set_audience`, and `set_required_spec_claims(["exp","iss","aud","sub"])` pin issuer, audience, and required claims, and `validate_exp` defaults on. Matches principle 5 (asymmetric only, issuer and audience pinned, `none` rejected). Tests `expired_access_token_is_refused` and `a_token_from_another_key_is_refused` cover the expiry and wrong-key cases.
- Refresh rotation and reuse-is-theft (`store.rs` both variants): every rotation replaces the stored SHA-256, and a presented secret whose hash does not match a live session revokes it. The in-memory path is proven by `refresh_rotates_and_reusing_the_old_token_revokes_the_session`, which also asserts the rotated access token is subsequently refused as `Revoked`.
- PKCE S256 verify and one-time-code redemption (`http.rs` `verify_pkce_s256`, `token`): the code is consumed by `redeem` before the PKCE check, so it is single-use, and a mismatched verifier is rejected. Proven by `loopback_code_exchange_with_pkce` (reuse rejected, wrong verifier rejected).
- openidconnect client build and MS any-tenant matcher (`provider_oidc.rs`): the manual `CoreClient::new` plus `set_auth_uri` / `set_token_uri` / `set_redirect_uri` yields one concrete `ConfiguredClient` typestate. For the Microsoft pattern the verifier runs with `require_issuer_match(false)` but still verifies the signature against the discovered JWKS and the audience, then re-checks the issuer against the prefix/suffix/non-empty-tenant pattern. Signature verification is not weakened. `verify_claims` maps `(iss, sub)` and enforces the assurance bar. (Test gap noted below.)
- `session_expires_at` derivation (scrutiny item 5): all four sites compute `min(idle_deadline, absolute_deadline)`. `unix_secs` clamps to 0 at the epoch, `unix_ms` saturates to `i64::MAX` only on absurd input, and `time_from_ms` clamps a negative to the epoch. No silent `0` or `i64::MAX` on normal input.
- `_connetto_identity` is not synced (scrutiny item 2): every write to it goes through `stamp_identity` under `SuspendedCapture` (via `bind_identity`), the same discipline as `_connetto_meta` and `_connetto_pending`, so it never enters a captured changeset, and the relay enumeration filter `name NOT GLOB '_connetto*'` in `connetto-web/src/relay.rs` excludes it a second time. Two independent layers.
- One wire addition holds (scrutiny item 7): `FatalErrorReason::AuthenticationFailed` is the only sync-wire change, `Handshake.auth_token` is unchanged, and `user_id` / `session_expires_at` are HTTP token-response fields, not sync-wire fields. Aligned with the spec.
- No server-side dead plumbing that should consume these fields (scrutiny item 8): `user_id` and `session_expires_at` are purely client-facing outputs, populated into the HTTP responses and not otherwise consumed server-side. (The `refresh_locks` growth below is a separate minor issue, not dead plumbing.)
- `run_handshake` wiring (`session.rs`): the trust-the-client-id line is gone, replaced by `self.verifier.verify_session(&handshake.auth_token)`, which on failure sends the fatal frame and returns `SessionError::Authentication` before any subscription work. The default `TrustingSessionVerifier` is documented as non-production. Proven by the three `authentication.rs` tests.
- `purge_replica` sidecar handling (scrutiny item 6): builds `""`, `-wal`, `-shm` suffixes and treats `NotFound` as success, so it is idempotent. A partial delete (db removed, then a sidecar delete failing for a non-absence reason) leaves an orphan `-wal`/`-shm`, which SQLite ignores when the db is later recreated from the template, so the inconsistency is benign. For `:memory:` or URI filenames the suffixed names simply do not exist and are skipped. Native transport uses plain file paths, so the URI case does not arise in practice.

---

# Taste and minor (maintainability, style)

- T1. Two `unix_secs` helpers exist, `token.rs` (returns `Result<u64, TokenError>`) and `service.rs` (returns `u64`, epoch-clamped), plus `unix_ms` / `time_from_ms` in the `store` DB module and a `UNIX_EPOCH + Duration` reconstruction in `connetto-client/src/auth.rs` and `connetto-web/src/auth.rs`. Consolidating the epoch-seconds and epoch-millis conversions into one small module would remove the drift risk between the two clamping conventions.
- T2. `AuthService.refresh_locks` (`service.rs`) is a `HashMap<String, Arc<AsyncMutex<()>>>` that gains one entry per session that ever refreshes a provider token and is never pruned. On a long-lived server with many sessions this is an unbounded slow leak. Prune the entry when its `Arc` strong count drops to one, or key the lock by a bounded structure.
- T3. `DbAuthStore` never garbage-collects revoked or absolute-expired `connetto_sessions` (or their `connetto_provider_tokens`), so the tables grow without bound. A periodic delete of sessions past `absolute_deadline_ms` or `revoked = true` is worth adding, and `connetto_provider_tokens` has no foreign key to `connetto_sessions`, so an orphan row is possible.
- T4. Store-variant divergence for a missing session: `InMemoryAuthStore::set_retained_provider_token` silently drops the write when the session is absent (the `get_mut` returns `None`), while `DbAuthStore` inserts an orphan row (no existence check, no FK). Make the two behave the same, preferably both refusing or both requiring an existing session.
- T5. Non-constant-time secret comparisons: `store.rs` compares `hash_secret(secret) != record.current_refresh_hash` and `http.rs` `verify_pkce_s256` compares with `==`. Neither is exploitable to forge (both compare a hash of an attacker-supplied preimage against a stored value, and forging needs the preimage), so this is defense-in-depth only, but a constant-time comparison on the refresh-secret hash is cheap and conventional.
- T6. Account linking is latent, not implemented. The `connetto_identities` linking table exists and `create_session` resolves `(issuer, subject)` through it, but no procedure ever links a second `(issuer, subject)` to an existing `user_id`, so each provider identity always maps to a distinct `user_id`. The spec's "one human may hold several logins" and the account-linking safe procedure are not built. This is a completeness gap against the deployment story, not a defect in what ships. Note it so it is not mistaken for working.
- T7. Doc inaccuracy in `http.rs` module comment: it says the no-`redirect_uri` JSON path is "the programmatic and browser-worker case", but the browser worker (`connetto-web`) does pass `redirect_uri` and `code_challenge` and uses the one-time-code path, not the JSON path. The JSON path serves pure programmatic callers only. Related hardening: `callback` falls through to returning the token pair as JSON whenever `redirect_uri` and `code_challenge` are not both present, so a caller that supplies `redirect_uri` without `code_challenge` gets tokens returned in the browser response, breaking custody. Reject a partial PKCE parameter set (redirect present XOR challenge present) at `login_start`.

---

# Deduplication and simplification (assessment of each candidate)

- `TokenResponse` defined three times (`http.rs` with `Serialize` and five fields including `expires_in`; `connetto-client/src/auth.rs` and `connetto-web/src/auth.rs` with `Deserialize` and four fields, both ignoring `expires_in`). Worth consolidating a shared serde struct (deriving both `Serialize` and `Deserialize`) if it can live where all three crates can reach it. The wasm workspace boundary is the constraint: `connetto-web` would need to depend on wherever the type lands (`connetto-core` is the natural home and is already in the dependency graph). Medium-low value, mainly guards against the field sets drifting.
- `AcquiredSession` (native, `SystemTime`) and `BrowserSession` (wasm, `u64`) are near-identical. The `SystemTime`-versus-`u64` split and the platform boundary make a shared shape marginal; the duplication is small and each is used only within its platform. Leave as is, or unify only if `TokenResponse` is unified (they are the parsed forms of it).
- Time conversion helpers: see T1. Worth consolidating.
- Three refresh stores: native already has a `RefreshTokenStore` trait with `KeyringStore` and `MemoryRefreshStore`, which is the right shape. The browser `RefreshStore` is a concrete OPFS-backed struct with a single implementation, and putting a cross-workspace trait around one wasm implementation buys nothing. The platform split justifies the separation. No change recommended.

---

# Test-quality assessment

Strong, contract-defending tests (not plumbing):

- `authentication.rs`: absent credential rejected with `AuthenticationFailed`, forged credential rejected, and a verified identity ignores a spoofed `client_id` (asserts the resolved `AuthContext` reaches the snapshot, not the client-supplied id). Directly proves the spoofing hole is closed.
- `authn_flow.rs`: login token opens a real handshake then revocation refuses it while the token is still time-valid (revocation is authoritative), refresh rotates and reuse revokes the session, expired access token refused, wrong-key token refused, and the full HTTP OAuth flow plus loopback PKCE code exchange with one-time and mismatch checks. This is the security core and it is well covered on the in-memory path.
- `provider.rs`: verified ID token maps to identity, wrong nonce or audience refused, MFA assurance requires the configured `amr`. These exercise the real `verify_claims` path with a locally signed token.
- `authentication_client.rs`: handshake rejection surfaces as `ClientError::Auth`, identity continuity (unbound then stamp then idempotent rebind then mismatch refused, durable across reopen), and reconnect routes a rejected credential to `AuthenticationRequired` rather than `Closed`.
- `native_auth.rs`: the full native loopback flow end to end with a fake browser, plus silent reacquire, plus the memory store round-trip.
- `teardown.rs` unit tests: warn only when near expiry with unsynced work, and purge blocks on unsynced unless forced (and is idempotent). Both defend the observable contract.

Test gaps:

- G1. The Microsoft any-tenant matcher (`IssuerMatch::matches`, `tenant_of`) and the `verify_claims` pattern branch (`require_issuer_match(false)`) are untested. Only the `Exact` issuer path is exercised. Add a test that a well-formed `https://login.microsoftonline.com/<tenant>/v2.0` issuer matches and extracts the tenant, and that a lookalike (wrong host, missing `/v2.0`, empty tenant) is refused. This is a security-relevant acceptor with no coverage.
- G2. D2's specific failure (a transient refresh fault during reconnect) is untested. `reconnect_routes_rejected_credential_to_relogin` uses a genuine handshake `AuthenticationFailed`, which is correctly terminal, but no test drives a 5xx or a network error from `/auth/refresh` to assert it retries rather than terminating. Adding this test would have caught D2.
- G3. The DB store (`authn_db.rs`) is Docker-gated and was not re-run after phase 6 (Q5).
- G4. The entire `connetto-web` worker path is compile-only (Q1).

---

# Prioritized list

1. D1: add a `redirect_uri` allowlist (loopback for native, explicit allowlist otherwise) on the auth endpoints. Highest security impact, enables account takeover in a public browser deployment.
2. D2: stop conflating transient refresh faults with credential rejection in the client `post_json` (native and browser), so reconnect retries instead of forcing re-login.
3. D5 and D4: give one-time codes and pending authorizations a short TTL, and fix or correct the eviction-order claim.
4. D3: check the replica identity stamp before connecting in `boot_db_worker`, so an account switch does not resume the wrong identity first.
5. Q5 and G3: run `authn_db.rs` with Docker approval to confirm the DB reuse-revoke and `session_expires_at` paths.
6. Q1, Q2, G4: exercise the browser worker under headless Chrome (login broadcast, OPFS refresh persistence, account-switch purge and rebuild).
7. G1: add Microsoft any-tenant matcher tests.
8. Maintainability: T2 (refresh-lock leak), T3 (session GC and provider-token FK), then T1/T4/T5/T6/T7 and the dedup items as cleanup.
