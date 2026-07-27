# Handoff: aggressive, precise, impartial review of the authentication implementation

## Goal in one sentence

Review the authentication code (OAuth 2.0 / OIDC, phases 1 to 6 of `docs/architecture/11-authentication.md`) hard and impartially, and produce a findings report of real problems, risks, and deduplication or simplification opportunities. This session writes a report, not fixes, unless the reader is asked to fix afterward.

## What to deliver

A written review at `docs/review-oauth-authentication.md`. For every finding: the file and symbol, what is wrong or smells wrong, why it matters (severity: correctness, security, maintainability, style), and a concrete suggested change. Separate confirmed defects from open questions from taste. End with a short prioritized list. If a claimed behavior cannot be verified from the code alone, say so rather than guessing.

## Ground rules for the review (read this first)

1. **Do not trust the author's summaries.** The roadmap paragraphs (`docs/roadmap.md`, the Authentication section) and the memory notes describe intent. Verify every claim against the actual code. Where code and prose disagree, the code is the fact and the prose is a finding.
2. **The spec is `docs/architecture/11-authentication.md`.** Read it as the contract. Check the implementation against its principles (asymmetric-only, `iss` and `aud` pinned, `none` rejected, authentication gates sync not local reads, one wire addition only, refresh-token lifetime defines replica lifetime, resume requires the same identity, logout and expiry share one teardown). Any drift is a finding.
3. **Impartial means neutral.** The "things to scrutinize" list below is a set of open questions, not a verdict. Confirm or refute each from the code. Do not assume a listed item is a bug, and do not assume an unlisted area is clean.
4. **Do not redesign authorization.** `docs/architecture/08-authorization.md` (RLS, OpenFGA, rls2fga) is out of scope. The only connecting fact is that the verified identity becomes `AuthContext.user_id`, consumed by RLS via `set_config('app.user_id', ...)`.
5. **Scope is the auth surface across all six phases**, with heaviest attention on phases 5 and 6 (the least runtime-proven). Do not limit the review to phase 6.

## The code under review (the map)

Everything is uncommitted on `main`. The auth surface, by crate:

`connetto-core`:
- `src/traits.rs`: `SessionVerifier` trait, `SessionVerifyError`, `SessionVerifyFuture` (boxed Send future), `MaybeSend`.
- `src/auth.rs`: `AuthContext`, `TrustingSessionVerifier` (the trust-nothing stand-in).
- `src/messages/error.rs`: `FatalErrorReason::AuthenticationFailed` (the single wire addition).
- `src/messages/handshake.rs`: `Handshake.auth_token`, `HandshakeAck`.

`connetto-server` (`src/authn/`):
- `token.rs`: `TokenAuthority` (Ed25519 via `jsonwebtoken`, algorithm and `iss` and `aud` and `exp` pinning, `AuthContext` rebuild), `AuthConfig`, `RefreshLifetimes`, the access-token claims.
- `store.rs`: `AuthStore` trait (RPITIT `-> impl Future + Send`), `InMemoryAuthStore`, `DbAuthStore` (behind `pg-async`), `IssuedSession`, `RefreshOutcome` (both now carry `session_expires_at`), refresh rotation and reuse-is-theft, the identity linking table.
- `service.rs`: `AuthService` (login, refresh, revoke, `provider_access_token` lazy refresher), `TokenPair` (now carries `user_id`, `session_expires_at_secs`), `ConnettoSessionVerifier`, the `unix_secs` helper.
- `provider.rs`: `IdentityProvider`, `ProviderRegistry`, `AssuranceRequirement`, `PermissiveProvider`, `IssuedAuthCode` (now carries `user_id`, `session_expires_at_secs`), `AuthCodes`.
- `provider_oidc.rs`: `GenericOidcProvider` (openidconnect 4, manual `CoreClient::new`, google and microsoft presets, Microsoft any-tenant matcher).
- `http.rs`: the `axum` login, callback, token, and refresh handlers, `TokenResponse` (now carries `user_id`, `session_expires_at`) and its `From<TokenPair>`, PKCE S256 verify.
- `src/session.rs`: `run_handshake` resolving identity through `Arc<dyn SessionVerifier>` over `auth_token`.
- Server binary wiring: `CONNETTO_AUTH`, `CONNETTO_AUTH_BIND`, `CONNETTO_JWT_PRIVATE/PUBLIC_KEY_FILE`, `CONNETTO_OIDC_PROVIDER` and `CONNETTO_OIDC_CLIENT_ID/SECRET/ISSUER/REDIRECT_URL/SCOPES/TENANT`.

`connetto-client`:
- `src/lib.rs`: `exchange_handshake` (maps `FatalError(AuthenticationFailed)` to `ClientError::Auth`), `ClientError::IdentityMismatch`, `ClientEvent::AuthenticationRequired`, `META_DDL` (adds `_connetto_identity`), `load_identity` and `stamp_identity`, `ConnettoConnection::bind_identity` and `identity` and `unsynced`, `AccessTokenSource`, `ClientConfig`.
- `src/live.rs`: `Recovery` enum, `recover` (three-way outcome), the pump routing to `AuthenticationRequired`.
- `src/auth.rs` (feature `native-auth`): `NativeAuthenticator`, `RefreshTokenStore` (`KeyringStore`, `MemoryRefreshStore`), `AcquiredSession` (renamed off `Session` to avoid the diesel-sqlite-session collision), acquire and refresh and login returning it, `token_source`.
- `src/teardown.rs` (new): `expiry_warning`, `ExpiryWarning`, `purge_replica` and `PurgeError` (feature `native-transport`).

`connetto-web` (standalone wasm workspace at `crates/connetto-web`):
- `src/auth.rs`: `BrowserAuthenticator`, `RefreshStore` (OPFS SQLite), `LoginMessage` (the tokenless broadcast enum), `TokenResponse`, `BrowserSession`, `Acquired`, `PendingLogin`, `await_login_code`, `deliver_login_code`.
- `src/workers.rs`: `WorkerStorage` (`Opfs` or `Memory`, with `delete_db`), `acquire_session`, `boot_db_worker` (identity binding plus account-switch purge and rebuild), `DbWorkerConfig` (`auth`, `auth_db_name`).

Tests: `connetto-server/tests/{authentication.rs, authn_flow.rs, provider.rs, authn_db.rs}`, `connetto-client/tests/{native_auth.rs, authentication_client.rs}`, and the `#[cfg(test)]` module in `connetto-client/src/teardown.rs`. Assess whether these defend observable contracts or merely exercise plumbing.

## Baseline and how to reproduce green

- Builds and tests use `cargo +stable`. Clippy uses `cargo +nightly` only.
- Green gate at the root workspace: `cargo +stable fmt --all -- --check`, `cargo +nightly clippy --all-targets --all-features -- -D warnings`, `cargo +stable test --release --all-features`.
- `connetto-web` is a separate workspace: run its `fmt` and `cargo +nightly clippy --target wasm32-unknown-unknown --all-targets -- -D warnings` from `crates/connetto-web`.
- All three passed as last left. Confirm this before reviewing so a finding is about the code, not a stale tree.

## What is proven versus not (weight findings accordingly)

- Runtime-tested: the in-memory store path, native acquisition and refresh, the reconnect auth-fatal routing, replica identity continuity, and the teardown logic (all Docker-free).
- Compile-only: the `connetto-web` browser worker path (wasm build plus clippy, no headless-Chrome run has exercised login broadcast, OPFS refresh persistence, or the account-switch purge and rebuild).
- Not re-run after the phase-6 change: the Docker-gated `authn_db.rs`. `DbAuthStore` now populates `session_expires_at` but the DB path was only compile-checked under `pg-async` this session (running it needs Docker approval).
- Never exercised against a live IdP: provider verification is tested against locally minted, locally signed tokens and `PermissiveProvider`.

## Specific things to scrutinize (open questions, not verdicts)

1. **Auth-fatal conflation in `recover`.** `live.rs` treats any `Err(ClientError::Auth(_))` from `resume` as terminal `ReauthRequired`. Trace where `ClientError::Auth` originates: the handshake `AuthenticationFailed` mapping and the native `AccessTokenSource` refresh. Does a transient refresh-endpoint fault (a network blip or a 5xx from `/auth/refresh`, mapped in `connetto-client/src/auth.rs post_json`) become a terminal re-login instead of a retry? Is that acceptable, and does it match the spec's "the client refreshes before the handshake" intent?
2. **Is `_connetto_identity` actually never synced?** `bind_identity` writes under `SuspendedCapture`, but confirm the table is excluded from the capture and upload path the same way `_connetto_meta` and `_connetto_pending` are, including the hub and relay `GLOB '_connetto*'` filter. A stamp that can ride a changeset would be a defect.
3. **Is identity continuity enforced or advisory?** `bind_identity` is driven by the `user_id` the app reads from the auth HTTP response, not by anything the sync handshake asserts. The server resolves identity from the token independently. Determine whether a mismatch between the token the server accepts and the replica's stamp can occur undetected, and whether the guard is where it should be.
4. **Browser account-switch purge and rebuild** in `workers.rs boot_db_worker`. It drops the worker connection, calls `storage.delete_db`, opens a second `BrowserSocket`, reconnects, and re-binds. Check: is the OPFS sync access handle released synchronously on `drop` before `delete_db`, or is there a race. Does opening a second server session briefly is a problem. Should the local or frontend tier also be purged on a switch, or is leaving device-local data correct. This path is runtime-untested.
5. **`session_expires_at` derivation** across the four store sites (in-memory create and rotate, DB create and rotate). Confirm the value is consistently `min(idle_deadline, absolute_deadline)` and that the `unix_secs` and `time_from_ms` conversions saturate sensibly rather than silently producing `0` or `i64::MAX` on odd input.
6. **`purge_replica` sidecar path building** in `teardown.rs` pushes `-wal` and `-shm` onto the db path OsString. Check behavior for non-file targets (`:memory:`, URI filenames) and whether a partial delete (db removed, sidecar delete then failing) leaves an inconsistent state.
7. **Doc and code alignment.** The client now learns `user_id` and `session_expires_at` from the auth HTTP responses. Confirm `11-authentication.md` still holds ("one wire addition" is about the sync wire, these are HTTP fields) and that the offline-expiry-warning and identity-continuity mechanisms match what the doc's "Offline-first and token expiry" section prescribes.
8. **Server-side dead plumbing.** Confirm nothing on the server needs to consume `user_id` or `session_expires_at` that currently ignores them, and that these are purely client-facing outputs.
9. **Phase 1 to 4 depth**, not just phase 6: the JWT verification pinning in `token.rs`, the refresh rotation and reuse-theft and the revoke-outside-the-aborted-transaction handling in `store.rs`, the PKCE verify and one-time-code redemption in `http.rs`, the openidconnect manual client build and the Microsoft any-tenant matcher in `provider_oidc.rs`, and the `AuthStore` RPITIT Send bounds. These carry the real security weight.

## Deduplication and simplification candidates (confirm each is worth it)

- `TokenResponse` is defined three times (`connetto-server/src/authn/http.rs`, `connetto-client/src/auth.rs`, `connetto-web/src/auth.rs`) with overlapping fields, plus two `From` conversions. Assess whether a shared serde type belongs in `connetto-core` and whether the wasm workspace boundary makes that practical.
- `AcquiredSession` (native, `SystemTime`) and `BrowserSession` (wasm, `u64`) are near-identical. Consider one shared shape.
- Time conversion helpers (`unix_secs`, `time_from_ms`, the `UNIX_EPOCH + Duration` reconstruction in the client) recur. Consider consolidating.
- The three `RefreshTokenStore` and `RefreshStore` implementations (native keyring, native memory, browser OPFS) share a load and save and clear shape across crates. Judge whether a common trait is warranted or whether the platform split justifies the duplication.

## Traps and constraints

1. `cargo +stable` for build and test, `cargo +nightly` for clippy only.
2. ASCII punctuation only in any prose you write (no semicolons, no em or en dashes, no ` - ` as punctuation).
3. The browser path cannot be runtime-verified without a headless-Chrome run, and the Docker-gated tests need explicit approval. Flag anything that can only be caught at runtime as such rather than asserting it works or fails.
4. Do not commit, push, or open anything. This is a review.
5. `missing_docs` is forbid across these crates, so any new public item in a suggested fix must be documented.

## What "done" looks like for the review

`docs/review-oauth-authentication.md` exists with grounded findings, each tied to a file and symbol, each with severity and a concrete suggestion, confirmed defects separated from open questions and from taste, and a short prioritized list at the end. Every behavioral claim is verified against the code or explicitly marked as unverifiable without a runtime run.
