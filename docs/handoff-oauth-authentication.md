# Handoff: authentication (OAuth 2.0 / OIDC) architecture design

## Goal in one sentence

Produce a technical architecture document that specifies how authentication (OAuth 2.0 / OIDC) will work across connetto, backend and both frontends, in a general reusable form: the flows, the trust boundary, the dependency choices, and any upstream or fork work required. The deliverable is a design document, not code.

## What to deliver

A new architecture doc at `docs/architecture/11-authentication.md` (the numbering slot after the existing `08-authorization.md`, `09-wasm.md`, and the two `10-*` docs). It must read like the other architecture chapters: a purpose, principles, the decided design, a dependency evaluation with a verified tradeoff table, named open questions, and a phased plan for a LATER implementation session. No production code is written this session. If the design concludes an upstream or fork change is required, capture it as a proposal in the repo's `upstream-*.md` convention, but do not implement it.

This is authentication only. Authorization (who may see or write which rows) already has its own chapter, `docs/architecture/08-authorization.md` (RLS mirrored server-side, per-row checks, OpenFGA and rls2fga). The new doc defines how a caller proves WHO they are and how that verified identity becomes the `AuthContext` that the authorization layer then consumes. Keep the authN and authZ boundary explicit and cross-reference `08-authorization.md`.

## Why this exists: the gap, grounded in the code

The wire and the types already anticipate a verified identity, but nothing verifies it.

- `connetto_core::messages::Handshake` carries `auth_token: String` (`crates/connetto-core/src/messages/handshake.rs`), documented as "Opaque JWT or session token, validated once at handshake and used to build the session `AuthContext`. The server never returns this on the wire." So the design intent (a JWT in the handshake, verified once) is already on the wire.
- `connetto_core::auth::AuthContext { user_id, tenant, roles, claims }` (`crates/connetto-core/src/auth.rs`) is documented as "Established from the JWT (or session lookup) presented in `Handshake`."
- But the server does not verify anything. `crates/connetto-server/src/session.rs` (`run_handshake`, around line 771) does `let auth_ctx = AuthContext::new(handshake.client_id.clone());` with the comment "Token validation (JWT decode or session lookup) lands with OpenFGA and rls2fga; for now the client id is the identity carried into the auth policy." The `auth_token` field is ignored entirely.
- That identity is load-bearing for security. `RlsAuth` and the write and snapshot paths run `SELECT set_config('app.user_id', $1, true)` binding `auth_ctx.user_id` (`crates/connetto-server/src/auth.rs`, `snapshot.rs`, `write_target.rs`), so Postgres RLS decides visibility and write authority from that string. Because the string is the unverified client id today, any client can assume any identity. This is the glaring hole the diagram now marks red on `connetto-server` and both clients.
- The client side simply sends whatever string it was configured with: `ClientConfig.auth_token` (`crates/connetto-client/src/lib.rs`) goes into `Handshake::new(...)` at connect (same file, the handshake builder around line 569), and the binary reads it from `CONNETTO_TOKEN` (`crates/connetto-server/../connetto-client/src/bin/connetto-client.rs`). There is no acquisition, no refresh, no provider.

So authentication is entirely absent end to end. The design must close that from token acquisition on the client to cryptographic verification on the server.

## The questions the design MUST answer

Server (verification):

- Which token shape: OIDC ID token, OAuth access token as a JWT, or opaque token plus introspection. Recommend one and say why.
- OIDC discovery and JWKS: how the server fetches and caches the provider's signing keys, key rotation, cache TTL, and behavior when the JWKS endpoint is unreachable (fail closed at handshake).
- JWT validation: signature, `iss`, `aud`, `exp`, `nbf`, allowed algorithms (pin asymmetric, reject `none` and algorithm confusion), clock skew tolerance.
- Claim to identity mapping: which claim becomes `AuthContext.user_id` (`sub` by default, configurable), how `tenant` and `roles` and `claims` are populated, and how that stays consistent with the RLS `app.user_id` contract.
- The seam: replace the trust-the-client-id step in `session.rs run_handshake` with a pluggable verifier. Mirror the existing `AuthPolicy` pattern (a trait with a real implementation plus a `Permissive`/test stand-in) so tests and local runs do not require a real IdP. Name the trait and where it plugs in.
- Failure surface: a bad or expired token at handshake should terminate with a clear `FatalError` reason (consider whether a new `FatalErrorReason` variant is needed, cross-reference `02-protocol.md`).

Client (acquisition), for BOTH the native app and the wasm browser app:

- Flow: OAuth 2.0 Authorization Code with PKCE for public clients (no client secret). Describe the native flow (loopback redirect, system browser) and the wasm flow (redirect or popup in the browser) and where they diverge.
- Token storage: where the access and refresh tokens live on each platform, and the threat model. In the browser, name the XSS exposure of `localStorage` and evaluate alternatives (in-memory plus silent refresh, storage inside the dedicated DB worker, or the leader tab). On native, evaluate OS secure storage.
- Refresh: refresh token rotation, when to refresh, and how a refreshed token reaches the handshake on the next connect or reconnect.
- Attaching to the wire: the acquired access token becomes `Handshake.auth_token`. Confirm this needs no wire change, or specify the change.

Offline-first implications (this is a local-first system, so this section is essential):

- The replica is local and readable offline. Authentication gates SYNC (the server connection), not local reads. State this as a principle.
- Token expiry while offline: a token can expire during a long offline period. Specify reconnect behavior when the token is expired, how refresh is attempted, and what happens to queued pending mutations if re-authentication fails on reconnect (cross-reference `06-reconnect.md` and the exactly-once mutation design).
- The interim risk: until this lands, `app.user_id` is unverified. The doc should state the current exposure plainly and note that the leader or DB worker owns the one connection to the server, so token handling on the browser side is centralized there (cross-reference `09-wasm.md` and the topology in the roadmap).

Deployment shape:

- Multi-provider and multi-tenant: configurable issuer or issuers, audience, and claim mapping. How a deployment points connetto at its IdP.
- The PostgreSQL mesh: whether authentication is per-instance or global across the mesh, and how the resolved identity relates to the per-instance RLS.
- Revocation: access-token lifetime versus session lifetime, and whether the server needs any revocation check beyond token expiry (align with the file-session token reasoning in `08-authorization.md`).

## Dependencies to evaluate (verify every claim)

Name concrete candidate crates and evaluate them in a tradeoff table. Per the repo rule, every capability or cost cell MUST be verified against the crate's source or documentation before it is presented, and any unverified cell must say so. Candidates to assess (confirm names, versions, maintenance, and wasm support against docs.rs and each repo, do not assume):

- Server verification: `openidconnect` (OIDC discovery plus ID-token validation), `jsonwebtoken` (JWT verify), `oauth2` (the flow primitives), a JWKS fetcher or the JWKS support inside `openidconnect`, and the async HTTP client they pull (for example `reqwest`) and whether it fits the server's existing tokio and diesel-async stack.
- Client native: `oauth2` or `openidconnect` for the code-plus-PKCE flow, a loopback redirect listener, and an OS secure-storage crate (for example `keyring`), each checked for fit.
- Client wasm: the primary risk. Determine whether `openidconnect` and `oauth2` compile to `wasm32-unknown-unknown`, whether their HTTP layer can be swapped for a `web-sys` fetch, and how the redirect and PKCE flow work in the browser and dedicated worker topology. If no crate cross-compiles cleanly, that is a likely uphill: assess whether a thin browser-side flow over `web-sys` plus server-side verification is the pragmatic split, and whether any upstream or fork work is warranted.

Reach for the librarian or the rust-docs tooling to confirm crate capabilities from source rather than assuming.

## Traps

1. **Authentication is not authorization.** This doc defines identity proof only. Do not restate or redesign the RLS and OpenFGA authorization model, reference `08-authorization.md`. The single connecting fact is that the verified identity becomes `AuthContext.user_id`, which the authorization layer and RLS `app.user_id` already consume.
2. **The identity feeds RLS directly.** Whatever claim maps to `user_id` becomes the RLS principal via `set_config('app.user_id', ...)`. A weak or spoofable mapping reintroduces the current hole. Pin the mapping and its verification.
3. **Algorithm and audience pinning.** Reject `none`, reject symmetric algorithms verified with a public key, and pin `iss` and `aud`. Say so explicitly.
4. **The browser token store is a real threat surface.** `localStorage` is XSS-readable. Evaluate keeping the token off the page (in the DB worker or leader), given connetto's topology already centralizes the server connection there.
5. **Offline expiry is a first-class case, not an error.** A local-first client must keep working offline with an expired token for local reads, and re-authenticate only to resume sync. Design the reconnect and refresh path around that, do not treat expiry as a hard failure of the app.
6. **No wire redesign unless justified.** `Handshake.auth_token` already exists. Only propose a protocol change if verification genuinely needs one (for example a new `FatalErrorReason`), and cross-reference `02-protocol.md`.
7. **Pluggable verifier, mirror the existing pattern.** The server already has `AuthPolicy` with `PermissiveAuth` and `RlsAuth`. Authentication should follow the same shape (a trait plus a permissive stand-in) so tests and Docker-free loops do not need a live IdP.
8. **ASCII punctuation only** in all prose (no semicolons, no em or en dashes, no ` - ` as punctuation).

## What "done" looks like

`docs/architecture/11-authentication.md` exists and reads like a peer of the other architecture chapters. It states the authN and authZ boundary, recommends a token shape and flow, specifies server verification and the pluggable verifier seam at `session.rs run_handshake`, specifies client acquisition for native and wasm, treats offline token expiry as a designed case, and includes a dependency tradeoff table whose every cell is verified against source or explicitly marked unverified. It names any upstream or fork work as a proposal without implementing it, adds an authentication open question to `docs/architecture/open-questions.md`, and the roadmap gets a short pointer. No code, no crate added to any manifest.
