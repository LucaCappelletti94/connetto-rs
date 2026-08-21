# 02: Protocol

**Status**: draft

---

## Purpose

Define how client and server talk to each other: the transport channel, the message framing, the message types, and the sequencing rules.

---

## Transport Channel

The primary transport is a **persistent, full-duplex connection** (WebSocket is the baseline). Both sides can send messages at any time without a request/response pairing.

### Why not HTTP request/response?

Subscription updates and CDC pushes are asynchronous server-initiated events. HTTP SSE or long-poll could carry server→client traffic, but they add complexity for the client→server mutation path and make flow control harder. WebSocket handles both directions on one connection.

### HTTP fallback

Environments that block WebSocket (some corporate proxies) need an alternative. Options:

- HTTP SSE for server→client + HTTP POST for client→server
- HTTP long-poll

This is deferred until the WebSocket path is stable.

---

## Message Framing

Each message is a length-prefixed binary frame. The frame structure:

```
[ 1 byte: tag ][ 4 bytes: payload length (big-endian u32) ][ payload bytes ]
```

The payload is a serialized `ControlMessage` or `BulkMessage`, chosen by the tag byte. There is no single top-level message type.

### Serialization format

Open question, see below. Candidates:

| Format | Pros | Cons |
|---|---|---|
| MessagePack | Compact, schema-less, fast | Schema evolution without versioning is fragile |
| Protobuf / FlatBuffers | Compact, schema-enforced, good evolution story | Requires `.proto` or schema files and a code-gen step |
| JSON | Human-readable, easy to debug | Verbose, slower, no binary blob support without base64 |
| CBOR | Compact, standardized (RFC 7049), native binary | Less tooling than protobuf |

### Two-plane framing

The protocol has two planes. The **control plane** carries typed, MessagePack-encoded frames for signaling, handshake, and subscription management. The **bulk plane** carries large, opaque, Zstd-precompressed byte payloads (snapshot data, live patches, and client-uploaded mutation patchsets). The tag byte at the start of each frame distinguishes the planes: `TAG_CONTROL = 0`, `TAG_BULK = 1`. Bulk payloads arrive already compressed. The transport does not re-compress them, and decompression is the consumer's responsibility.

| Plane | Tag | Encoding | Frame types | Status |
|---|---|---|---|---|
| Control | `TAG_CONTROL = 0` | MessagePack | `Handshake`, `Subscribe`, `SnapshotBegin`, `SnapshotEnd`, `MutationHeader`, and so on | **Built** |
| Bulk | `TAG_BULK = 1` | Short MessagePack header, then the Zstd-precompressed payload appended untouched | `SnapshotPatch`, `LivePatch`, `MutationPatch` | **Decided (R16 part B)** |

**The bulk row is the target, and the code does not implement it. Settled 2026-08-07.** This table gave the bulk plane as opaque precompressed bytes from the first draft, and `crates/connetto-core/src/messages/bulk.rs` says the same in its module comment, while `encode_bulk` in `crates/connetto-core/src/codec.rs` runs `rmp_serde::to_vec_named` over a `BulkMessage` whose variants embed the payload as a field. So the payload is copied into a MessagePack buffer per socket and then again into the tagged frame. R16 part B records that as a drift from this specification rather than a change of direction, and settles the layout:

```
[ 1 byte: tag ][ 4 bytes: header length (big-endian u32) ][ header ][ compressed payload ]
```

The header is a MessagePack-encoded enum mirroring the bulk variants with the payload field removed. On a byte-stream transport the existing outer length wraps all three parts. `17-fan-out.md` owns the reasoning, the copy counts, and what else has to move before the payload reaches a socket without being copied.

---

## Message Types

### Client → Server

| Message | Purpose |
|---|---|
| `Handshake` | Opens or resumes a session: a client-chosen correlation label (never a trust input), the resume cursor, the server-issued session token when resuming, and zero or more opaque grants. **Decided (R3)** for the grant list shape. |
| `Subscribe` | Registers a new subscription: sub ID + `SubscriptionSpec` |
| `Unsubscribe` | Cancels a subscription by sub ID |
| `MutationHeader` | Submits a mutation: control frame carrying the client sequence number, paired one-to-one with the `MutationPatch` bulk frame that follows it |
| `AckCredits` | Client returns flow-control credits for delivered bulk payloads |
| `Ping` | Keepalive probe |

### Server → Client

| Message | Purpose |
|---|---|
| `HandshakeAck` | Session accepted: a per-connection routing label, the session token to persist, the current cursor, the schema version, the initial credit, and the durable mutation watermark. Carries nothing about a grant that failed to resolve: not-allowed and never-existed are indistinguishable on the wire, and must be. **Decided (R3)** |
| `SnapshotBegin` | Control frame: start of initial snapshot for a subscription |
| `SnapshotPatch` | **Bulk plane.** Snapshot data: `sub_id` + `patchset_zstd` (Zstd-compressed SQLite patchset). One or more frames complete the snapshot. |
| `SnapshotEnd` | Control frame: snapshot complete; carries `sub_id` and the LSN at which the snapshot was taken |
| `LivePatch` | **Bulk plane.** Incremental CDC patch: `sub_id` + `cursor` + `patchset_zstd` |
| `AggregateUpdate` | Incremental or full aggregate result update |
| `MutationApplied` | Mutation accepted: client sequence number echoed |
| `MutationReject` | Mutation rejected: client sequence number + reason code. **Built (R5b, 2026-08-12)**: gains `MutationRejectReason::Indeterminate` for when the authorization service is unreachable. It must not reuse `Unauthorized`, which asserts the caller lacks permission when the truth is that the server cannot tell, and which makes a client stop retrying and possibly discard the mutation. The variant's doc comment states the client MUST retry. |
| `MutationConflict` | Conflict detected: client sequence number, table, and the server's current copy of the row. **Built (R8).** The row is optional, because a write against a row somebody else deleted conflicts with nothing to send, and it reaches the application rather than being discarded by the client. |
| `FullResyncRequired` | Server requires the client to re-snapshot a subscription. **Built (R8, extended R7 2026-08-16).** `FullResyncReason` carries two variants, one per producer: `CursorOutsideRetention` when a resuming cursor has fallen out of the retained window, and `AuthorizationChange` when a grant reaching the subscription's table moved. Adding a variant is a wire change: the enum has no forward-compatible fallback for an unknown value. |
| `Pong` | Keepalive reply |
| `Error` | Non-fatal error associated with a specific request. **Built (R38, 2026-08-06).** A refusal on the subscribe path carries one fixed `detail` (`subscription refused`) whatever the cause, on the direct server and through the relay alike, because a detail that varied told a caller which stage refused and so whether the table or column it guessed exists. The cause goes to the structured log. |
| `RateLimited` | Server refuses one request for asking too often, correlated by `related_to` and carrying `retry_after_ms`. **Built (R19, 2026-08-06).** Typed rather than a detail string, and deliberately not folded into `Error`: a caller must be able to tell "retry later" from "this will never work", because a reconnect re-declares every subscription at once and can trip a limit while perfectly well behaved. Saying so discloses nothing, since a caller already knows how fast it was asking. |
| `SyncStatus` | Relay to tab only, on the same control plane: whether the worker's upstream connection stands (`Connected` or `Offline`). **Built (R20, 2026-08-08).** The real server never sends it, because a server cannot tell a client it is not reaching that it is unreachable. The worker derives the state, the relay forwards each change to every handshaken tab, and each newly handshaken tab is told the current value right after its ack. Natively the same state arrives as `ClientEvent::SyncStatus` with no frame involved. |
| `FatalError` | Server is closing the session: reason code. **Built (R2, R8, R19).** Every variant names a close the server performs, there is no catch-all, and `crates/connetto-core/tests/wire.rs` guards that with a wildcard-free match. R2 wired `SessionRevoked` and `ConnectionSuperseded`, R8 sends `ServerShuttingDown` on SIGINT or SIGTERM by walking the connection registry, R19 added `RateLimited` with its `retry_after_ms` for a caller over its connection or credential-refusal limit, and the client surfaces the reason as `ClientEvent::ServerClosed` instead of treating it as a protocol violation, so it backs off rather than dying silently. |

**Built (R5b, 2026-08-12): a delivery-paused signal.** When the authorization service is unreachable connetto fails closed, delivering no patch, and a caller must be able to distinguish that from nothing changing. `ControlMessage::DeliveryPaused { cause: PauseCause }` carries this signal, and `ControlMessage::DeliveryResumed` cancels it. `PauseCause::AuthServiceUnreachable` names the OpenFGA outage, and `PauseCause::ChangeStreamStalled` names a change stream that is connected but not advancing. `NonFatalError` carries only `related_to` and an untyped `detail`, so a typed signal rather than a string a client parses was the right shape. Snapshots are unaffected throughout, because they run on Postgres RLS, so an outage stops live delivery and writes while a fresh connection can still read. See `08-authorization.md`.

---

## Grants and the handshake

**Built (R3).** A grant is a connetto-signed token asserting that the bearer is a named subject, either a person (`user:alice`) or a key (`key:abc123`). It says nothing about what the subject may do: `08-authorization.md` answers that from the authorization model. The list may be empty, and each grant is checked independently.

**Opaque to the client, with one exception the format already permits. Amended 2026-08-06, and the exception is Built (R45 step 3, 2026-08-09).** The client stores and presents a grant and never interprets what it authorizes. The exception is `exp`: a grant is an EdDSA JWT and a JWT payload is base64url, signed rather than encrypted, so a client reads the expiry of a token it already holds with no key and no round trip. It does so in `crates/connetto-client/src/grant_expiry.rs` and skips presenting a key whose time has passed, because otherwise a dead key is re-presented on every reconnect and draws a refusal every time. This is safe because it is advisory only: the server verifies `exp` authoritatively regardless, so a client trusting a forged claim either presents a dead key and is refused as now, or skips a live one and harms only itself. Anything the client cannot read is presented rather than withheld, for the same reason. No other claim may drive any client decision.

**Every grant is checked by arithmetic.** Because both kinds are connetto-signed, checking one is a signature verification against connetto's own public key, with no database lookup. So the list carries no routing metadata, nothing sniffs the shape of a string, no order of checks is load-bearing, and an unrecognised string costs arithmetic and nothing more.

A grant that fails to resolve does not end the connection. The session proceeds on whatever resolved. A caller who presents an expired key beside a valid login is signed in and sees less, which is the ordinary case.

The reply (`HandshakeAck`) says nothing about a failure: no reason, and not which grant it was. Not-allowed, no-longer-allowed, and never-existed are indistinguishable, on the same reasoning that a service does not distinguish an authorization failure from a missing resource. Failures are recorded in the server's structured log and nowhere else, which is what makes them loud, and `FatalErrorReason::AuthenticationFailed` is deleted because nothing can send it any more.

This replaces the single `auth_token` field with a variable-length list and is a breaking wire change (no bump before the first release, see the version-bump decision under Decisions). `HandshakeAck` also gained `resume_token` beside `session_token`, which are two different things: the handle in the clear, which the application reads because a synced row written before anybody signed in is attributed to it, and the bearer secret proving that handle is this caller's.

See `12-identity-session-capability.md` for the full model.

---

## Session token

**Built (R2, R3).** The request field is `resume_token`, the credential a run presents to continue, and the reply carries both `session_token`, the handle in the clear, and `resume_token`, the credential for next time. The server refuses a credential it did not sign, so a caller can neither invent a handle nor resume as a visitor whose handle it obtained. An identified run takes its handle from its login grant instead and ignores the field.

**Decided (R2).** Under R2 the server mints a real opaque durable handle at handshake. The client persists it outside the local replica (because an unidentified session's replica is in memory and would not survive a reload) and presents it on reconnect. The exactly-once mutation watermark is re-keyed from `(user_id, session_id)` onto the session handle alone.

See `12-identity-session-capability.md` for the session model.

---

## Sequencing Rules

### Client mutations

- Mutations carry a monotonically increasing `client_seq` per session.
- The server processes mutations in `client_seq` order per session.
- The server echoes `client_seq` in `MutationApplied`, `MutationReject`, and `MutationConflict`.
- The client does not send a new mutation until the previous one is acknowledged, **or** the client sends a window of N mutations and back-pressures at N unacknowledged (to be decided).

### Server → client ordering

- Row updates and aggregate updates carry the server LSN.
- The client applies updates in LSN order. Updates out of order are buffered until the gap is filled.
- The client stores its highest applied LSN and sends it in `Handshake` on reconnect.

### Snapshot before updates

- After a `Subscribe`, the server sends `SnapshotBegin` (control), one or more `SnapshotPatch` bulk frames, then `SnapshotEnd(lsn)` (control).
- **`SnapshotEnd` cannot overtake the rows it completes. Built (R33, 2026-08-09).** It shares the outbound queue with the `SnapshotPatch` frames rather than going straight to the socket, so a client whose credit window is shut receives neither until it replenishes. It still costs no credit: it waits its turn, it is not rationed. Before this it went out immediately and a backlogged client was told its snapshot was complete over an empty replica, then recorded the resume position that frame carries.
- No frame goes out until the snapshot read has succeeded (R38). A subscription the server cannot serve draws exactly one `Error` frame, bare and byte-identical whatever the cause, so a refusal never discloses whether the name passed registration.
- The LSN in `SnapshotEnd` is the point at which the snapshot was taken.
- Any `LivePatch` frames with LSN > snapshot LSN that arrive after `SnapshotEnd` are applied on top.
- `LivePatch` frames overlapping the snapshot are re-applied, not filtered. Neither the snapshot LSN nor a change's WAL position orders by visibility, so a discard rule loses data. Decided at R28 part A, see `04-subscriptions.md`.

---

## Flow Control

The client maintains a **receive credit** budget. On connect, the server is granted an initial credit (e.g. 64 messages). Each bulk frame consumes one credit, and the client sends `AckCredits(n)` to replenish `n` credits after processing `n` of them. No control frame is ever charged, so keepalive and acknowledgements cannot deadlock behind a full window.

The server pauses bulk delivery when credits reach zero and resumes when credits are replenished.

**Not rationed and not ordered are separate properties, and the queue carries both. Decided (R33).** `SnapshotEnd` is the one control frame that waits in the queue: it describes rows the client has not received, so releasing it early is a statement the client would act on wrongly. Everything else on the control plane bypasses the queue entirely.

This is a simple stop-and-wait variant. A sliding-window variant may be needed for high-throughput scenarios.

---

## Rate limiting

**Built (R19, 2026-08-06), and it is a different job from flow control.** Credits bound how much undelivered data a session accumulates. They do not bound what a caller may ask for, so before this nothing did: a caller could declare subscriptions as fast as it liked, and each one costs a full snapshot of the subscribed shape.

Three signals are metered on the sync path, subscription creation, connections, and refused grants, each per window and each **tiered by whether the handshake resolved an identity**. An authenticated caller is accountable, there is a user to attribute cost to and a session to revoke, and an unidentified one has neither by definition, so its allowance is smaller rather than absent. Everything counts against the durable session handle rather than a per-connection counter, which is what makes a limit survive a reconnect instead of capping one connection.

Over the limit, a subscription draws `RateLimited` and the session stays open, while a connection or a flood of refused grants is closed with `FatalErrorReason::RateLimited`. Nothing is served slowly: connetto refuses rather than queues, because a queue is the cost the caller wanted to impose.

**What one read may cost is bounded too. Built (R58, 2026-08-21).** The sentence above about credits still holds, and R19's answer to it was a count. What a single read costs is now bounded separately: the query is wrapped with a row cap derived from a per-tier byte budget, a per-tier time limit is set on the read's own transaction because a row cap bounds connetto's memory and the wire and not the database's work, and a row above a per-tier ceiling is refused rather than delivered.

**A large read is served rather than refused, which is why an initial snapshot may arrive as several `SnapshotPatch` frames.** A read past its budget is paged by primary key, never by offset, and the next page is taken when the client acknowledges the last, so the credit window paces the database reads as well as the wire. `SnapshotBegin` and `SnapshotEnd` still bracket exactly one read, and the cursor `SnapshotEnd` carries is the first page's, so resuming from it can only re-deliver changes the client already has. **A live patch may now arrive between two pages**, where before nothing preceded `SnapshotEnd`: this is safe in one direction only, and it is the right one, because a page is read after every frame already sent and so can never carry a value older than one the client has applied. Delivery order carries no promise, since the client reads its replica with its own queries.

A read the server will not serve is refused, never truncated, and every cause reaches the wire as R38's one fixed phrase with the cause in the server's log. A read that fails part way through the pages is replaced once through `FullResyncRequired`, whose new `SnapshotInterrupted` reason says so, and refused if the replacement fails too.

**connetto never meters a network address, and never fingerprints a caller.** By the time it could consult an address it has accepted the connection, completed the upgrade and allocated a session, which is the whole cost. That belongs to the edge. Fingerprinting was examined separately and declined on its own merits (R36), not inherited from the address decision: connetto terminates no TLS, so it never sees a `ClientHello` and cannot compute a fingerprint, and one would name a client library rather than a caller in any case. The consequence is accepted rather than hidden: a caller that discards its handle every connection gets a fresh allowance. **Answering that is R39's**, which reserves a share of the connection pool for identified callers and so bounds unnamed traffic without needing to name it, plus the edge for raw volume. See `16-server-capacity.md`, and `08-authorization.md` for the same reasoning applied to bans.

---

## Open Questions

1. ~~**Serialization format**: which format? Decision needed before any message types are implemented.~~ **Decided (Q2.1):** MessagePack via `rmp-serde` for the control plane, JSON for aggregate results only. Shipped: `crates/connetto-core/src/codec.rs` implements MessagePack encode/decode with length-prefixed framing (`:1`, `:5`).
2. ~~**Mutation window**: single in-flight mutation vs. sliding window of N? What is N, and how does it interact with client-seq ordering?~~ **Decided (Q2.2):** Dissolved. The client sends PatchSets, not individual mutations, so the window concept does not apply.
3. **Versioning / evolution**: `PROTOCOL_VERSION` exists on the wire and `ProtocolVersionMismatch` is a `FatalErrorReason`. A mismatch is fatal and the connection closes. Negotiation is not currently implemented: a client on the wrong version is disconnected. Whether the server should advertise its version before disconnecting, or whether a compatibility range should be negotiated, is **deferred until the first release, and is not an open question before then**. The workspace is at `version = "0.0.0"` and nothing is published, so no client exists that a server must stay compatible with and negotiation would protect nothing. The condition that makes it real is a released client that updates on its own schedule, a mobile fleet being the obvious case, and it should be decided then rather than guessed now.
4. ~~**HTTP fallback**: is it in scope for v1?~~ **Decided (Q2.4):** Dissolved by Q0.1. WebSocket only.
5. ~~**Compression**: per-message or per-frame compression (e.g. `permessage-deflate` for WebSocket)? Worthwhile for large snapshots.~~ **Decided (Q2.5):** Zstd at the application layer on PatchSet and snapshot payloads only. Control plane messages are not compressed.

---

## Decisions

- **Grant list shape (R3, built)**: `Handshake` carries zero or more opaque grants, not one credential. Each resolves independently into an identity, capabilities, or a refusal, and two logins on one handshake leave the caller unidentified so no order of checks decides who is calling.
- **Silent rejection (R3, built)**: a grant that fails to resolve does not end the connection and produces no field on `HandshakeAck`. Not-allowed, no-longer-allowed, and never-existed are indistinguishable on the wire, and `FatalErrorReason::AuthenticationFailed` is deleted. **A boolean reporting that some grant failed was added on 2026-08-06 and removed the same day**, recorded so it is not re-derived. Its justification was that a client cannot discover a share key revoked while it was away, and that is false: revoking a share deletes an application row and never touches the token, so the grant still checks out and no refusal occurs (see `authn/service.rs`, which makes no store call for a capability by design). The boolean was therefore silent for the case it was written for, and fired only for expiry, which the client answers offline by reading `exp`. Naming which grants failed stays rejected on its own merits, since it would let one handshake resolve a batch of guesses.
- **Session token (R2)**: the server mints a real durable handle at handshake and the client persists it outside the local replica. The current implementation is a non-functional stub (**Built, defective**).
- **Enum-variant wire change**: adding a variant to `FullResyncReason` or `FatalErrorReason` is a wire-breaking change. Neither enum has a forward-compatible fallback for an unknown value.
- **Version bumps (decided)**: `PROTOCOL_VERSION` stays frozen at 1 until the first release, wire changes land freely before then, and the first release performs one deliberate bump. Per-phase bumps were considered and rejected as ceremony while nothing is published. A mismatch stays detectable throughout.

---

## Notes

- `SubscriptionSpec` is defined in `01-pieces.md`. Its exact wire encoding depends on the serialization format decision.
- The `client_seq` namespace is per-session, not global. It resets on reconnect from the client's perspective (the server associates it with the session ID).
- For the canonical model of grants, sessions, and identity, see `12-identity-session-capability.md`.
