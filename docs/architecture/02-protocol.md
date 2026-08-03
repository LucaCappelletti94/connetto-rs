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

| Plane | Tag | Encoding | Frame types |
|---|---|---|---|
| Control | `TAG_CONTROL = 0` | MessagePack | `Handshake`, `Subscribe`, `SnapshotBegin`, `SnapshotEnd`, `MutationHeader`, and so on |
| Bulk | `TAG_BULK = 1` | Zstd-precompressed opaque bytes | `SnapshotPatch`, `LivePatch`, `MutationPatch` |

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
| `MutationReject` | Mutation rejected: client sequence number + reason code. **Decided (R5b)**: gains a reason meaning cannot determine, retry, for when the authorization service is unreachable. It must not reuse `Unauthorized`, which asserts the caller lacks permission when the truth is that the server cannot tell, and which makes a client stop retrying and possibly discard the mutation. Adding a variant is a wire change. |
| `MutationConflict` | Conflict detected: client sequence number, table, and the server's current copy of the row. **Built (R8).** The row is optional, because a write against a row somebody else deleted conflicts with nothing to send, and it reaches the application rather than being discarded by the client. |
| `FullResyncRequired` | Server requires the client to re-snapshot a subscription. **Built (R8).** `FullResyncReason` carries exactly the one variant anything sends, `CursorOutsideRetention`. It gains a variant for authorization change in phase R7. Adding a variant is a wire change: the enum has no forward-compatible fallback for an unknown value. |
| `Pong` | Keepalive reply |
| `Error` | Non-fatal error associated with a specific request |
| `FatalError` | Server is closing the session: reason code. **Built (R2, R8).** Every variant names a close the server performs, there is no catch-all, and `crates/connetto-core/tests/wire.rs` guards that with a wildcard-free match. R2 wired `SessionRevoked` and `ConnectionSuperseded`, R8 sends `ServerShuttingDown` on SIGINT or SIGTERM by walking the connection registry, and the client surfaces the reason as `ClientEvent::ServerClosed` instead of treating it as a protocol violation, so it backs off rather than dying silently. |

**Decided (R5b): a delivery-paused signal.** When the authorization service is unreachable connetto fails closed, delivering no patch, and a caller must be able to distinguish that from nothing changing. `NonFatalError` carries only `related_to` and an untyped `detail`, so this needs a typed signal rather than a string a client parses. Snapshots are unaffected throughout, because they run on Postgres RLS, so an outage stops live delivery and writes while a fresh connection can still read. See `08-authorization.md`.

---

## Grants and the handshake

**Built (R3).** A grant is a connetto-signed token asserting that the bearer is a named subject, either a person (`user:alice`) or a key (`key:abc123`). It is opaque to the client, which never parses it and only stores and presents it. It says nothing about what the subject may do: `08-authorization.md` answers that from the authorization model. The list may be empty, and each grant is checked independently.

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
- The LSN in `SnapshotEnd` is the point at which the snapshot was taken.
- Any `LivePatch` frames with LSN > snapshot LSN that arrive after `SnapshotEnd` are applied on top.
- Any `LivePatch` frames with LSN <= snapshot LSN that arrive before `SnapshotEnd` are buffered and discarded after the snapshot is complete (they are already reflected in the snapshot).

---

## Flow Control

The client maintains a **receive credit** budget. On connect, the server is granted an initial credit (e.g. 64 messages). Each server message consumes one credit. The client sends `Ack(n)` to replenish `n` credits after processing `n` messages.

The server pauses delivery when credits reach zero and resumes when credits are replenished.

This is a simple stop-and-wait variant. A sliding-window variant may be needed for high-throughput scenarios.

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
- **Silent rejection (R3, built)**: a grant that fails to resolve does not end the connection and produces no field on `HandshakeAck`. Not-allowed, no-longer-allowed, and never-existed are indistinguishable on the wire, and `FatalErrorReason::AuthenticationFailed` is deleted.
- **Session token (R2)**: the server mints a real durable handle at handshake and the client persists it outside the local replica. The current implementation is a non-functional stub (**Built, defective**).
- **Enum-variant wire change**: adding a variant to `FullResyncReason` or `FatalErrorReason` is a wire-breaking change. Neither enum has a forward-compatible fallback for an unknown value.
- **Version bumps (decided)**: `PROTOCOL_VERSION` stays frozen at 1 until the first release, wire changes land freely before then, and the first release performs one deliberate bump. Per-phase bumps were considered and rejected as ceremony while nothing is published. A mismatch stays detectable throughout.

---

## Notes

- `SubscriptionSpec` is defined in `01-pieces.md`. Its exact wire encoding depends on the serialization format decision.
- The `client_seq` namespace is per-session, not global. It resets on reconnect from the client's perspective (the server associates it with the session ID).
- For the canonical model of grants, sessions, and identity, see `12-identity-session-capability.md`.
