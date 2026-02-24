# 02 — Protocol

**Status**: draft

---

## Purpose

Define how client and server talk to each other: the transport channel, the message framing, the message types, and the sequencing rules.

---

## Transport Channel

The primary transport is a **persistent, full-duplex connection** — WebSocket is the baseline. Both sides can send messages at any time without a request/response pairing.

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
[ 4 bytes: payload length (big-endian u32) ][ payload bytes ]
```

The payload is a serialized `WireMessage`.

### Serialization format

Open question — see below. Candidates:

| Format | Pros | Cons |
|---|---|---|
| MessagePack | Compact, schema-less, fast | Schema evolution without versioning is fragile |
| Protobuf / FlatBuffers | Compact, schema-enforced, good evolution story | Requires `.proto` / schema files; code-gen step |
| JSON | Human-readable, easy to debug | Verbose; slower; no binary blob support without base64 |
| CBOR | Compact, standardized (RFC 7049), native binary | Less tooling than protobuf |

---

## Message Types

### Client → Server

| Message | Purpose |
|---|---|
| `Handshake` | Opens session: client ID, last known server LSN, auth token |
| `Subscribe` | Registers a new subscription: sub ID + `SubscriptionSpec` |
| `Unsubscribe` | Cancels a subscription by sub ID |
| `Mutation` | Submits a mutation: client sequence number + `MutationRecord` |
| `Ack` | Client acknowledges receipt of a server batch (used for flow control) |
| `Ping` | Keepalive probe |

### Server → Client

| Message | Purpose |
|---|---|
| `HandshakeAck` | Session accepted: assigned session ID, current server LSN, schema version |
| `SchemaUpdate` | New schema version: full schema payload |
| `SnapshotBegin` | Start of initial snapshot for a subscription |
| `SnapshotRows` | Batch of rows for the ongoing snapshot |
| `SnapshotEnd` | Snapshot complete for a subscription; includes the LSN at which snapshot was taken |
| `RowUpdate` | Incremental row-level change batch (CDC-sourced) |
| `AggregateUpdate` | Incremental or full aggregate result update |
| `MutationAck` | Mutation accepted: client sequence number echoed |
| `MutationReject` | Mutation rejected: client sequence number + reason code |
| `MutationConflict` | Conflict detected: client sequence number + server's current value |
| `Pong` | Keepalive reply |
| `Error` | Non-fatal error associated with a specific request |
| `FatalError` | Server is closing the session: reason code |

---

## Sequencing Rules

### Client mutations

- Mutations carry a monotonically increasing `client_seq` per session.
- The server processes mutations in `client_seq` order per session.
- The server echoes `client_seq` in `MutationAck` / `MutationReject` / `MutationConflict`.
- The client does not send a new mutation until the previous one is acknowledged, **or** the client sends a window of N mutations and back-pressures at N unacknowledged (to be decided).

### Server → client ordering

- Row updates and aggregate updates carry the server LSN.
- The client applies updates in LSN order; updates out of order are buffered until the gap is filled.
- The client stores its highest applied LSN and sends it in `Handshake` on reconnect.

### Snapshot before updates

- After a `Subscribe`, the server sends `SnapshotBegin` → zero or more `SnapshotRows` → `SnapshotEnd(lsn)`.
- The LSN in `SnapshotEnd` is the point at which the snapshot was taken.
- Any `RowUpdate` messages with LSN > snapshot LSN that arrive after `SnapshotEnd` are applied on top.
- Any `RowUpdate` messages with LSN ≤ snapshot LSN that arrive before `SnapshotEnd` are buffered and discarded after the snapshot is complete (they are already reflected in the snapshot).

---

## Flow Control

The client maintains a **receive credit** budget. On connect, the server is granted an initial credit (e.g. 64 messages). Each server message consumes one credit. The client sends `Ack(n)` to replenish `n` credits after processing `n` messages.

The server pauses delivery when credits reach zero and resumes when credits are replenished.

This is a simple stop-and-wait variant; a sliding-window variant may be needed for high-throughput scenarios.

---

## Open Questions

1. **Serialization format**: which format? Decision needed before any message types are implemented.
2. **Mutation window**: single in-flight mutation vs. sliding window of N — what is N, and how does it interact with client-seq ordering?
3. **Versioning / evolution**: how are breaking changes to `WireMessage` handled? A version field in `Handshake`? A negotiation step?
4. **HTTP fallback**: is it in scope for v1?
5. **Compression**: per-message or per-frame compression (e.g. `permessage-deflate` for WebSocket)? Worthwhile for large snapshots.

---

## Decisions

*(none yet)*

---

## Notes

- `SubscriptionSpec` is defined in `01-pieces.md`; its exact wire encoding depends on the serialization format decision.
- The `client_seq` namespace is per-session, not global; it resets on reconnect from the client's perspective (the server associates it with the session ID).
