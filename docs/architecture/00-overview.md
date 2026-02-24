# 00 — Overview

**Status**: draft

---

## What This System Does

connetto-rs is a transport and synchronization layer that keeps SQLite-based edge/frontend clients in sync with a PostgreSQL backend.

The system:

- Accepts mutations from clients, validates and applies them server-side, and reports outcomes (success, conflict, rejection) back to the originating client
- Watches PostgreSQL for data changes (via CDC) and pushes relevant updates to subscribed clients
- Lets clients declare interest in specific queries (row-level or aggregate); delivers an initial snapshot and subsequent incremental updates
- Handles reconnect and offline gaps: clients track their position in the server's change log and catch up on reconnect; full re-sync when the log window is exceeded
- Distributes schema from PostgreSQL to clients so local SQLite databases stay consistent
- Synchronizes file content on a separate channel from row data, with chunking, hashing, and resumability
- Enforces authorization on every read and write, derived from PostgreSQL RLS policy

The system does **not**:

- Provide a query language or ORM — clients write queries against their local SQLite
- Replace PostgreSQL as the source of truth — the server database is authoritative
- Manage UI state or application routing
- Guarantee strong consistency at the client — clients operate against a local replica that may lag

---

## Big-Picture Data Flow

```
┌──────────────────────────────────────────────────┐
│  Client (edge / browser)                         │
│                                                  │
│  ┌──────────┐   mutations    ┌────────────────┐  │
│  │  Local   │ ─────────────▶ │   Sync Client  │  │
│  │  SQLite  │                │                │  │
│  │          │ ◀───────────── │  (worker /     │  │
│  └──────────┘   row updates  │   background)  │  │
│                              └───────┬────────┘  │
└──────────────────────────────────────│───────────┘
                                       │  WebSocket / transport
┌──────────────────────────────────────│───────────┐
│  Server                              │            │
│                                      ▼            │
│  ┌────────────┐    ┌───────────────────────────┐  │
│  │ PostgreSQL │    │      Session Manager       │  │
│  │            │    │  (one session per client)  │  │
│  │  (source   │    └─────┬──────────────────────┘  │
│  │  of truth) │          │                        │
│  │            │    ┌─────▼──────────────────────┐  │
│  │  CDC / WAL │───▶│      CDC Fanout Engine      │  │
│  │            │    │  (subscription matching,    │  │
│  └────────────┘    │   auth filter, delivery)   │  │
│                    └────────────────────────────┘  │
└───────────────────────────────────────────────────┘
```

**Mutation path** (left → right → up):
1. Client writes to local SQLite optimistically
2. Client queues mutation and sends it to server
3. Server validates, applies, and acknowledges or rejects
4. Server-side change triggers CDC

**CDC push path** (down → right → up):
1. PostgreSQL emits a WAL/logical replication event
2. CDC engine matches the event against active subscriptions
3. Authorization filter removes rows the client cannot see
4. Relevant clients receive the update and apply it to local SQLite

---

## Open Questions

1. What is the initial target transport — WebSocket only, or also HTTP long-poll / SSE for environments where WebSocket is restricted?
2. Should the client and server crates live in this repository or in separate crates published independently?
~~3. Is the initial target native clients, WASM/browser, or both simultaneously?~~

---

## Decisions

**Transport: WebSocket only.** HTTP fallback (long-poll / SSE) is not planned. Legacy transparent proxies are a non-issue with `wss://`. Serverless runtimes are architecturally incompatible with the system — no persistent process means no subscription state, no CDC listener, no session registry.

**Client targets: native and WASM simultaneously.** The immediate consumer is a Dioxus application. Dioxus targets both native and WASM from the same codebase, so the trait boundaries between the sync engine and I/O adapters must be correct from the start.

---

## Notes

- "Edge client" and "frontend client" are used interchangeably; the architecture is the same for both native and browser targets with WASM-specific abstractions handled separately (see `09-wasm.md`).
- The server is not a proxy — it is an active participant that owns subscription state and authorization.
