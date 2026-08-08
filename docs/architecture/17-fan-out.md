# 17: Fan-out

**Status**: normative. This chapter owns how one change event reaches many subscribers: the unit of computation, what stays proportional to subscriber count, catchup, and what adopting the shape costs.

**Read the marker convention first.** Every normative statement below carries `Built` or `Decided (RN)`, per `12-identity-session-capability.md`. R16 part B is a design phase, so a `Decided (R16 part B)` marker means settled and **not** built, with no phase yet assigned to build it. Deriving those phases from this chapter is the next step and is recorded against R16 in `plans/master-implementation-plan.md`. Where an existing phase already owns a piece, that phase is named instead.

---

## Purpose

`08-authorization.md` used to assert that delivery is K messages for K subscribers "and always will be". R16 part A checked that against six shipping systems and found it half true. This chapter is what replaces the assumption: the shape connetto aims at, stated concretely enough that a phase can be written from it.

The evidence lives in `08-authorization.md` under "The per-client floor" and is not repeated here. One line of it is load-bearing throughout: the floor is one socket write per client, of bytes that need not be distinct, computed, encoded, or copied per client.

---

## The measurement this design targets

**Built (R0 part B), measured 2026-08-07.** Postgres 16 in Docker, release build, ten-second windows, `connetto_test_harness::fanout::fanout_load`.

| | 10 subscribers | 100 subscribers |
|---|---|---|
| events per second delivered | 170.0 | 17.0 |
| deliveries per second | 1,700 | 1,700 |
| materializer lock takes per event | 12 | 102 |
| materializer lock wait | 0 ns | 0 ns |
| payload bytes copied per subscriber per event | ~39 | ~39 |

Three readings, and the design rests on these rather than on arithmetic.

**The ceiling is one quantity**, the rate at which sequential visibility round trips complete, roughly 590 microseconds each. Deliveries per second are identical across a tenfold change in subscriber count, which is what identifies the round trip as the whole ceiling rather than one contributor to it.

**The materializer mutex is free, not merely cheap.** Only the change-ingest task takes it while delivery runs, so the `3 + K` acquisitions per event cannot contend. This is structural, not a lucky reading.

**Copy elimination buys nothing measurable at this row size.** Thirty-nine bytes per subscriber per event on a two-column row. The case for the frame split and the shared payload is that both scale with patch size, not that either shows up in these numbers.

---

## The unit of computation

**Decided (R16 part B): the unit is one change event.** Not one subscriber, and not one subscription. **Every computation a change requires happens once per event.** What remains per subscriber is a lookup, a verdict entry and a socket write, and none of the three recomputes anything the event already produced. The next section says which of them is inherent and which is merely accepted.

Per event, exactly once:

| Work | Status |
|---|---|
| One predicate evaluation per distinct interned predicate, with matched consumers resolved from a bitmap | **Built**, `subql` interns by a hash of normalised SQL and refcounts |
| One patchset build and one Zstd compression | **Built**, `Materializer::dispatch` |
| One visibility answer naming every watcher of the event | **Built (R5a)**, `subql::visibility::VisibilityPolicy::may_see` |
| One oplog append | **Built**, `SessionManager::dispatch_event` |
| One frame built, header and body together | **Decided (R16 part B)** |

Per subscriber, and nothing beyond this:

| Work | Status |
|---|---|
| One route lookup | **Built** |
| One verdict entry, filled by the single per-event call | **Built (R5a)** |
| One socket write, carrying shared bytes | **Decided (R16 part B)** |

The reason the unit is the event rather than the subscriber is that a change event is the only thing in the system that happens once. A subscriber is a destination, not a computation, and every layer that treated it as one has been eliminated by at least one system that ships.

---

## What stays proportional to subscriber count

Stated explicitly, because the phase exists to replace an assumption with an account.

**The socket write. Inherent.** Bytes must reach each client and no studied system escapes it, including the one that relocates the writes to a CDN. Accepting it is not a concession: it is the floor, and reaching it is the whole objective.

**One verdict per watcher. Accepted.** `may_see` fills a vector with one entry per watcher, so the answer is proportional to watcher count even when computing it is not. **Decided (R5b)**: tier 1 answers by set-membership of the row's derived subject against the watcher list with no round trip, and tier 2 asks once per distinct group the row grants to. Both are local tests per watcher over a bounded number of round trips. Tier 3 is the exception and its cost does grow with subscribers, accepted there because a relation that spans, intersects or subtracts across tables has no local answer and refusing to serve such a policy would be worse than serving it slowly.

**One route lookup per matched consumer. Accepted.** A hash lookup against `routes`, which is not the kind of cost this chapter exists to remove.

**One payload copy per subscriber, until two things move together.** `tokio-tungstenite` is pinned at 0.24, where `Message::Binary` takes an owned `Vec<u8>` (verified in `tungstenite-0.24.0`, `protocol::message::Message`), so the frame handed to each socket is an owned contiguous buffer. See "Reaching zero copies" for why the version bump alone does not fix this.

**What stops being proportional**: computation, compression, frame encoding, authorization round trips, and (once the two items above move) payload copies.

---

## The frame

**Decided (R16 part B), and this is recorded as a fix rather than a change.** A bulk frame becomes the tag, a short encoded header, then the compressed payload appended untouched. Two records already describe that shape: the bulk-plane row in `02-protocol.md` gives the encoding as Zstd-precompressed opaque bytes, and the module comment on `crates/connetto-core/src/messages/bulk.rs` says the payload is carried so the transport never re-compresses it. The code disagrees with both: `encode_bulk` runs `rmp_serde::to_vec_named` over a `BulkMessage` whose variants embed the payload as a field, so every send copies the payload into a MessagePack buffer and then again into the tagged frame.

Layout, on a message-delimited transport where the frame boundary is the WebSocket frame:

```
[ 1 byte: tag ][ 4 bytes: header length, big-endian u32 ][ header ][ compressed payload ]
```

The header is a MessagePack-encoded enum mirroring `BulkMessage`'s variants with the payload field removed, so it carries the subscription handle and the cursor on a live patch, the handle alone on a snapshot patch, and the client sequence on a mutation patch. On a byte-stream transport `encode_bulk_framed` wraps the same three parts in the existing outer length, so the length-prefixed pair needs the identical split and nothing else.

**Consequences, all of them accepted.** Four decoder sites change, and all four are today the identical two lines that split the tag and call `decode_bulk`: `WebSocketTransport::recv` in `crates/connetto-core/src/transport.rs`, and the `recv` on each of `BrowserSocket`, the broadcast transport and the port transport in `crates/connetto-web`. `decode_bulk` keeps its signature and performs the split internally, so those four sites change only if they stop paying for a copy. `BulkMessage` stops being a plain serde round-trip, so the wire round-trip test is rewritten rather than adjusted. The upload path benefits identically, which was not the motivation.

**No browser client makes this more expensive. Verified against the tree.** None of the four decoders inspects the payload. The one browser participant that reads a bulk payload structurally is the relay: `patch_tables` in `crates/connetto-web/src/relay.rs` decompresses each upstream patch once to learn which tables it touches, then re-frames it per tab. That decompression is per upstream patch and independent of frame layout, and the per-tab re-framing currently copies the payload once per tab, so the relay is a second fan-out with the same shape and the same saving available to it.

### Copies per subscriber per event

| Stage | Today | After the split and the shared payload | After a shared frame |
|---|---|---|---|
| Clone into `MatchedPatch`, `Materializer::dispatch` | 1 | 0, shared handle | 0 |
| MessagePack encode embedding the payload, `encode_bulk` | 1 | 0, the body is not encoded | 0 |
| Concatenate into the tagged frame, `send_bulk` | 1 | 1 | 0, built once per event |
| **Total** | **3** | **1** | **0** |

---

## Subscription identity

**Decided (R16 part B): a data frame carries a server handle derived from the question, not the name the client chose.** The client keeps its own name and the subscribe reply maps it to the handle. This is ElectricSQL's shape handle and Zero's transformation hash expressed in connetto's terms, and it is what makes two clients' frames capable of being identical at all: a client-chosen name (`sub_id` in `crates/connetto-core/src/messages/subscription.rs`, documented as client-chosen and unique per session) guarantees they never are.

**It needs nothing upstream.** `subql`'s `RegisterResult` already returns `predicate_hash` and `created_new_predicate` (verified in `src/types.rs` and `src/runtime/engine.rs` at the pinned revision), and `Materializer::register_request` in `crates/connetto-server/src/materializer.rs` discards both, keeping only the subscription id. The signal is handed over on every registration and dropped one line later.

**What the client gives up: nothing on the bulk plane.** Verified against the tree. The client never routes a bulk frame by the name: the `SnapshotPatch` and `LivePatch` arms of `ConnettoConnection::next_event` both apply the patch to the one replica, and the name only rides out as a label on `ClientEvent`. The relay already discards the upstream name, destructuring `ClientEvent::LivePatch { cursor, patchset_zstd, .. }` and choosing each tab's own subscription by table intersection. The one load-bearing use of the name on the receive path is a control frame, `FullResyncRequired`, which drives `clear_subscription_rows`, and control frames are untouched by this chapter. **Updated 2026-08-08 (R29):** that function no longer reads an in-memory table map. It resolves the resyncing subscription and its siblings from the subscription set persisted in the replica, so the name has to match a stored subscription id rather than a key in a map that a restart emptied.

**Per-subscription cursors are not load-bearing today, and this chapter does not make them so.** The client persists exactly one cursor: `_connetto_meta` is declared `CHECK (id = 1)` and every live patch overwrites it whatever its subscription, so `persist_cursor` and `load_cursor` in `crates/connetto-client/src/lib.rs` maintain a single session-level resume point. The handshake carries one cursor, folded to one `resume_lsn` that every re-declared subscription replays from. Server side, `Materializer::advance_cursor` writes a per-`(session, subscription)` cursor into `subql`, which does expose `cursor_for` and `cursors_for_session`, and connetto calls neither. The only observable effect of that bookkeeping is `subql`'s non-monotonic rewind error. Recorded because a reader can go and find the per-subscription state still being written, and would otherwise assume something depends on it.

---

## Frames shared across clients

**Decided (R16 part B): one frame per distinct pair of handle and event, cloned per socket.** A live frame's three parts are then all shared. The handle is derived from the question. The cursor is already per event rather than per client: `Materializer::dispatch` stamps every `MatchedPatch` with the same value taken from the event's checkpoint. The payload is already computed once. So the whole frame, tag included, is identical for every allowed subscriber on that handle, and a subscriber the verdict denied simply does not receive it.

**Nothing in this mechanism waits on R5b.** The shape it needs is R5a's and is already in the tree: `may_see` takes one row and every watcher and returns one verdict each, so the partition over subscribers exists today. R5b changes how cheaply that partition is computed, not what it is. **No permission-class identifier has to be invented**, which is what the sequencing record expected to be the blocker.

**R5b decides whether it pays, and that is a real gate.** With the per-subscriber round trip in place at roughly 590 microseconds, a saved header encode is noise. Two clients on one handle who fall on different sides of the verdict for a given row still share nothing for that row, which is `08-authorization.md`'s property 4 stated from the delivery side: sharing applies to the allowed subset, and its value is proportional to how often that subset has more than one member.

### Reaching zero copies

**Decided (R16 part B), and it corrects the process record, which said one copy was the floor until the transport dependency moved.** The dependency bump is necessary and not sufficient. `tungstenite` 0.28 changes `Message::Binary` to take `Bytes` (verified in `tungstenite-0.28.0`, `protocol::message::Message`, and that version is already in this workspace's lock file through `dioxus-devtools`, so nothing in the ecosystem blocks it). But `Message::Binary` takes one contiguous region, so a per-subscriber header ahead of a shared body still forces a per-subscriber concatenation that copies the body. **Zero copies therefore needs the handle, the shared frame and the transport bump together**, at which point the one frame is built once per event, held as one `Bytes`, and cloned per socket for a refcount bump.

Sending the header and the body as separate WebSocket continuation fragments would avoid the concatenation without the handle. Declined: `tungstenite` does not expose fragmentation through `Message`, and it would put a cross-frame sequencing rule on the wire to save a copy that the handle removes anyway.

---

## Payload ownership

**Decided (R14): the compressed payload is held by shared reference, as `Arc<[u8]>`, with no new dependency.** R14 step 3 owns this, and R16 part A already corrected that step's speculation about needing an upstream change: `subql`'s `pgoutput_patchset` returns an owned `Vec<u8>` (verified in `src/emit.rs` at the pinned revision), so wrapping it costs nothing and changes no `subql` signature. The type flows through `MatchedPatch`, the bulk message variants, and the `Transport` trait.

**`Arc<[u8]>` is precedent here rather than a new convention.** `ClientEvent::LivePatch` in `crates/connetto-client/src/lib.rs` already carries `patchset_zstd: Arc<[u8]>`, for exactly this reason, so a relay can forward without re-encoding.

**And it does not foreclose the zero-copy send.** `bytes::Bytes::from_owner` accepts any `AsRef<[u8]> + Send + 'static` owner and takes ownership without copying (verified in `bytes-1.12.1`, which is already in the lock file), and `Arc<[u8]>` satisfies that bound. So after the transport bump the frame is converted once per event and cloned per socket, and `connetto-core`'s public types never grow a `bytes` dependency.

---

## Catchup

**The one finding from part A with no home in the plan, and this chapter is its home.** `SessionManager::catch_up_row` in `crates/connetto-server/src/session.rs` calls `Materializer::encode_patch` per record per subscription, which rebuilds the patchset from the stored event and re-compresses it, for bytes that were already built when the change was live. No studied system does this, and the closest comparable one does the exact inverse: ElectricSQL encodes each shape log line once at append time and never again.

**Decided (R16 part B): the oplog stores the prepared compressed patch beside the event, and catchup streams the stored bytes.** `encode_patch` leaves the catchup path. This is the inversion, applied.

**The event stays. Storing the patch instead of it does not work**, because catchup needs the structured event twice per record and neither use is the one being replaced: `Materializer::match_row_consumers` decides whether the subscription matches, and `EventRow::current` supplies the post-image for the visibility question.

**So oplog storage grows on both backends, and the process record said otherwise.** `plans/fanout-architecture-decisions.md` expected Postgres storage to fall, reasoning that `PgOplog::append` writes `serde_json::to_vec(record.event())` and would write compressed bytes instead. That describes replacing the event, which the paragraph above rules out. The Postgres row keeps its JSON event and gains a patch column, and `InMemoryOplog` keeps its `ChangeEvent` and gains the patch on the heap.

**Decided (R16 part B): `OplogConfig` gains a byte bound, on by default, and connetto logs which bound pruned.** The window is bounded today by entry count and age alone (one million entries or seventy-two hours, `06-reconnect.md`), and neither notices row width. At the thirty-nine bytes R0 measured for a two-column row a full window of patches is tens of megabytes, and at a few kilobytes per row it is gigabytes. The failure mode of a bound set too small is extra full snapshots rather than lost data, because a resume point that has fallen off the front of the log already draws `FullResyncRequired`, which is a working path. That is precisely why the log line is part of the decision and not a nicety: extra snapshots look like a client defect and are actually a retention setting. The default value has no measurement behind it and is a starting point, not a finding.

**This is a memory bound and not an abuse defence.** The oplog holds one entry per change event, appended once regardless of who is watching or how many, so a caller cannot enlarge it by connecting. Only a writer to Postgres adds entries, and a writer already permitted to write can fill Postgres itself.

**Not the client replica.** `15-replica-retention.md` opens by disclaiming the server oplog, and this section constrains nothing in that chapter. The two share a word and nothing else.

### The subscription must outlive its socket

**Decided (R16 part B), and the previous decision does not work without it.** `Materializer::dispatch` builds a payload only when at least one consumer matches, the oplog appends unconditionally, and teardown destroys the subscription the instant the socket closes. So a change arriving while a client is briefly offline matches nothing live, is appended with no payload, and that client is exactly who will ask for it. A subscription therefore outlives its socket by the same window the log retains, then expires. The predicate and its binding stay in the dispatch set, matching changes still build a payload, and no fallback rebuild path is needed.

Today the two lifetimes contradict each other: the log promises a delta for a client that was away, while the subscription defining what that delta is was destroyed the moment it left.

**It needs nothing upstream.** `subql` already models the distinction as `SubscriptionScope::{Durable, Session}` (verified in `src/types.rs` at the pinned revision, `Durable` persisting until explicitly unregistered and `Session` auto-removed when the session ends), and connetto uses neither, so every subscription is implicitly durable and connetto destroys it by hand. The lifetime policy is entirely connetto's.

Three consequences, none optional:

- **Teardown splits.** `remove_route` and `unregister` happen together at three sites in `SessionManager` today: connection teardown, an explicit unsubscribe, and a failed subscribe. The route must still drop immediately, and only the subscription defers.
- **An expiry sweeper**, keyed to the retention window, which does not exist.
- **A registry cap**, because the registry is uncapped and retained subscriptions make a disconnect storm unbounded. `subql`'s `max_subscriptions` defaults to `None`, documented as growing unbounded, and connetto never calls `with_max_subscriptions`. `EvictionPolicy::EvictBySession` is the policy to evaluate if connetto starts declaring a scope.

A retained registration produces a `MatchedPatch` on every matching event, discarded immediately by the route lookup miss. With the payload shared that is a refcount bump rather than a copy. Retained state is one parameter binding per recently-disconnected subscriber, sharing one compiled predicate, because `subql` separates the two.

### What catchup does not get

**Catchup frames are not shared across clients, and that is correct rather than a gap.** Two clients resuming from different positions receive different sequences, so the sharing above has nothing to key on. Catchup gets the copy elimination and not the frame sharing.

**And it still pays two costs per record per client**, neither addressed here: one predicate match, and one visibility question. **Decided (R5b)** makes the second free in tier 1. The first is `subql`'s interned-predicate evaluation and is left alone.

---

## The materializer lock

**Decided (R16 part B): hoisting the per-subscriber cursor advance out of the fan-out loop is worth nothing, and is not carried as a live improvement.** R0 measured zero lock wait at both subscriber counts. That is structural: only the change-ingest task takes the lock while delivery runs, so the `3 + K` acquisitions per event cannot contend. R14 step 1 is known in advance to buy nothing and survives only as a guard against a hoist introducing contention where there was none.

**One case the measurement does not cover, stated so it is not read as more than it is.** `catch_up_row` takes the lock from a session task rather than from the ingest task, three times per replayed record. R0's fixture measures a steady-state dispatch window after routes have settled, with no client catching up, so a catchup storm concurrent with live dispatch is the one shape where the lock could contend and no number exists for it. The stored patch removes one of the three takes, which is a reason to prefer it and not a reason to claim a measurement.

**Sharding or removing the mutex is declined**, for now with no evidence behind it. Convex shards across a fixed manager count and ElectricSQL and Supabase run a process per shape or topic. Revisit if a measurement of concurrent catchup and dispatch shows contention.

---

## What it costs to get there

Part A established that nothing on the delivery side needs an upstream change, and every claim in the table below was re-verified against the pinned `subql` revision in the root `Cargo.toml`. So the cost is connetto's alone.

| Change | Where | Status |
|---|---|---|
| Bulk frame becomes tag, header length, header, body | `codec.rs`, `messages/bulk.rs` in `connetto-core` | **Decided (R16 part B)** |
| Header type mirroring the bulk variants without the payload | `messages/bulk.rs` | **Decided (R16 part B)** |
| Four decoders keep their shape, `decode_bulk` splits internally | `transport.rs`, and `lib.rs`, `broadcast.rs`, `port.rs` in `connetto-web` | **Decided (R16 part B)** |
| Length-prefixed pair takes the same split, wire round-trip test rewritten | `codec.rs`, `connetto-core/tests/wire.rs` | **Decided (R16 part B)** |
| Payload as `Arc<[u8]>` through `MatchedPatch`, the bulk variants and `Transport` | `materializer.rs`, `connetto-core` | **Decided (R14)** |
| `Transport` gains a send taking an already-framed shared buffer | `traits.rs` in `connetto-core`, every transport impl | **Decided (R16 part B)** |
| Server handle derived from `predicate_hash`, returned on the subscribe reply, carried in the header | `materializer.rs`, `session.rs`, `messages` | **Decided (R16 part B)** |
| One frame built per handle per event, cloned per socket | `session.rs` | **Decided (R16 part B)** |
| `tokio-tungstenite` from 0.24, and the frame handed over as `Bytes` | `connetto-core/Cargo.toml`, `transport.rs` | **Decided (R16 part B)** |
| Oplog stores the prepared patch beside the event | `oplog.rs` | **Decided (R16 part B)** |
| `OplogConfig` gains a byte bound, and pruning names the bound that fired | `oplog.rs` | **Decided (R16 part B)** |
| `encode_patch` leaves the catchup path | `session.rs` | **Decided (R16 part B)** |
| Teardown splits, route immediate and subscription deferred, at three sites | `session.rs` | **Decided (R16 part B)** |
| Expiry sweeper on the retention window | `session.rs` | **Decided (R16 part B)** |
| Registry cap and eviction policy through `with_max_subscriptions` | `materializer.rs` | **Decided (R16 part B)** |
| Nothing | `subql`, `rls2fga`, `pg2sqlite`, `diesel` | verified |

**No protocol version bump.** `PROTOCOL_VERSION` stays frozen at 1 until the first release, so the frame shape changes freely and the new wire is simply the wire (`02-protocol.md`).

---

## What this design declines

- **A pull path.** `K1` in the sequencing record. Push only, over one WebSocket with a credit window. The trigger to revisit is a deployment needing more concurrent readers of one shared query than one server's socket budget allows, and `02-protocol.md` already contemplates an HTTP fallback and defers it.
- **Storing the patch instead of the event.** Ruled out above: match and visibility both need the event.
- **Per-subscription resume cursors as a client-visible capability.** Not built, not used, and this chapter does not add them.
- **Sharding the materializer mutex.** No evidence, and the one path that could contend has no measurement.

---

## Cross-references

- `08-authorization.md`: the per-client floor, the six-layer separation, and the five protocol properties this chapter implements. Also the R5b tiers that make the verdict cheap.
- `02-protocol.md`: the two planes and the framing this chapter changes.
- `06-reconnect.md`: the oplog, its retention window, and the catchup decision.
- `10-subscription-materializer.md`: the component that owns the fan-out and the boundary with `subql`.
- `15-replica-retention.md`: the client replica, which shares the word retention with this chapter and nothing else.
