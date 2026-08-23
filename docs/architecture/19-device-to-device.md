# 19: Device-to-device sync

**Status**: normative for the decisions it records. Nothing in this chapter is built yet: every statement carries **Decided (RN)**, where `RN` is the phase in `plans/master-implementation-plan.md` that builds it. The design was settled and adversarially reviewed on 2026-08-21 and derived into phases R74 to R80 on 2026-08-22; the R25 section of the plan records every decision with its rejected alternatives, and the review that amended the design in place.

---

## Purpose

**Decided (R25).** Several people collaborate offline on tasks. The driving case is sample collection in the wild: a team in the Amazon basin with zero internet, mixed iPhone and Android fleets, camera media, and days of irreplaceable observations. Their devices hold overlapping replicas and today cannot exchange anything, because every path assumes the server: the exactly-once watermark is keyed on a server-minted handle, cursors are positions in the server's change log, and change-path authorization is answered server-side.

## Semantics: provisional, the server adjudicates

**Decided (R25).** What peers build offline is provisional, and the server still adjudicates when connectivity returns. The alternative, a peer-authoritative CRDT mesh with the server as just another peer, was rejected because it replaces server-wins, the single Postgres-authoritative log and the change-path authorization model, and no surveyed system keeps a logical-replication core under one.

Stated so nobody oversells it: an offline edit can be reversed later by the server's verdict, a right the local policy cannot answer blocks the write instead of guessing, two people editing the same row offline get one locally visible version with the displaced author recorded (one row per key exists, the server orders the truth later), and nothing here serves collaboration between strangers who were never online together with the same deployment.

## Trust: device identity and certificates

**Decided (R74).** While online and authenticated, a device generates an Ed25519 keypair (the private key beside R41's stores on the same custody backend behind the R23 gate, as its own record type, never inside `ReplicaKeyStore`) and the server signs an X.509 certificate binding the public key to the account, returning it with the deployment CA certificate for offline peer verification. One certificate per account on the device, matching R42's model. The CA keypair is deployment-provisioned material checked at startup.

The lifetime is application-requested under a server ceiling and refused if over, the R4 pattern: an expedition asks for its length, an office deployment for days, and renewal auto-runs on any connectivity past half-life. Lifetime IS the offline revocation lag, because peers cannot see a ban until the certificate dies. There is no human pairing ceremony (the CA and the policy check replace Syncthing-style fingerprint exchange) and no offline enrolment or sub-issuance (a server CA cannot mint in the field, and delegation is attack surface for marginal gain), so a device that never enrolled is a spectator until it meets the server once.

## One exactly-once domain: the per-device applied frontier

**Decided (R75), and it reshapes the R2 watermark contract.** Every write carries its durable identity, the pair of the author's device key and its pending-queue sequence. The server keeps one applied frontier per device key, and the normal reconnect path, the courier path and an archive restore all consult it; the session watermark becomes a cache of the frontier rather than a second truth. A collision at one (key, sequence) is first-seen-wins, audited, the second refused: the Secure Scuttlebutt fork rule, adopted after the review mapped SSB's known fork condition onto archive restore. An archive import therefore always retires the archived device's enrolment and mints a fresh key, with restored entries carrying their original identity as provenance so the frontier deduplicates the logical writes across the restore. The pending queue refuses at capacity instead of evicting its oldest, because an evicted entry would leave provisional copies on peers that can never be confirmed or retracted.

## Transport

**Decided (R76).** The data plane is the local network: discovery by gateway-probe first (a hotspot host IS the gateway, so clients need no multicast to find it) with mDNS as the general case under the service type `_connetto-peer._tcp.local`, then mutual TLS over plain TCP with both sides verifying against the deployment CA. Native targets only: browsers cannot take the listening role on any radio path and keep the server path. The TXT record carries the protocol version and a certificate fingerprint only, never an account identity, and discovery is treated as fully public with authentication happening only at the handshake.

Field facts the decision rests on: a hotspot host is a member of its own network (Android `192.168.x.1` via `LocalOnlyHotspot`, app-startable with no SIM service; iOS `172.20.10.1`, manual toggle, carrier-gated, zero-coverage start unverified until R80's field test), Android multicast reception needs a `MulticastLock`, iOS 14+ prompts for local-network permission, in a mixed fleet the Android device hosts, and a battery travel router removes every hotspot caveat. A BLE advertise-only beacon ("join my hotspot") is the recorded later bootstrap; a full BLE data plane is never promised, the crate landscape being pre-1.0 and single-maintainer, and Noise returns to the cipher table only if that plane ever exists.

## The exchange

**Decided (R77).** Each device offers its own pending queue, entries signed by its device key, direct exchange only, no relay and no gossip: a camp group on one network is small and fully pairwise. Per peer, a device keeps the highest sequence received, and an exchange is: mutual offer of queue bounds plus the acked frontier plus the retraction log, request from cursor plus one, signed changesets streamed in order, cursor advanced in the same transaction as the apply.

Cleared sequences need no tombstones, with one repair: an acked row reaches a peer through ordinary subscription delivery only where the peer's subscriptions cover it, so each exchange carries the author's acked frontier, and provisional rows at or below it are marked adjudicated and fall under ordinary coverage. Refusal keeps its own signal: a signed retraction log of refused sequences with their `MutationRejectReason`, and a retraction removes the peer's provisional copy. The author is authoritative over its own queue's fate.

Offline authorization is the translated replica policy evaluated with the author's identity bound, through a rebindable evaluator, failing closed on OpenFGA-derived and locally unanswerable rights. Two limits are part of the contract: the answer is computed on the receiver's partial replica, so an absent membership row produces a false deny (fail closed, accepted), and an offline-stale replica can produce a bounded false allow, the same staleness class as certificate revocation lag.

## The provisional tier

**Decided (R77).** Peer-applied rows live in the ordinary replica tables so the application's own SQL sees them, with provenance beside them in the device-private tier keyed by table and key: author identity, author device, received-at, state. Peer applies suspend capture exactly as server patches do, or a peer's write would re-upload as the receiver's own. Eviction spares provisional rows through their own spare clause beside the pending one. The conflict rule is explicit: the receiver's own unsent write is never displaced, any other collision applies last-writer-locally with the displaced author recorded, and server-wins stays reserved for server patches. Server-sourced data writing a key clears its provenance record. The client exposes typed provenance reads and applied, confirmed and retracted-with-cause events; presentation is the application's.

**Aggregates do not follow, stated so nobody expects it (added by the 2026-08-22 review).** Server-computed aggregate values (`LiveValue`) are pushed by the server and freeze while offline, so they reflect neither the device's own unsent writes nor peer-applied provisional rows, and they catch up only when connectivity returns and the server has adjudicated. An application showing counts or sums over provisional data derives them from the rows with its own local queries, which see the provisional tier by construction.

## Media over the link

**Decided (R79), the join point with chapter 18.** Metadata rows travel in the exchange like any rows, thumbnails are ordinary derived files a peer prefetches over the link (instant at their size), and full content is pull-on-demand by chunk hash: the author's device answers after evaluating the requester against its translated policy fail-closed, the receiver verifies against the hashes the signed row carries, re-encrypts under its own key, and stores in the never-exported cache class. The application can additionally mark content for replication to present peers, the survivability half of couriering.

## Field survivability: courier recovery

**Decided (R78), deployment-opt-in, default off.** A lost device's work is recoverable from the camp: the server accepts author-signed changesets from any certified bearer, deduplicated by the same frontier every path consults. The boundary is cryptographic, not trusted. The courier authenticates as itself and can only relay verbatim what the author's device key signed; its own document rights are never consulted; what a malicious courier can do is withhold (no worse than not couriering, with sequence-gap refusal preventing reordering) and delay (no worse than the author's own delayed reconnect, policy evaluated at apply time). Five constraints ride with the path because it is the first place session identity and write author differ: opt-in default off, a distinct `auth_events` record per couriered application naming courier and author, per-courier metering, refusal of revoked enrolments, and author notification on next login. Signatures carry no trusted timestamp, so acceptance is governed by the account's and enrolment's standing at apply time, with certificate expiry gating only peer trust in the field.

## The archive

**Decided (R75, R77).** Provisional rows and all peer bookkeeping (provenance, cursors, the retraction log) travel in the R26/R56 archive because they live in the tiers it already carries, so a restored device resumes exchanges correctly. Peer-fetched cache chunks stay out, and the archive is not the survivability mechanism, the courier path is. The one archive rule the frontier adds: an import retires the archived enrolment and mints a fresh device key.

## Phases

R74 device identity and certificates, R75 the per-device applied frontier, R76 the peer link, R77 the exchange and provisional tier, R78 courier recovery, R79 media over the link, R80 the demos and the iOS hotspot zero-coverage field test. R77's retraction reason rides on R57's fix of the client-side `MutationRejectReason` drop, and R79 needs the file phases R64 to R67.
