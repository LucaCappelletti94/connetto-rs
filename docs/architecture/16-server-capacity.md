# 16: Server capacity and admission

**Status**: normative, and short by intent. Paragraphs marked **Built.** describe what exists today. Every normative statement is marked **Decided**, naming its phase in `plans/master-implementation-plan.md`. The reservation this chapter decides is unbuilt, and three of its inputs are undecided and named as such at the end. The survey behind the decisions is `docs/research-overload-and-fairness.md`, a process artifact carrying a citation per claim.

---

## Not rate limiting

`02-protocol.md` owns rate limiting, which bounds what one caller may ask for over time and answers a caller that asks too often. This chapter owns admission, which bounds what the server holds in flight at once and answers a caller arriving when there is no room. The two are independent. A caller can be inside every rate limit and still find the server full, and a caller can be over its limit while the server sits idle.

They also fail differently, which is why they are separate mechanisms rather than one. A rate limit has to recognise the caller, so a caller that discards its name escapes it. Admission only has to count, so nothing escapes it.

---

## The two pools

**Built.** The server builds two Postgres pools through one helper, `build_pool` in `crates/connetto-server/src/bin/connetto-server.rs`, and gives neither a size, so both take bb8's default of ten connections.

The **owner pool** connects as the deployment's owning role and carries re-execution (`PgAsyncDieselConnector`), the authentication store (`DbAuthStore`) and audit writes (`pg_audit_hook`). Row-level security does not apply to it, which is the entire reason a second pool exists.

The **reader pool** connects as a role that row-level security does apply to, and the binary refuses to start without it (R1, see `08-authorization.md`). It carries everything a caller's own request touches: every visibility question (`RlsAuth::visible`), every snapshot read (`PgSnapshotSource`), every mutation apply (`pg_write_target`), and the durable watermark read that `run_handshake` performs before any handshake can complete.

**The reader pool is therefore the contended resource**, and what contends for it is callers rather than connetto's own background work.

---

## What contention costs today

**Built, defective.** `08-authorization.md` records the cost per unit and names it the current scalability wall: one visibility question takes a pooled connection, opens a transaction, binds the caller, runs a `SELECT EXISTS` and commits, and these are awaited one after another across watchers. That is not restated here.

What this chapter adds is the consequence at the pool. Nothing distinguishes callers at checkout, so unidentified and signed-in traffic contend first-come-first-served for the same ten connections, and a caller opening connections in a loop competes on equal terms with one that signed in.

---

## Reserving for identified callers

**Decided (R39).** A share of the reader pool is held for callers whose handshake resolved an identity. Unidentified callers may occupy the total less that share and no more, so a connection remains reachable by an identified caller whatever volume of unidentified traffic has arrived.

The guarantee is arithmetic rather than behavioural. It detects nothing, has no threshold and no window, and keeps no state that decays. It needs no key for the caller, only the tier the handshake already established, which `Tier` in `crates/connetto-server/src/throttle.rs` carries to every limit call today.

**This is what reaches a caller a ban cannot.** A ban needs a durable name, and a caller presenting no resume credential is minted a fresh one every connection (R36, and `12-identity-session-capability.md` for what a handle is). A reservation never asks who is calling, so the number of identities a caller cycles through does not enter into it. No source surveyed closes that gap by detection, and the literature treats it as a load problem rather than an abuse problem.

**Built (R36, 2026-08-06): what a caller with no identity gets instead is a per-connection tally.** Three refusal counts within one socket, no window because the connection is the window, and the outcome is that socket closing with no durable record and nothing reported to the application. It ends a runaway loop inside the connection it is happening in and nothing more, since a reconnect starts over. The gap this chapter names is therefore narrower than it was and still open: a prober that reconnects between crossings stays invisible, and only the reservation below bounds it.

---

## Why a reservation rather than a cap on the unidentified tier

**Decided (R39).** Two shapes were rejected, both recorded because each is the obvious reach.

**A quota shared across unidentified callers** is refused: one caller exhausting it switches off anonymous access for every legitimate visitor, and anonymous read access is a supported feature rather than a residue. The narrowness matters. A shared bucket is not wrong in general, and Google's own per-customer quota example ends with one covering every caller it cannot attribute. It is wrong here because the tier is a product.

**Requiring an identity before any action that could be counted** is refused for the same reason. It trades away the tier itself.

A reservation sets no per-caller allowance at all. It does bound unidentified callers to the unreserved share, so it is not free, but that bound scales with whatever capacity exists rather than being a number picked in advance. The shape is Stripe's reserved fraction for critical requests, Netflix's percentage guarantee per request class, and Google's shedding by request criticality under measured utilization.

---

## What connetto does not do

**Decided (R19, R36).** Connetto never reads or acts on a network address. Volumetric defence belongs to the edge, and this is sourced rather than assumed: the Google SRE book puts address-keyed limits at the reverse proxy and global shedding at the load balancer, leaving the individual task only the job of protecting itself, while AWS and NIST place absorption further out still. No source surveyed assigns volumetric defence to the application.

Connetto's obligation is the narrow one, and the same book states it: a task provisioned for a certain rate should keep serving at that rate whatever excess arrives. Defeating the sender is somebody else's job.

**Challenge-based defences are unavailable rather than declined.** Proof-of-work and interstitial challenges need JavaScript running in a browser document. Connetto's transport is a socket that carries native clients too, so a challenge would deny the callers it cannot test instead of testing them.

**Nor does connetto fingerprint a caller. Decided (R36), examined on its own merits rather than inherited from the address decision.** The two were argued as one and only the address half had reasoning behind it, so the survey in `docs/research-client-fingerprinting.md` tested the other half. A TLS fingerprint is unavailable by construction, since JA3 and JA4 come from the ClientHello and only the process terminating TLS ever sees one, which connetto never does. It would not identify a caller in any case: a fingerprint names a library version, so every user of one browser build shares it, and spoofing it is a one-line library switch, which the caller it targets is the one most likely to make. Zero of eleven surveyed peer systems fingerprint an unauthenticated connection. Beyond effectiveness there is a shape argument: EDPB Guidelines 2/2023 place fingerprinting inside ePrivacy Article 5(3) with no general security exemption, so a default-on fingerprint in a library would transfer that exposure to everybody who deploys it.

**One address mechanism survives the forgeability argument and was still declined.** The PROXY protocol frames the client address in the TCP stream ahead of any HTTP, so a client cannot forge it when the backend is not directly reachable, and it needs neither TLS termination nor a vendor tier. It would have supplied a per-caller key for callers with no identity. It was declined on 2026-08-06 in favour of identities as the only key, with the reserve above bounding the rest. **The accepted cost:** connetto cannot tell two unnamed callers apart, so a slow, patient prober stays invisible to abuse detection however long it persists. That is a known limit of this design, not an oversight.

---

## Not decided

R39 settles these before any code, per the standing rule on under-defined sections.

1. **The size of each pool.** Both are a library default nobody chose, and a reserve cannot be carved out of a number that was never decided. The number should come from measurement, and R0 part B supplies the first piece of it, on 2026-08-07: **the change path is not what sizes the reader pool.** Visibility questions are issued one at a time by the single change-ingest task, so that path holds exactly one connection at any moment whatever the subscriber count, while turning it over roughly 1,700 times a second. What competes for the rest is per-caller work, snapshots and the handshake watermark read, which is what item 3 below is already about. R0 did not measure those, so the size itself is still open.
2. **Strict or work-conserving.** A strict reserve holds its share back even when no identified caller wants it, and guarantees availability immediately. A work-conserving one lets unidentified traffic use everything and engages the reserve only while an identified caller is waiting, wasting nothing but weakening the guarantee to however long in-flight work takes to drain.
3. **One reserve or several.** A snapshot read holds a connection far longer than a visibility question does, so a single count may be the wrong unit.
