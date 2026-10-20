# Architecture index

What each chapter owns, so a reader starts here rather than following mentions between chapters. Add a line when you add a chapter.

The numbering records the order chapters were written, not a reading order and not a dependency order. Read `00` first, then whichever chapter owns the question you have.

## Chapters

| Chapter | Owns |
|---|---|
| `00-overview.md` | What connetto is, what it does not do, and the vocabulary the other chapters use |
| `01-pieces.md` | A catalogue of every component that must exist, and the ten crates in the workspace |
| `02-protocol.md` | How client and server talk: the two planes, the framing, the message types, and the sequencing rules |
| `03-sync-pipeline.md` | How writes travel to the server and how server-side changes travel back |
| `04-subscriptions.md` | How a client declares interest in data, and the life of a subscription |
| `05-aggregate-queries.md` | Counts, sums and grouped results, which are a different problem from row subscriptions |
| `06-reconnect.md` | Going offline and coming back: resume, catchup, the oplog and its retention window |
| `07-file-sync.md` | The historical record behind the file-handling decisions. Superseded by chapter 18, which is normative where they disagree |
| `08-authorization.md` | Which caller may see which row, on reads, on changes and on writes. The two executors and the revocation path |
| `09-wasm.md` | Running the client in a browser: the worker topology, storage, and what the platform does and does not offer |
| `10-subscription-materializer.md` | The server component that hosts `subql` and turns its per-consumer output into per-session wire output |
| `11-authentication.md` | How a caller proves who it is, from login to a verified identity bound onto a session, and the app login an app-signed assertion buys a bot. **Decided, not built** for the app login, R91 |
| `12-identity-session-capability.md` | **The canonical chapter for identity.** The three concepts, what each keys, the status-marker discipline, the threat model that bounds the encryption design, and apps, bots and installations. It governs where other chapters disagree with it. **Built (R91)** for bots, lists and installations |
| `13-client-connection.md` | The client-side Diesel connection, reactivity, the two framework adapters, and the headless reactor and app credential. **Decided, not built** for the reactor, R91 |
| `14-at-rest-encryption.md` | The replica page codec, key custody, ordering constraints, and what the encryption does and does not defend |
| `15-replica-retention.md` | Why the replica grows, and eviction and physical trimming |
| `16-server-capacity.md` | What the server holds in flight at once, the two connection pools, and the share reserved for identified callers |
| `17-fan-out.md` | How one change event reaches many subscribers: the unit of computation, what stays proportional to subscriber count, catchup, and what adopting the shape costs. **Built** for the fan-out and the oplog's stored patches, **Decided (R16 part B), not built** for the shared frame and the byte bound |
| `18-file-handling.md` | File handling: identity, chunking, the encrypted stores, tickets, the availability convention, and the abuse surface. **Built through R68** (the core, the file server, the connetto seam, the native client and the browser client), with R69 the demos, R87 the quotas and R70's boot reconcile and healing built |
| `19-device-to-device.md` | Offline collaboration between devices: certificates, the per-device frontier, the LAN link, the exchange, the provisional tier, and courier recovery. **Built (R74)** for device identity, enrolment, revocation, issuer rotation, the client's half of the clock rule and the lost-key path, **Built (R76)** for the link, discovery, the Android hosting and joining, the beacon and the exchange, the text and QR fallback, the iPhone host and iPad join, the Linux hosting and joining and the Mac join, **Decided, not built** for Windows and R75 to R80 |
| `20-deployment.md` | What a deployment holds and what each backup method carries, what a restore to an earlier point does to connected clients (R70), and the failover recipe (R73). **Built** for the inventory, the chunk store, rows, logins and the authorization store, every adopted boot reconciling the whole OpenFGA store against Postgres |
| `21-clocks.md` | Which clock every timer and deadline reads, what each does across a suspend, and the skew two machines' wall clocks may have. **Built (R72)** |

## Not chapters

| File | What it is |
|---|---|
| `open-questions.md` | Every question ever raised, with its recorded decision. The index of record for what is settled |
| `subql.md` | A tracking document for responsibilities connetto's decisions have assigned to `subql`, and whether each has shipped |
| `architecture-diagram.svg` | A picture of the whole, coloured by build status |

## Two conventions that apply to every chapter

**Every normative statement carries a status marker**, one of `Built`, `Built, defective`, or `Decided (RN)` naming a phase in `plans/master-implementation-plan.md`. A chapter may not claim a mechanism exists without either marking it built or naming the phase that builds it. Table cells carry markers too. The convention is defined in `12-identity-session-capability.md`.

**Citations name a file and a symbol, not a line number**, because line numbers rot silently and several in this repository already had.
