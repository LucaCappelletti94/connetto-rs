# Architecture index

What each chapter owns, so a reader starts here rather than following mentions between chapters. Add a line when you add a chapter.

The numbering records the order chapters were written, not a reading order and not a dependency order. Read `00` first, then whichever chapter owns the question you have.

## Chapters

| Chapter | Owns |
|---|---|
| `00-overview.md` | What connetto is, what it does not do, and the vocabulary the other chapters use |
| `01-pieces.md` | A catalogue of every component that must exist, and the seven crates in the workspace |
| `02-protocol.md` | How client and server talk: the two planes, the framing, the message types, and the sequencing rules |
| `03-sync-pipeline.md` | How writes travel to the server and how server-side changes travel back |
| `04-subscriptions.md` | How a client declares interest in data, and the life of a subscription |
| `05-aggregate-queries.md` | Counts, sums and grouped results, which are a different problem from row subscriptions |
| `06-reconnect.md` | Going offline and coming back: resume, catchup, the oplog and its retention window |
| `07-file-sync.md` | File content sync, which connetto does **not** build. Retained as the record behind that decision and as input to the exploratory integration phase R24 |
| `08-authorization.md` | Which caller may see which row, on reads, on changes and on writes. The two executors and the revocation path |
| `09-wasm.md` | Running the client in a browser: the worker topology, storage, and what the platform does and does not offer |
| `10-subscription-materializer.md` | The server component that hosts `subql` and turns its per-consumer output into per-session wire output |
| `11-authentication.md` | How a caller proves who it is, from login to a verified identity bound onto a session |
| `12-identity-session-capability.md` | **The canonical chapter for identity.** The three concepts, what each keys, the status-marker discipline, and the threat model that bounds the encryption design. It governs where other chapters disagree with it |
| `13-client-connection.md` | The client-side Diesel connection, reactivity, and the two framework adapters |
| `14-at-rest-encryption.md` | The replica page codec, key custody, ordering constraints, and what the encryption does and does not defend |
| `15-replica-retention.md` | Why the replica grows, and eviction and physical trimming. **Decided, not built**, and blocked on upstream diesel work |
| `16-server-capacity.md` | What the server holds in flight at once, the two connection pools, and the share reserved for identified callers. **Decided, not built** |
| `17-fan-out.md` | How one change event reaches many subscribers: the unit of computation, what stays proportional to subscriber count, catchup, and what adopting the shape costs. **Decided, not built** |

## Not chapters

| File | What it is |
|---|---|
| `open-questions.md` | Every question ever raised, with its recorded decision. The index of record for what is settled |
| `subql.md` | A tracking document for responsibilities connetto's decisions have assigned to `subql`, and whether each has shipped |
| `architecture-diagram.svg` | A picture of the whole, coloured by build status |

## Two conventions that apply to every chapter

**Every normative statement carries a status marker**, one of `Built`, `Built, defective`, or `Decided (RN)` naming a phase in `plans/master-implementation-plan.md`. A chapter may not claim a mechanism exists without either marking it built or naming the phase that builds it. Table cells carry markers too. The convention is defined in `12-identity-session-capability.md`.

**Citations name a file and a symbol, not a line number**, because line numbers rot silently and several in this repository already had.
