<p align="center"><img src="logo.svg" width="180" alt="connetto-rs"></p>

# connetto-rs

[![CI](https://github.com/LucaCappelletti94/connetto-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/connetto-rs/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/LucaCappelletti94/connetto-rs/graph/badge.svg)](https://codecov.io/gh/LucaCappelletti94/connetto-rs)
[![Quality gate](https://sonarcloud.io/api/project_badges/measure?project=LucaCappelletti94_connetto-rs&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=LucaCappelletti94_connetto-rs)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Transport and sync layer that keeps SQLite replicas on native and browser clients in sync with one PostgreSQL database. Clients write to their local SQLite and read it with Diesel. Every write travels to the server, applies under the database's own row-level security, and comes back to every subscribed device as a change. Every read a client subscribes to, rows or aggregates, stays live from the database's change stream. The whole client state is encrypted at rest and survives going offline.

## What works today

| Area | Built |
|---|---|
| Sync loop | Optimistic local writes, server apply under Postgres RLS, change data capture through `subql`, live row subscriptions, reconnect with resume, catch-up from the change log and a forced resync past its window, replication slot lifecycle |
| Aggregates | `COUNT`, `SUM`, `AVG`, variance, grouped `GROUP BY` and `HAVING`, folded server-side per change. `MIN`, `MAX`, joins and row-shaped queries re-executed against Postgres under a read budget, per viewer on RLS tables |
| Identity | OAuth 2.0 and OIDC login with connetto as the backend-for-frontend, durable sessions with revocation, grants that authorize without identifying, capabilities for sharing a row at read or write level, an audit table, request throttling, abuse bans, a reserved pool share for identified callers |
| Authorization | Postgres RLS on every snapshot read and every write. On the change path the row policy is translated by `rls2fga` and answered locally or by OpenFGA, so a change reaches only the devices allowed to see the row as it was |
| Clients | A native Diesel connection with a background sync worker, a browser client on a dedicated worker over OPFS with every tab relaying through it, and `use_live` hooks for Dioxus and Yew |
| At rest | SQLCipher natively with OS keyring custody, `sqlite3mc` in the browser with IndexedDB custody and a passkey unlock gate, a device-private tier that never syncs, replica retention and trimming, several accounts signed in at once, a data wipe that removes everything the replica key opens |
| Portability | Export and import of a device archive, one entry in memory at a time, restoring the device tier, unsent writes and unsent content under another key |
| Files | Content-defined chunking with BLAKE3 identity and per-chunk encryption, a file server with a two-phase upload and ranged serving under tickets granted on the sync connection, and a client that keeps manifests, an outbox and pins in the replica, natively and in the browser |
| Schema | PostgreSQL DDL translated to the replica's SQLite DDL at build time by `pg2sqlite`, with fail-closed write guards and a manifest the client is refused without |
| Operations | Structured `tracing` logs on every crate, a Docker-backed test stack, browser suites under headless Chrome, and CI over the seven workspaces |

## Where it stands

The plan in `plans/master-implementation-plan.md` is the record. Its status table tracks 87 phases, 63 of them done and 24 open. Every core mechanism above is built and proven by tests, and the remaining work is the last mile around it.

| Remaining | Phases |
|---|---|
| Files in every demo, then storage quotas | R69, R87 |
| Native unlock gates and the mobile build of a demo they need | R51, R52, R53, R88 |
| One page codec on both targets, Linux key custody across a reboot | R21, R71 |
| Application schema majors, the shared public store, the portability download | R31, R11, R61 |
| Backup and restore, clock discipline, failover verification | R70, R72, R73 |
| The browser refresh token in an `HttpOnly` cookie, a failing re-execution read ending only its subscription, demo feature gaps | R90, R89, R57 |
| Device-to-device sync without a server, designed in chapter 19 | R74 to R80 |

## The design

`docs/architecture/README.md` indexes the chapters. `00-overview.md` is the entry point, `open-questions.md` the index of every numbered question and its decision. Every statement in a chapter carries a status marker, and a chapter outranks the plan on decisions while the plan outranks a chapter on phases.

The drawing below is the whole system coloured by build status. It is too dense to read inline, so open it in the browser and zoom.

[![Architecture diagram](docs/architecture/architecture-diagram.svg)](https://raw.githubusercontent.com/LucaCappelletti94/connetto-rs/main/docs/architecture/architecture-diagram.svg)

## Layout

| Crate | Role |
|---|---|
| `connetto-core` | Wire protocol, framing, and the traits every side agrees on |
| `connetto-server` | Session manager, subscription materializer, auth stack, mutation handler |
| `connetto-client` | Native Diesel connection, background sync, live queries, teardown, archives |
| `connetto-web` | Browser platform on wasm32, the DB worker, the relay, storage and custody |
| `connetto-dioxus`, `connetto-yew` | Framework adapters exposing live queries as hooks |
| `connetto-file-core`, `connetto-file-server`, `connetto-file-client` | The file stack, which depends on connetto and never the reverse |
| `connetto-test-harness` | The in-process CDC loop and the browser stack runner behind the tests |

`examples/` holds a Dioxus desktop demo, Dioxus and Yew web demos, the browser smoke suite, and the passkey unlock proof.
