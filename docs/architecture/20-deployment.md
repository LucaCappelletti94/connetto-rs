# 20: Deployment, backup and restore

**Status**: normative. Paragraphs marked **Built.** describe what exists today. Every normative statement is marked **Decided**, naming its phase in `plans/master-implementation-plan.md`. R70 owns backup and restore and R73 owns failover, and both write here because a standby promoted behind on lag and a server restored to an earlier point put clients ahead of the server in the same way.

---

## What a deployment holds

**Built.** A deployment holds state in three places, which are its Postgres cluster, the stores beside it, and key files. The server binary emits no DDL, so every table below is created by the deployment's migration, and the table says what the server does at startup when one is missing.

**Built (R98, 2026-10-04).** Every table connetto reads through a trait is a member of one `ConnettoSchema`, and the startup check names each member's tables from the `TABLES` the member reports, so a custom member is checked by its own names. Only names are checked, never columns.

| Artifact | Named by | In a Postgres backup | At startup when missing |
|---|---|---|---|
| Application tables | `CONNETTO_PG_DDL` | Yes | The deployment's own concern |
| `connetto_sessions`, `connetto_provider_tokens` | `ConnettoSchema::Auth`, emitted by `connetto_schema!` | Yes | Refused by `preflight::require` (`Artifact::Table`) |
| `_connetto_mutations`, the exactly-once watermark | `ConnettoSchema::Watermark` | Yes | Refused by `preflight::require` (`Artifact::Table`) |
| `connetto_bans`, only under `CONNETTO_BANS=database` | `ConnettoSchema::Bans` | Yes | Refused by `preflight::require` (`Artifact::Table`) when bans are on |
| The audit table, only under `CONNETTO_AUDIT=database` | `ConnettoSchema::Audit` | Yes | Refused by `preflight::require` (`Artifact::Table`) when the audit is on |
| `connetto_device_enrolments`, `connetto_device_certificates`, `connetto_device_lists`, only with device identity (R74) | `ConnettoSchema::Enrolments` | Yes | Refused by `preflight::require` (`Artifact::Table`) when device identity is on |
| The reconnect log, `connetto_oplog`, and its last commit, `connetto_oplog_commit` | `CONNETTO_OPLOG_TABLE`, with `_commit` appended for the second | Yes | Both refused by `preflight::require` (`Artifact::Table`) |
| `connetto_epoch`, the cluster the deployment last served from | `connetto_server::epoch::EPOCH_DDL` | Yes, which is what lets a restore into another cluster be seen | Refused by `preflight::require` (`Artifact::Table`) |
| The publication and its previous images | `CONNETTO_PUBLICATION` | Yes | Refused (`Artifact::Publication`, `Artifact::PreviousImages`, and `Artifact::PublishedTable` for every table a policy reads) |
| The logical replication slot | `CONNETTO_SLOT` | **No**, under every method | Refused (`Artifact::ReplicationSlot`) |
| The file server's `_cfs_*` tables and functions | `connetto_file_server::DEPLOYMENT_DDL` | Yes | Refused by `connetto_file_server::preflight` |
| The chunk store | `CONNETTO_CONTENT_STORE`, a `fs:` directory or an `object_store` URL | **No** | Opened by `open_store`, with nothing checked against the manifests |
| The OpenFGA store | `CONNETTO_FGA_STORE` | Only when OpenFGA's own datastore lives in the same cluster | Refused without the id. A new model loads every fact from Postgres (`ModelState::Written`), an installed one reconciles only its whole-shape regions (`ModelState::Adopted`) |
| The token signing key pair | `CONNETTO_JWT_PRIVATE_KEY_FILE`, `CONNETTO_JWT_PUBLIC_KEY_FILE` | **No** | Refused. The deployment keeps the pair on disk so a token survives a restart |
| The content ticket key | `CONNETTO_CONTENT_KEY` | **No** | Refused when `CONNETTO_CONTENT_URL` is set, which is what makes the key required. It is the deployment's own and survives a restart |
| Device attestation (R74) | `CONNETTO_DEVICE_ACCEPTED_ATTESTATION`, the levels accepted, all three by default, `CONNETTO_DEVICE_APP_ATTEST_APP_IDS` and `CONNETTO_DEVICE_APP_ATTEST_ENVIRONMENT` for Apple's App Attest, and `CONNETTO_DEVICE_ANDROID_STATUS`, a URL or file standing in for Google's attestation status list | **No** | Each refuses startup without `CONNETTO_DEVICE_ISSUER_DIR`. A status list that cannot be fetched is logged, and Android devices record `unproven` until a copy arrives |
| The device certificate issuer, its key and the root it chains to (R74) | `CONNETTO_DEVICE_ISSUER_DIR`, the directory `connetto-ca issuer` wrote, and `CONNETTO_DEVICE_ROOT`, its `root.der`, with `CONNETTO_DEVICE_RETIRED_ISSUER_DIRS` and `CONNETTO_DEVICE_ROOT_LIST` for rotated and revoked issuers | **No** | No issuer directory means no device identity, and any other `CONNETTO_DEVICE_*` setting without it refuses startup. An issuer the root did not sign or an expired issuer refuses startup, and one with under sixty days left is logged |
| The device root key and the root's revocation list (R74) | `root.key.p8e` and `root-list.der` in the operator's `connetto-ca` directory, the key encrypted under a passphrase | **No**, and never on the server | Not read by the server, which ships the root certificate in the applications |
| Provider client secrets | `CONNETTO_OIDC_<PROVIDER>_CLIENT_SECRET` | **No** | Re-issued by the provider |

**The slot is recreated after every restore, whatever the method.** A physical base backup omits `pg_replslot`, and a logical dump carries no slots. A recreated slot starts at the restored cluster's current write position.

**A Postgres backup restores every file manifest and no chunk bytes** (`18-file-handling.md`), so the chunk store is backed up separately, and the next section shows what happens where the two disagree.

---

## What a restore does to connected clients

**Built for rows, logins and the chunk store. Built defective for authorization, whose fix is Decided (R70), not built.** The row and login facts below are asserted by the Docker-gated tests in `crates/connetto-server/tests/it/restore.rs`, green on 2026-09-23, and the authorization facts were observed on 2026-09-22 by a demonstration in the same file that prints what it sees and asserts nothing. In each run a client synced three rows, the deployment took a backup, two more rows reached the client, the database was restored, and one new row was written on the restored server. The same-cluster run drops the slot by hand before restoring, so it covers recreating the slot and not a slot left in place across the restore.

| What a restore rewinds | Point-in-time, onto a new timeline | Dump into a fresh cluster | Dump into the same cluster |
|---|---|---|---|
| A client ahead of the restored server | Resyncs and matches the server | Resyncs and matches the server | Resyncs and matches the server |
| A refresh token from before the restore, rotated or current | Refused with `401` | Refused with `401` | Refused with `401` |
| The restored cluster's system identifier | The backed-up one's | Another | The backed-up one's |
| The replication slot | Absent, so the operator recreates it | Absent | Dropped before the restore and recreated |

**Why each method converges, inferred from the code rather than read from the server's log.** A client's cursor is a write position, the timeline it was issued on and the cluster's system identifier. Within one cluster write positions only grow, so after a same-cluster restore the recreated slot resumes past the rewound reconnect log's end, which is the case the server's resume check (`SessionManager::reconcile_stream`, proven by `stream_gap.rs`) answers by forcing every returning client to resync. A point-in-time restore promotes onto a new timeline that branched below the client's cursor, so R73's timeline check resyncs the client. A dump into a fresh cluster starts again at timeline 1 with the restored write positions below the client's cursor, where the log alone would answer `Catchup` and skip a new row written behind the cursor, so the identifier it carries, which the restored cluster does not share, resyncs it.

**A rewound auth store would revive rotated refresh tokens**, under every method, because `connetto_sessions` holds the hash that was current at the backup, so a token rotated away after the backup would refresh again. **Built (R70).** The server therefore revokes every session whenever the cluster differs from the one `connetto_epoch` recorded, and at boot whenever the slot resumes past the reconnect log, before the listener opens, and each device logs in again. A running server whose feed reconnects to another cluster revokes at once. The recorded cluster is rewritten and the reconnect log trimmed only after the revocation succeeds, so a revocation that fails meets the same restore at the next try. A failover keeps its primary's identifier and its synced slot, so it logs nobody out.

**A rewound OpenFGA store is not rewound.** A membership granted after the backup and removed by the restore stays in the store after the restored server boots, because an installed model reconciles only its whole-shape regions (`Translated::reconcile_materialised`), so the change path keeps answering for a grant the database no longer holds.

**A restore leaves the database and the chunk store disagreeing two ways.** A restored manifest can name chunks the sweep removed after the backup, and a chunk uploaded after the backup is named by no registry row, which the sweep, starting from registry rows, never reaches.

**Built (R70, 2026-09-22) for the chunk store.** A boot pass before the listener opens deletes stored chunks no registry row names once past the grace window, and marks lost every manifest naming a chunk whose bytes are gone, telling the application `lost`, so a read refuses before it streams. A device still holding the file uploads it again, restoring it under its original uploaders. A lost file counts toward no uploader's quota until it heals, and its heal meets the deployment ceilings like any upload, because the store no longer holds those bytes. `18-file-handling.md` states the mechanism, and `crates/connetto-file-server/tests/it/restore.rs`, the native `offline_photo.rs` and the browser `examples/wasm-smoke/tests/photo_heal.rs` prove it.

**Built (R73) for the timeline.** A cursor carries the timeline it was issued on beside its write position. One whose position lies beyond where its timeline ended in the current history takes a full resync, and one at or below that point resumes, so a failover inside the replicated window resyncs nobody (`crates/connetto-server/src/timeline.rs`, `06-reconnect.md`).

**Built (R70) for the cluster.** A cursor also carries the cluster's system identifier, read from the `IDENTIFY_SYSTEM` the timeline read already sends, and one from another cluster takes a full resync with `CursorBeyondHistory`, because a database restored into another cluster starts again at timeline 1 and the timeline check does not see it.

**Decided (R70), not built.** Every boot reconciles the whole authorization store against Postgres.

---

## Running the server

**The binary is a translation from its environment into one `ServerBuilder`, and the builder is the one assembly path.** The binary reads every setting, binds the one listener and serves through the builder's own lifecycle, and owns what a process owns and a library must not own, the logging, the shutdown signal and the exit code. `CONNETTO_BIND` (default `127.0.0.1:8080`) names the one listener that serves the `/sync` WebSocket route, the login endpoints and the file routes. `CONNETTO_AUTH` accepts only `database`, the persisted JWT key files are required so a token survives a restart, and `CONNETTO_CONTENT_KEY` is required when `CONNETTO_CONTENT_URL` is set. The process exits `1` when the change stream cannot answer what a row looked like before it changed, or gives up reconnecting.

**A program embeds the same builder.** `ServerBuilder::build` returns the parts, the merged router, the sync routes and the HTTP routes separately, the change-stream future and the shutdown handle, and a program that embeds the server mounts them into its own application. `ServerBuilder::serve` binds them and runs the serving lifecycle without ever ending the process, the change-stream future closes every session when a terminal outcome arrives, and the shutdown signal closes every session with `ServerShuttingDown` on its own drain. `crates/connetto-server/examples/embed.rs` builds the parts and mounts them beside a route of its own, so the application serves the sync, login and file routes from its own listener.

**Built (R98, 2026-10-04). The builder takes the deployment's schema as its one type parameter.** `ServerBuilder` defaults to `ConnettoDefaults`, the tables `connetto_schema!` emits under the names this chapter lists, with a `String` user id and `DefaultUuidResolver` mapping each login to it. `ServerBuilder::deployment_schema::<D>(resolver)` serves over a deployment's own `ConnettoSchema` instead, with any user id type, and takes the `IdentityResolver` typed by that id at the same call, so a schema switch without one does not compile. `identity_resolver` replaces the resolver without switching schema, which is how a deployment maps logins into its own users table. `crates/connetto-server/tests/it/deployment_schema.rs` serves a deployment with its own watermark table and a `uuid::Uuid` user id.
