# 20: Deployment, backup and restore

**Status**: normative. Paragraphs marked **Built.** describe what exists today. Every normative statement is marked **Decided**, naming its phase in `plans/master-implementation-plan.md`. R70 owns backup and restore and R73 owns failover, and both write here because a standby promoted behind on lag and a server restored to an earlier point put clients ahead of the server in the same way.

---

## What a deployment holds

**Built.** A deployment holds state in three places, which are its Postgres cluster, the stores beside it, and key files. The server binary emits no DDL, so every table below is created by the deployment's migration, and the table says what the server does at startup when one is missing.

| Artifact | Named by | In a Postgres backup | At startup when missing |
|---|---|---|---|
| Application tables | `CONNETTO_PG_DDL` | Yes | The deployment's own concern |
| `connetto_sessions`, `connetto_provider_tokens` | `connetto_auth_tables!` | Yes | No check. The first login or refresh fails |
| `_connetto_mutations`, the exactly-once watermark | `connetto_watermark_table!` | Yes | No check. The first client write fails (`11-authentication.md`) |
| `connetto_bans` | `ban.rs` | Yes | No check |
| The audit table, only under `CONNETTO_AUDIT=database` | `connetto_audit_table!` | Yes | No check |
| The reconnect log, `connetto_oplog` | `CONNETTO_OPLOG_TABLE` | Yes | Refused by `preflight::require` (`Artifact::Table`) |
| `connetto_epoch`, the cluster the deployment last served from | `connetto_server::epoch::EPOCH_DDL` | Yes, which is what lets a restore into another cluster be seen | Refused by `preflight::require` (`Artifact::Table`) |
| The publication and its previous images | `CONNETTO_PUBLICATION` | Yes | Refused (`Artifact::Publication`, `Artifact::PreviousImages`, and `Artifact::PublishedTable` for every table a policy reads) |
| The logical replication slot | `CONNETTO_SLOT` | **No**, under every method | Refused (`Artifact::ReplicationSlot`) |
| The file server's `_cfs_*` tables and functions | `connetto_file_server::DEPLOYMENT_DDL` | Yes | Refused by `connetto_file_server::preflight` |
| The chunk store | `CONNETTO_CONTENT_STORE`, a `fs:` directory or an `object_store` URL | **No** | Opened by `open_store`, with nothing checked against the manifests |
| The OpenFGA store | `CONNETTO_FGA_STORE` | Only when OpenFGA's own datastore lives in the same cluster | Refused without the id. A new model loads every fact from Postgres (`ModelState::Written`), an installed one reconciles only its whole-shape regions (`ModelState::Adopted`) |
| The token signing key pair | `CONNETTO_JWT_PRIVATE_KEY_FILE`, `CONNETTO_JWT_PUBLIC_KEY_FILE` | **No** | An ephemeral pair, so every token dies at each restart (`build_token_authority`) |
| The content ticket key | `CONNETTO_CONTENT_KEY` | **No** | An ephemeral key, so every ticket dies at each restart (`ticket_keypair`) |
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

**A rewound auth store would revive rotated refresh tokens**, under every method, because `connetto_sessions` holds the hash that was current at the backup, so a token rotated away after the backup would refresh again. **Built (R70).** The server therefore revokes every session whenever the cluster differs from the one `connetto_epoch` recorded, and at boot whenever the slot resumes past the reconnect log, before either listener opens, and each device logs in again. A running server whose feed reconnects to another cluster revokes at once. The recorded cluster is rewritten and the reconnect log trimmed only after the revocation succeeds, so a revocation that fails meets the same restore at the next try. A failover keeps its primary's identifier and its synced slot, so it logs nobody out.

**A rewound OpenFGA store is not rewound.** A membership granted after the backup and removed by the restore stays in the store after the restored server boots, because an installed model reconciles only its whole-shape regions (`Translated::reconcile_materialised`), so the change path keeps answering for a grant the database no longer holds.

**A restore leaves the database and the chunk store disagreeing two ways.** A restored manifest can name chunks the sweep removed after the backup, and a chunk uploaded after the backup is named by no registry row, which the sweep, starting from registry rows, never reaches.

**Built (R70, 2026-09-22) for the chunk store.** A boot pass before the listeners open deletes stored chunks no registry row names once past the grace window, and marks lost every manifest naming a chunk whose bytes are gone, telling the application `lost`, so a read refuses before it streams. A device still holding the file uploads it again, restoring it under its original uploaders. A lost file counts toward no uploader's quota until it heals, and its heal meets the deployment ceilings like any upload, because the store no longer holds those bytes. `18-file-handling.md` states the mechanism, and `crates/connetto-file-server/tests/it/restore.rs`, the native `offline_photo.rs` and the browser `examples/wasm-smoke/tests/photo_heal.rs` prove it.

**Built (R73) for the timeline.** A cursor carries the timeline it was issued on beside its write position. One whose position lies beyond where its timeline ended in the current history takes a full resync, and one at or below that point resumes, so a failover inside the replicated window resyncs nobody (`crates/connetto-server/src/timeline.rs`, `06-reconnect.md`).

**Built (R70) for the cluster.** A cursor also carries the cluster's system identifier, read from the `IDENTIFY_SYSTEM` the timeline read already sends, and one from another cluster takes a full resync with `CursorBeyondHistory`, because a database restored into another cluster starts again at timeline 1 and the timeline check does not see it.

**Decided (R70), not built.** Every boot reconciles the whole authorization store against Postgres.
