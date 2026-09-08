[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](../../LICENSE)
[![CI](https://github.com/LucaCappelletti94/connetto-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/connetto-rs/actions)

# connetto-file-server

Chunk storage, upload protocol, ticket-gated serving, and GC for connetto-rs.

Content bytes never enter Postgres. Chunks live in a local filesystem directory or any `object_store`-compatible backend (S3, `MinIO`, local). Manifests and reference counts stay in three typed diesel-async tables. Upload and download are gated by compact Ed25519-signed tickets.

## Deployment contracts

The server relies on two SQL artifacts the deployment provisions before startup.

`connetto_visible_files(file_ids BYTEA[]) RETURNS BYTEA[]` runs with caller rights (SECURITY INVOKER) and requires `SET search_path` so the deployment's own row-level security applies. It answers which of the supplied file ids the current caller may see and drives the upload dedup oracle prevention.

`connetto_set_content_state(file_id BYTEA, new_state TEXT, caller TEXT)` is a SECURITY DEFINER setter that writes `content_state` on the deployment's metadata table after a successful commit, requires `SET search_path`, and triggers the CDC availability signal without requiring a direct UPDATE grant for the file server role.

`preflight()` verifies both functions exist with the correct signatures before the server accepts any request, and names exactly what is missing when one is absent.

## Upload flow

```text
POST /files/{id}/intent?t=<ticket>   // declare manifest, receive needed hashes
PUT  /chunks/{hash}?t=<ticket>       // upload one chunk, BLAKE3 verified
POST /files/{id}/commit?t=<ticket>   // verify all chunks, flip content_state, caller must be declarer
```

```text
GET /files/{id}?t=<ticket>           // range-aware download, ETag, immutable cache
```

A crashed upload (intent without commit) never serves. Its chunks are cleaned by the mark-sweep collector whose grace window matches the ticket lifetime.
