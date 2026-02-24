# 07 — File Sync

**Status**: draft

---

## Purpose

Define how file content is synchronized between server and clients. File sync is deliberately separated from row-level sync: metadata travels on the row-sync channel; content travels on a separate channel with its own chunking and addressing scheme.

---

## Separation of Concerns

| Concern | Channel | Mechanism |
|---|---|---|
| File metadata (name, path, size, content hash, version) | Row-sync channel | Standard table subscription |
| File content (bytes) | Content channel | Chunked, hash-addressed transfer |

This separation keeps the row-sync channel message sizes predictable and allows content transfer to be paused, resumed, and deduplicated independently.

---

## File Metadata Table

File metadata is a normal synced table, e.g.:

```sql
CREATE TABLE files (
  file_id      UUID PRIMARY KEY,
  path         TEXT NOT NULL,
  size_bytes   BIGINT NOT NULL,
  content_hash TEXT NOT NULL,   -- e.g. SHA-256 hex or Blake3
  version      BIGINT NOT NULL, -- monotonically increasing per file
  created_at   TIMESTAMPTZ NOT NULL,
  updated_at   TIMESTAMPTZ NOT NULL,
  deleted_at   TIMESTAMPTZ      -- soft delete; NULL = active
);
```

Clients subscribe to this table like any other. When a file is created, updated, or deleted, the metadata change arrives as a `RowUpdate`. The metadata update is the *signal* that triggers the client to fetch (or evict) content.

---

## Content Channel

Content is transferred on a separate channel from row updates. In a WebSocket context, this may be:

- The same WebSocket connection with distinct message type prefixes (simpler, shared flow control)
- A separate HTTP endpoint for chunk upload/download (allows HTTP caching, range requests, parallel streams)

The choice is an open question; the rest of this document describes the logical protocol without assuming the physical channel.

---

## Content Addressing

File content is split into fixed-size chunks (e.g. 256 KiB or 1 MiB — configurable). Each chunk is addressed by its hash:

```
chunk_hash = Blake3(chunk_bytes)
```

The file's `content_hash` in the metadata table is the hash of the ordered sequence of chunk hashes (a Merkle root or a simple hash-of-hashes — exact scheme is an open question).

Content addressing gives:

- **Deduplication**: identical chunks across files are stored and transferred once.
- **Resumability**: a transfer interrupted at chunk N resumes at chunk N+1.
- **Integrity**: the client verifies each chunk's hash before accepting it.

---

## Upload Path (Client → Server)

1. Client writes a new file or modifies an existing one locally.
2. Client inserts/updates the metadata row (queued as a mutation via the standard mutation path).
3. Concurrently, client chunks the file content and computes chunk hashes.
4. Client sends `FileUploadIntent { file_id, chunk_count, chunk_hashes: Vec<Hash> }` to the server.
5. Server responds with `FileUploadNeeded { needed_hashes: Vec<Hash> }` — chunks the server doesn't already have.
6. Client uploads only the needed chunks: `FileChunk { hash, data }` for each.
7. Server assembles the file, verifies the content hash against the metadata row, and confirms: `FileUploadComplete { file_id }`.

If the connection drops mid-upload, the client resumes by re-sending the `FileUploadIntent`. The server re-checks which chunks it already received and returns an updated `needed_hashes` list.

---

## Download Path (Server → Client)

1. Client receives a `RowUpdate` for the `files` table indicating a new or changed file.
2. Client checks whether it already has the content (local cache keyed by `content_hash`).
3. If not (or if it has partial chunks): client sends `FileDownloadRequest { file_id, have_hashes: Vec<Hash> }`.
4. Server responds with `FileDownloadManifest { file_id, chunk_hashes: Vec<Hash> }` — the ordered list of chunks for this file version.
5. For each chunk the client does not already have: server sends `FileChunk { hash, data }`.
6. Client writes each chunk to local storage, verifies the hash.
7. After all chunks are received, client assembles the file and verifies the overall content hash.

The `have_hashes` field in the download request allows the client to skip chunks it already has from a previous version (or from a different file that shares chunks).

---

## Resumability

Both upload and download are resumable at the chunk boundary:

- **Upload**: `FileUploadIntent` is idempotent; the server's `needed_hashes` response reflects its current chunk store.
- **Download**: the client tracks which chunks it has received in a local table. On reconnect, it sends a new `FileDownloadRequest` with the updated `have_hashes`.

---

## Deduplication

The server maintains a content-addressed chunk store. Multiple files referencing the same chunk hash share one stored copy. Reference counting or garbage collection ensures unreferenced chunks are eventually removed.

On the client, the same chunk cache serves multiple files.

---

## Deletion

When a file is soft-deleted (metadata `deleted_at` is set), the client receives a `RowUpdate` and may evict the local content. Hard deletion from the client's content cache happens at the application's discretion (the file might be kept offline even after deletion from the server).

When a file is hard-deleted from the server's chunk store, reference counting ensures chunks shared with other files are not removed.

---

## Authorization

File access is authorized at the metadata level: the client can only see metadata rows it is authorized to read (standard row-level auth). Visibility of a file's metadata implies authorization to download its content.

For content channel requests, the server issues a **session token** for each authorized file access:

1. Server embeds a `download_token` in the `FileDownloadManifest`.
2. Client presents the token when requesting chunks.
3. Token is short-lived (e.g. 5 minutes) and scoped to the specific `file_id` and `content_hash`.

This avoids per-chunk authorization checks on the hot path.

Upload follows a similar pattern with an upload token issued in response to `FileUploadIntent`.

---

## WASM / Browser Constraints

In the browser, there is no direct filesystem access. Content must be stored in browser-accessible storage:

- **OPFS (Origin Private File System)**: available in modern browsers; supports file-like access in workers.
- **IndexedDB**: fallback for environments without OPFS; less efficient for binary blobs.
- **Cache API**: suitable for read-heavy files (e.g. images); less suitable for mutable app data.

Chunk streaming is required: the client must not buffer an entire large file in memory before writing it to storage. The content channel protocol is designed so chunks can be written as they arrive.

*(See `09-wasm.md` for broader WASM constraints.)*

---

## Open Questions

1. **Physical content channel**: same WebSocket or separate HTTP endpoint? HTTP allows range requests and CDN integration; same WebSocket simplifies connection management.
2. **Chunk size**: 256 KiB? 1 MiB? Configurable per-server? Small chunks = more round-trips; large chunks = coarser resume granularity.
3. **Content hash function**: SHA-256 (widely supported) or Blake3 (faster, native Rust)? Does the choice matter for interoperability?
4. **File tree conflict resolution**: if two clients rename or move the same file concurrently, what wins? Simple last-writer-wins on the metadata row, or a CRDT-based file tree? *(This is one of the key open decisions from the overview.)*
5. **Chunk store GC**: how does the server clean up unreferenced chunks? Reference counting at write time, or periodic GC sweep?
6. **Large file limits**: is there a maximum file size? What is the backpressure story for a 10 GiB upload?
7. **Encryption at rest**: is content encrypted before storage on the server? Client-side encryption? Out of scope?
8. **CDN integration**: for large-scale deployments, should chunk download bypass the application server and go directly to a CDN/object store? How does the token model work in that case?

---

## Decisions

*(none yet)*

---

## Notes

- File metadata and content are deliberately decoupled so the row-sync pipeline does not need to handle binary blobs.
- The chunk store on the server is logically separate from PostgreSQL — it may be an object store (S3, GCS, local disk) rather than a database table.
- "File" in this context means any binary content. The system does not interpret file formats.
