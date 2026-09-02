# 18: File handling

**Status**: normative for the decisions it records. Nothing in this chapter is built yet: every statement carries **Decided (RN)**, where `RN` is the phase in `plans/master-implementation-plan.md` that builds it, and the R24 section there records each decision with its rejected alternatives. Chapter 07 is the historical record of the thinking that preceded these decisions and defers to this chapter wherever the two disagree.

---

## Purpose

Applications handle files: a photo attached to an entry, a dataset a scientist collected, a document. Rows are the wrong vehicle for their bytes, so file handling is its own subsystem: metadata travels as ordinary synced rows, content travels on its own channel with its own storage, and the boundary between the two is this chapter's subject.

## The boundary

**Decided (R24, concluded 2026-08-21).** connetto-core does not build file handling. The boundary is the crate, not the repository: the file crates live in this repository beside the demos, depend on connetto and never the reverse, and the demos carry the feature end to end per R54's rule. `connetto-core` deletes the old unimplemented `FileStore` trait and gains exactly one seam, the signer trait described under Tickets below (**Decided (R66)**).

The file crates own the traits with more than one implementation: `ChunkStore` (`write_chunk`, `read_chunk`, `has_chunk` by content hash, with OPFS, `std::fs`, in-memory and object-store implementations), `ManifestStore`, the application-facing content resolver, and the pin policy (**Decided (R64, R67)**).

## Identity, chunking, and the manifest

**Decided (R64).** A file's identity is the plain BLAKE3 hash of its bytes, computed in the same streaming pass as chunking. The identity is deliberately chunking-independent: BLAKE3 is internally a Merkle tree, so verified range streaming (bao) remains a later upgrade with no format change, anyone can recompute the identity with `b3sum`, and re-tuning chunk sizes never re-identifies a file. Rejected: a hash over the chunk hashes, whose identity silently depends on chunking parameters.

Content is split by FastCDC under a per-mime-class parameter table shipped as data, and a file at or under the maximum chunk size skips chunking. Compressed formats (JPEG, video, gzipped scientific data) get large parameters or whole-file treatment because sub-file dedup finds nothing in them. The manifest is the ordered list of per-chunk (BLAKE3, length) pairs, transport and dedup metadata only, lengths present because they map a byte range to chunks.

Each chunk is zstd-compressed (level 3, per-mime skip table, a compression flag in the chunk header) between chunking and encryption, the Borg and Kopia order: the dedup hash is always over plaintext. Text-heavy scientific data roughly halves under zstd, and the driving use case is exactly that.

## Client storage

**Decided (R24 position 3, R64, R67, R68).** One encrypted chunk store outside SQLite: chunk files in OPFS in the browser and plain files on native, each encrypted with XChaCha20-Poly1305 under a random 24-byte nonce stored with the ciphertext, the chunk's plaintext hash as authenticated associated data, and the key derived by BLAKE3 key derivation with a purpose label (decided 2026-09-02, superseding the HKDF wording: one hash family, zero extra dependencies) from the same custody `ReplicaKeyStore` serves, so the R23 unlock gate and crypto-shred-on-wipe cover content exactly as they cover the replica. XChaCha was chosen over AES-GCM at review: the 192-bit nonce removes the birthday bound and the AES-NI assumption on mobile cores, and the cipher is one shared pure-Rust layer on every target where the replica cipher is two (SQLCipher native, sqlite3mc wasm).

The device-private tier carries only the manifests and the upload outbox, committed in the same transaction as the entry row, so a crash orphans a chunk file (collected by sweep) but never commits a row pointing at bytes that were never written. SQLite never carries content bytes on either side of the wire.

Client content divides into two classes. Unsent content, authored here and not yet uploaded, is data: its chunk files travel in the R26/R56 archive by manifest walk, because an unsent write cannot be refetched. Fetched content is cache: evictable under pin rules, never exported, refetchable by construction. The rejected alternatives (all chunks as encrypted-tier blobs, all chunks in plaintext OPFS, and a provenance split routing unsent bulk into SQLite) are recorded in the plan's R24 section.

## Display is not sync

**Decided (R24 position 2).** The common case renders a short-lived signed URL and never touches client chunk storage: the file server assembles from chunks and serves plain HTTP with `Range` mapped through the manifest, a strong `ETag` equal to the content hash, and immutable caching, so the browser's own cache, progressive rendering and video seeking do their jobs. Local content sync happens in exactly three cases: pinned files (the byte-level mirror of R15's row pins), locally processed inputs (a FASTA or MGF parsed in wasm needs bytes or ranges), and content this device authored but has not uploaded.

A file reference row is an intent. Metadata can arrive before content is fetchable, offline authorship makes that unavoidable rather than a bug, and readers show a placeholder until the availability signal below flips. Thumbnails are ordinary derived files behind a `thumb_hash` column, one pipeline with everything else.

## Server storage

**Decided (R24 position 4, R65).** Content bytes never enter Postgres. Beyond ordinary TOAST costs, this deployment runs `wal_level = logical`, so `BYTEA` content would be fully WAL-logged and pinned by the R32 replication slot, letting one bulk upload eat the retention headroom that keeps offline devices resumable. Chunks live in a filesystem directory or an S3-compatible object store behind the same `ChunkStore` trait. Manifests and reference counts stay in Postgres through typed diesel. Garbage collection is refcount plus a reconciling mark-and-sweep whose grace window is the upload ticket lifetime.

The backup story splits and the deployment documentation must say so: a database backup restores every metadata row and no bytes, so the chunk store needs its own durability statement. R70 owns the wider backup and restore story this feeds into.

## The wire, tickets, and the mint

**Decided (R24 positions 6 and 9, R66), with the capability distinction recorded in chapter 12.** An `img` tag cannot present a grant, so the URL itself must prove the right to fetch. A content ticket is a transport ticket carrying an already-made decision from the websocket to HTTP, deliberately not an R4 capability, which must never carry its own permission: the ticket is never presented at a handshake and never enters a `Principal`, and its revocation lag is exactly its lifetime, the same bounded staleness as the existing decision caching.

What rides the websocket is the ticket request (file id, verb, and for the write verb the declared byte size) and its grant. connetto answers the visibility question from the metadata row with its own machinery, charges the byte budget once at the mint, and calls a deployment-wired signer, the `WriteTarget` pattern. The signer, its key, the token format and the verifying HTTP endpoint all live in one file crate, so no key material and no token vocabulary enter `connetto-core` beyond the seam trait. The whole upload negotiation (intent, needed-hashes, chunk PUTs, commit) is HTTP under that ticket, and the file server enforces the ticket's byte ceiling rather than keeping a second counter. Tickets carry a session-long lifetime, accepting cross-session cache misses over cookies or a service worker.

## Upload, and the availability signal

**Decided (R24 position 5, R65).** Upload is two-phase: intent, the needed-hashes answer, chunk PUTs, and a commit that verifies each chunk hash and the BLAKE3 identity, so a half-uploaded file is never a servable version and resume is re-sending the intent. After commit the file server writes a `content_state` column on the metadata row and CDC delivers the flip to every subscribed device with the row's own policy gating who learns it: a convention, deliberately not a trait. That write needs a grant nothing provides by default, because the file server's role is not the row's owner and R1 forbids superuser and BYPASSRLS, so the deployment provisions a column-scoped UPDATE policy or a `SECURITY DEFINER` setter, verified at startup through the `preflight.rs` pattern.

## The abuse surface

**Decided (R24 position 7, R65).** The content channel meters bytes per identity per window in both directions, enforced against the ticket's ceiling, because R19 deliberately meters occurrences and file upload is the system's first genuinely bulk write path. Refusals answer 404 whether a file is absent or forbidden, R38's principle on HTTP. The dedup negotiation's needed-hashes answer is scoped to the caller's own visibility domain, closing the existence oracle cross-user dedup would open, while storage dedups globally and silently. Convergent encryption is rejected outright.

## Phases

R64 the file core, R65 the file server, R66 the connetto seam, R67 the native client, R68 the browser client (its archive step coordinated with the R56 format), R69 the demos. Bottom-up, with every platform-neutral crate running its tests under wasm from R64 onward. R79 extends the peer link of chapter 19 with content pull, and is that chapter's business.
