-- File server deployment schema for connetto-file-server.
-- Apply once with a privileged role before starting the server.
-- preflight() verifies each named artifact at startup and refuses with an
-- exact error when one is missing.

-- File manifests: one row per (upload, uploader) pair.
-- The composite primary key lets every caller hold an independent declaration
-- over shared content-addressed chunks.  Two callers uploading identical bytes
-- each get their own row and can commit independently.
CREATE TABLE IF NOT EXISTS _cfs_manifests (
    file_id        BYTEA        NOT NULL,
    total_len      BIGINT       NOT NULL,
    accepted_bytes BIGINT       NOT NULL DEFAULT 0,
    committed      BOOLEAN      NOT NULL DEFAULT FALSE,
    uploaded_by    TEXT         NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    -- Set at boot when the store lost chunks this manifest names, until a re-upload.
    lost           BOOLEAN      NOT NULL DEFAULT FALSE,
    PRIMARY KEY (file_id, uploaded_by)
);

-- Per-chunk records: ordered, referencing the manifest row by composite key.
CREATE TABLE IF NOT EXISTS _cfs_manifest_chunks (
    file_id     BYTEA   NOT NULL,
    uploaded_by TEXT    NOT NULL,
    position    INTEGER NOT NULL,
    chunk_hash  BYTEA   NOT NULL,
    chunk_len   BIGINT  NOT NULL,
    stored      BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (file_id, uploaded_by)
        REFERENCES _cfs_manifests (file_id, uploaded_by) ON DELETE CASCADE,
    PRIMARY KEY (file_id, uploaded_by, position)
);

-- The sweep locks doomed hashes with a correlated anti-join from the registry
-- into these two tables, so both lookups must be indexed.
CREATE INDEX IF NOT EXISTS _cfs_manifest_chunks_chunk_hash_idx
    ON _cfs_manifest_chunks (chunk_hash);
CREATE INDEX IF NOT EXISTS _cfs_manifests_uncommitted_created_at_idx
    ON _cfs_manifests (created_at)
    WHERE NOT committed;

-- The per-identity storage quota (R87) sums this uploader's committed
-- manifests at commit time, so the reverse lookup must be indexed.
CREATE INDEX IF NOT EXISTS _cfs_manifests_uploaded_by_committed_idx
    ON _cfs_manifests (uploaded_by)
    WHERE committed;

-- Deployment traffic ledger (R87): one row per UTC day carrying the bytes
-- actually served and accepted.  Every replica upserts the same day row, so
-- the rolling bandwidth window is shared across the deployment with no
-- replica-local counter.
CREATE TABLE IF NOT EXISTS _cfs_traffic (
    day            DATE   NOT NULL PRIMARY KEY,
    served_bytes   BIGINT NOT NULL DEFAULT 0,
    accepted_bytes BIGINT NOT NULL DEFAULT 0
);

-- Per-hash state registry.  Each chunk hash has a lifecycle row:
--   pending   - declared by intent, not yet written to the object store
--   stored    - durably written to the object store
--   deleting  - sweep has marked it for deletion, no new uploads may claim it
--
-- Liveness is DERIVED: a hash is live while any _cfs_manifest_chunks row
-- references it.  No counter is maintained.  The sweep marks a hash
-- 'deleting' only when no manifest_chunks row references it.
CREATE TABLE IF NOT EXISTS _cfs_chunk_registry (
    chunk_hash BYTEA NOT NULL PRIMARY KEY,
    state      TEXT  NOT NULL
               CHECK (state IN ('pending', 'stored', 'deleting'))
);

-- The sweep resumes stranded deletions by listing rows in 'deleting' state.
-- Without this index the resume scan reads the full registry on every startup.
CREATE INDEX IF NOT EXISTS _cfs_chunk_registry_deleting_idx
    ON _cfs_chunk_registry (chunk_hash)
    WHERE state = 'deleting';

-- Deployment contract (1): visibility function.
--
-- The deployment implements a SQL function named exactly
-- connetto_visible_files with the signature below.  It must be
-- SECURITY INVOKER so the caller's own row-level security applies.
-- The SET search_path pins the search path so the function body cannot
-- be redirected through a different schema.
--
-- The file server binds both halves of the caller, the identity under
-- app.user_id and the packed share keys under app.subjects, so a template
-- reading only the identity refuses every caller whose rights come from a
-- share key.  An unheld half takes an unguessable marker, a value no row can
-- carry, so comparing against it is false rather than NULL.  Recognise a
-- caller holding nothing by its own rows, never by testing for NULL.
--
-- Example template (adapt to the deployment's metadata table):
--
-- CREATE OR REPLACE FUNCTION connetto_visible_files(p_file_ids BYTEA[])
-- RETURNS BYTEA[] LANGUAGE sql SECURITY INVOKER
--     SET search_path TO '' AS $$
--     SELECT ARRAY(
--         SELECT f FROM UNNEST(p_file_ids) AS f
--         WHERE EXISTS (
--             SELECT 1 FROM your_metadata_table m
--             WHERE m.file_id = f
--               AND (m.uploaded_by = current_setting('app.user_id', TRUE)
--                    OR m.uploaded_by = ANY(
--                        string_to_array(current_setting('app.subjects', TRUE), ',')))
--         )
--     )
-- $$;
-- GRANT EXECUTE ON FUNCTION connetto_visible_files TO <file_server_reader_role>;

-- Deployment contract (2): content-state setter.
--
-- The deployment implements connetto_set_content_state as SECURITY DEFINER
-- so the file server role can write the application metadata table without a
-- direct UPDATE grant.  The third argument names who the commit belongs to,
-- which is the identity when the caller has one and each share key it holds
-- otherwise, one call per key, so the setter must be idempotent.  SET
-- search_path prevents privilege escalation through a crafted search path.
-- The state is `available` at commit and `lost` when the boot reconcile finds
-- the file's bytes gone, and a setter that refuses `lost` stops the server's boot.
--
-- Example template:
--
-- CREATE OR REPLACE FUNCTION connetto_set_content_state(
--     p_file_id   BYTEA,
--     p_new_state TEXT,
--     p_caller    TEXT
-- ) RETURNS BYTEA LANGUAGE plpgsql SECURITY DEFINER
--     SET search_path TO '' AS $$
-- BEGIN
--     UPDATE your_metadata_table
--     SET    content_state = p_new_state
--     WHERE  file_id = p_file_id;
--     RETURN p_file_id;
-- END;
-- $$;
-- GRANT EXECUTE ON FUNCTION connetto_set_content_state TO <file_server_role>;
