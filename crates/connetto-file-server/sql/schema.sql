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

-- Deployment contract (1): visibility function.
--
-- The deployment implements a SQL function named exactly
-- connetto_visible_files with the signature below.  It must be
-- SECURITY INVOKER so the caller's own row-level security applies.
-- The SET search_path pins the search path so the function body cannot
-- be redirected through a different schema.
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
--               AND m.uploaded_by = current_setting('app.user_id', TRUE)
--         )
--     )
-- $$;
-- GRANT EXECUTE ON FUNCTION connetto_visible_files TO <file_server_reader_role>;

-- Deployment contract (2): content-state setter.
--
-- The deployment implements connetto_set_content_state as SECURITY DEFINER
-- so the file server role can write the application metadata table without a
-- direct UPDATE grant.  The third argument carries the uploader identity so
-- the deployment can attribute the commit.  SET search_path prevents privilege
-- escalation through a crafted search path.
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
