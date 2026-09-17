-- The two contracts the file server asks of this deployment, with the grants
-- its reader role needs. Apply after this file and after roles.sql:
--
--   schema.sql, connetto_file_server::DEPLOYMENT_DDL, roles.sql,
--   content.sql, policies.sql
--
-- connetto_visible_files is SECURITY INVOKER with a pinned search_path so row
-- level security answers from the caller's own identity, which is what both
-- the mint and the serving check consult. connetto_set_content_state is
-- SECURITY DEFINER with a pinned search_path so the file server's commit can
-- write content_state without owning the photos table. The writer grants on
-- photos live in roles.sql beside the other tables, because the demo's own
-- write path applies client mutations as connetto_reader.
CREATE OR REPLACE FUNCTION connetto_visible_files(p_file_ids BYTEA[]) RETURNS BYTEA[] LANGUAGE sql SECURITY INVOKER SET search_path TO '' AS $$ SELECT ARRAY(SELECT f FROM UNNEST(p_file_ids) AS f WHERE EXISTS (SELECT 1 FROM public.photos p WHERE p.content_id = f)) $$;
CREATE OR REPLACE FUNCTION connetto_set_content_state(p_file_id BYTEA, p_new_state TEXT, p_caller TEXT) RETURNS BYTEA LANGUAGE plpgsql SECURITY DEFINER SET search_path TO '' AS $$ BEGIN UPDATE public.photos SET content_state = p_new_state WHERE content_id = p_file_id; RETURN p_file_id; END; $$;
GRANT SELECT ON _cfs_manifests TO connetto_reader;
GRANT SELECT ON _cfs_manifest_chunks TO connetto_reader;
GRANT SELECT, UPDATE ON photos TO connetto_reader;
GRANT EXECUTE ON FUNCTION connetto_visible_files TO connetto_reader;
GRANT EXECUTE ON FUNCTION connetto_set_content_state TO connetto_reader;

-- Full previous images for the photos table. The commit flips content_state
-- with an update and the change path needs the row as it was. It is a
-- Postgres-only property with no SQLite equivalent, so the pg2sqlite
-- translation of schema.sql refuses it, and this file is the one deployment
-- SQL document that never goes through that translation.
ALTER TABLE photos REPLICA IDENTITY FULL;
