-- The non-owner role the connetto-server runs reads and writes as, named by
-- CONNETTO_READER_URL. Kept apart from schema.sql because that file also
-- feeds CONNETTO_PG_DDL and the pg2sqlite translation in build.rs, which
-- expect pure table DDL. Apply after schema.sql and after creating the
-- _connetto_mutations watermark table.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'connetto_reader') THEN
    CREATE ROLE connetto_reader LOGIN PASSWORD 'connetto_reader';
  END IF;
END $$;
GRANT USAGE ON SCHEMA public TO connetto_reader;
GRANT SELECT, INSERT, UPDATE, DELETE ON orders TO connetto_reader;
GRANT SELECT, INSERT, UPDATE, DELETE ON order_lines TO connetto_reader;
GRANT SELECT, INSERT, UPDATE ON _connetto_mutations TO connetto_reader;
