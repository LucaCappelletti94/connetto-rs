-- The local tier document: device-private tables that never sync. A separate
-- reference universe from schema.sql, so a REFERENCES clause crossing the
-- boundary fails the translation (pg2sqlite validates reference closure per
-- document). Postgres dialect is kept for the type system, even though this
-- document never touches a real Postgres.
CREATE TABLE notes (id BIGINT PRIMARY KEY, body TEXT);
