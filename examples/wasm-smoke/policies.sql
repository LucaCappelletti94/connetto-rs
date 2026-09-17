-- The row-level security the backend enforces on the synced tables, kept apart
-- from schema.sql because the two reach the server as separate documents:
-- schema.sql feeds CONNETTO_PG_DDL and is what clients sync, this file feeds
-- CONNETTO_PG_POLICIES and is what the authorization model is derived from.
-- Apply both to Postgres, this one last, after schema.sql, the file server
-- DDL, roles.sql and content.sql.
-- build.rs translates the pair together, which is what splits the replica's
-- orders into a backing table, a view of the logical name, and INSTEAD OF
-- triggers. The caller is read from app.user_id, which the server binds per
-- transaction and the replica answers with the registered current_app_user()
-- function, so both ends compare against the same identity.
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY orders_p ON orders USING (owner_id = current_setting('app.user_id', true));  -- NOSONAR S1192, SQL DDL has no constants for the caller setting the three policies share

-- The same shape on the composite-key table, so its replica half is split the
-- same way and its INSTEAD OF triggers have to match a row on two key columns
-- rather than one.
ALTER TABLE order_lines ENABLE ROW LEVEL SECURITY;
CREATE POLICY order_lines_p ON order_lines USING (owner_id = current_setting('app.user_id', true));

-- The photo rows are visible to the owner of the order they hang off, and the
-- owner is repeated on the row as it is on order_lines, so the comparison
-- settles from the row itself. The file server's visibility function consults
-- exactly this table under the caller's identity.
ALTER TABLE photos ENABLE ROW LEVEL SECURITY;
CREATE POLICY photos_p ON photos USING (owner_id = current_setting('app.user_id', true));
