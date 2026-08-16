-- The row-level security the backend enforces on the synced table, kept apart
-- from schema.sql because the two reach the server as separate documents:
-- schema.sql feeds CONNETTO_PG_DDL and is what clients sync, this file feeds
-- CONNETTO_PG_POLICIES and is what the authorization model is derived from.
-- Apply both to Postgres, this one after schema.sql.
-- build.rs translates the pair together, which is what splits the replica's
-- orders into a backing table, a view of the logical name, and INSTEAD OF
-- triggers. The caller is read from app.user_id, which the server binds per
-- transaction and the replica answers with the registered current_app_user()
-- function, so both ends compare against the same identity.
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY orders_p ON orders USING (owner_id = current_setting('app.user_id', true));
