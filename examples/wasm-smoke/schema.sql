-- The one source of truth for the demo: the Postgres dialect schema the
-- backend owns. build.rs translates this through pg2sqlite into the SQLite DDL
-- a first boot applies. The connetto-server for this demo must be started with
-- this same schema in CONNETTO_PG_DDL and must list every synced table in
-- CONNETTO_WRITABLE. Apply in this order: this file,
-- connetto_file_server::DEPLOYMENT_DDL, roles.sql (the non-owner role
-- required by CONNETTO_READER_URL), content.sql, then policies.sql.
-- The key default is load-bearing on the client rather than here: build.rs
-- translates it through pg2sqlite into the replica's own DEFAULT (uuidv4()),
-- which mints the key when a local write omits it. Both ends mint version 4.
-- The quantity is non-null because every client schema already declares it so.
-- owner_id carries who a row belongs to, which policies.sql compares against
-- the caller. It has no default: pg2sqlite maps current_setting only inside a
-- policy expression, so a default naming the caller would translate into a
-- call the replica cannot resolve, and every write names the owner instead.
CREATE TABLE orders (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), owner_id TEXT NOT NULL, quantity BIGINT NOT NULL CHECK (quantity >= 0));

-- The lines of an order, keyed by the order and the line number together. It is
-- the one table here whose key spans two columns, and the translation below
-- splits it like any policy-bearing table, so its INSTEAD OF triggers match a
-- row on both key columns rather than one. owner_id repeats rather than being
-- read through the parent order, so the policy settles from the row itself,
-- which is what keeps the change path free of a round trip.
CREATE TABLE order_lines (order_id UUID NOT NULL REFERENCES orders(id), line_no INTEGER NOT NULL, owner_id TEXT NOT NULL, quantity BIGINT NOT NULL CHECK (quantity >= 0), PRIMARY KEY (order_id, line_no));

-- The photo entry: metadata for one file's bytes, attached to an order.
-- content_id is the BLAKE3 identity the file server stores and serves under,
-- and content_state stays null until the file server's commit writes
-- `available`, so the placeholder condition is "not available" and the
-- availability flip arrives as an ordinary synced column change. owner_id
-- repeats from the parent order as it does on order_lines, so the visibility
-- policy settles from the row itself.
CREATE TABLE photos (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), order_id UUID NOT NULL REFERENCES orders(id), owner_id TEXT NOT NULL, content_id BYTEA NOT NULL, content_state TEXT);
