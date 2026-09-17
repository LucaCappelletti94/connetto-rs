-- The one source of truth for the demo: the Postgres dialect schema the
-- backend owns. build.rs translates this through pg2sqlite and bakes the
-- replica template database the app ships. The connetto-server for this demo
-- must be started with this same schema in CONNETTO_PG_DDL and must list
-- every synced table in CONNETTO_WRITABLE. Apply in this order: this file,
-- connetto_file_server::DEPLOYMENT_DDL, roles.sql (the non-owner role
-- required by CONNETTO_READER_URL), then content.sql.
-- The server also requires CONNETTO_AUTH, CONNETTO_AUTH_BIND, and the
-- CONNETTO_OIDC_* variables written by the dev IdP (see dev_idp.rs).
-- The key default is load-bearing on the client rather than here: build.rs
-- translates it through pg2sqlite into the replica's own DEFAULT (uuidv4()),
-- which mints the key when a local write omits it. Both ends mint version 4.
-- The quantity is non-null because every client schema already declares it so.
CREATE TABLE orders (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), quantity BIGINT NOT NULL CHECK (quantity >= 0));

-- The lines of an order, keyed by the order and the line number together. It is
-- the one table here whose key spans two columns, which the replica's own schema
-- and every key connetto encodes on the wire have to carry as a pair.
CREATE TABLE order_lines (
  order_id UUID NOT NULL REFERENCES orders(id),
  line_no INTEGER NOT NULL,
  quantity BIGINT NOT NULL CHECK (quantity >= 0),
  PRIMARY KEY (order_id, line_no)
);

-- The photo entry: metadata for one file's bytes, attached to an order.
-- content_id is the BLAKE3 identity the file server stores and serves under,
-- and content_state stays null until the file server's commit writes
-- `available`, so the placeholder condition is "not available" and the
-- availability flip arrives as an ordinary synced column change.
CREATE TABLE photos (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), order_id UUID NOT NULL REFERENCES orders(id), content_id BYTEA NOT NULL, content_state TEXT);
