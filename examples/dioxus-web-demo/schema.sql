-- The one source of truth for the demo: the Postgres dialect schema the
-- backend owns. build.rs translates this through pg2sqlite and bakes the
-- replica template database the app ships. The connetto-server for this demo
-- must be started with this same schema in CONNETTO_PG_DDL. Apply roles.sql
-- after this file to provision the non-owner role required by CONNETTO_READER_URL.
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
