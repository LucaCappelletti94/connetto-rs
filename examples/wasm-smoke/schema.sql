-- The one source of truth for the demo: the Postgres dialect schema the
-- backend owns. build.rs translates this through pg2sqlite into the SQLite DDL
-- a first boot applies. The connetto-server for this demo must be started with
-- this same schema in CONNETTO_PG_DDL. Apply roles.sql after this file to
-- provision the non-owner role required by CONNETTO_READER_URL.
-- The key default is load-bearing on the client rather than here: build.rs
-- translates it through pg2sqlite into the replica's own DEFAULT (uuidv4()),
-- which mints the key when a local write omits it. Both ends mint version 4.
-- The quantity is non-null because every client schema already declares it so.
CREATE TABLE orders (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), quantity BIGINT NOT NULL CHECK (quantity >= 0));
