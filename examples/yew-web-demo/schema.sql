-- The one source of truth for the demo: the Postgres dialect schema the
-- backend owns. build.rs translates this through pg2sqlite and bakes the
-- replica template database the app ships. The connetto-server for this demo
-- must be started with this same schema in CONNETTO_PG_DDL. Apply roles.sql
-- after this file to provision the non-owner role required by CONNETTO_READER_URL.
CREATE TABLE orders (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), quantity BIGINT);
