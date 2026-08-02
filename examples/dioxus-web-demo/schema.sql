-- The one source of truth for the demo: the Postgres dialect schema the
-- backend owns. build.rs translates this through pg2sqlite and bakes the
-- replica template database the app ships. The connetto-server for this demo
-- must be started with this same schema in CONNETTO_PG_DDL. Apply roles.sql
-- after this file to provision the non-owner role required by CONNETTO_READER_URL.
-- The server also requires CONNETTO_AUTH, CONNETTO_AUTH_BIND, and the
-- CONNETTO_OIDC_* variables written by the dev IdP (see dev_idp.rs).
CREATE TABLE orders (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), quantity BIGINT);
