//! Integration tests for connetto-file-server.
//!
//! All Docker-gated tests provision a fresh Postgres container and apply
//! the crate's `DEPLOYMENT_DDL` plus the test fixture (demo metadata table,
//! RLS policy, `connetto_file_server` reader role, visibility view, and
//! the content-state setter) before each test.

mod fixture;
mod macro_hygiene;
mod preflight;
mod serve;
mod sweep;
mod ticket;
mod upload;
