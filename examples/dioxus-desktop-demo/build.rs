//! Build-time schema pipeline for the desktop demo.
//!
//! This demo has its own schema and no local tier, so it runs the shared
//! schema step over its own documents rather than over the documents the
//! browser demos share.

fn main() {
    connetto_schema::emit::<String>(
        std::path::Path::new("schema.sql"),
        std::path::Path::new("policies.sql"),
        None,
    )
    .expect("translate the demo's schema");
}
