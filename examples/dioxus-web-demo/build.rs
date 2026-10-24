//! Build-time schema pipeline for this demo.
//!
//! The demo shares the deployment's synced schema and policies and adds its
//! own local tier, so it runs the shared schema step over those three. The
//! tier history lives in `tier_history` beside the source, and the build
//! step only reads that directory. Its exports are written by
//! `connetto-schema export-tier`, run from the workspace root as `cargo run
//! -p connetto-schema --bin connetto-schema -- export-tier --schema
//! examples/deployment/schema.sql --tier examples/dioxus-web-demo/frontend.sql
//! --dir examples/dioxus-web-demo/tier_history`.

fn main() {
    connetto_schema::emit::<String, connetto_schema::TextIds>(
        std::path::Path::new("../deployment/schema.sql"),
        std::path::Path::new("../deployment/policies.sql"),
        Some(&connetto_schema::TierSource::new(
            "frontend.sql",
            "tier_history",
        )),
    )
    .expect("translate the demo's schema");
}
