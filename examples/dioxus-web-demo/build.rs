//! Build-time schema pipeline for this demo.
//!
//! The demo shares the deployment's synced schema and policies and adds its
//! own local tier, so it runs the shared schema step over those three.

fn main() {
    connetto_schema::emit::<String>(
        std::path::Path::new("../deployment/schema.sql"),
        std::path::Path::new("../deployment/policies.sql"),
        Some(std::path::Path::new("frontend.sql")),
    )
    .expect("translate the demo's schema");
}
