//! Build-time schema pipeline for this demo.
//!
//! The shared deployment crate translates its own documents and this demo's
//! local tier, so a demo says which local tier it has and nothing else.

fn main() {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    connetto_demo_deployment::build_support::emit(Some("frontend.sql"), &out_dir);
}
