//! Build-time schema pipeline for the desktop demo.
//!
//! This demo has its own schema and no local tier, so it runs the shared
//! deployment crate's pipeline over its own document rather than over the
//! documents the browser demos share.

fn main() {
    println!("cargo::rerun-if-changed=schema.sql");
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    let synced = ["schema.sql"];
    let views = connetto_demo_deployment::build_support::translate(
        &synced,
        &out_dir.join("replica-ddl.sql"),
    );
    connetto_demo_deployment::build_support::write_policy_tables(
        &synced,
        &views,
        &out_dir.join("replica-tables.rs"),
    );
}
