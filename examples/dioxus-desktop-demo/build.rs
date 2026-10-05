//! Build-time schema pipeline for the desktop demo, and the deployment root a
//! build with the `device-identity` feature ships.
//!
//! This demo has its own schema and no local tier, so it runs the shared
//! schema step over its own documents rather than over the documents the
//! browser demos share.

/// The path of the deployment root's `root.der`, which `connetto-demo-stack`
/// mints and names to the program it runs.
const DEVICE_ROOT: &str = "CONNETTO_DEMO_BUILD_DEVICE_ROOT";

fn main() {
    connetto_schema::emit::<String>(
        std::path::Path::new("schema.sql"),
        std::path::Path::new("policies.sql"),
        None,
    )
    .expect("translate the demo's schema");

    if std::env::var_os("CARGO_FEATURE_DEVICE_IDENTITY").is_some() {
        println!("cargo:rerun-if-env-changed={DEVICE_ROOT}");
        let Some(path) = std::env::var_os(DEVICE_ROOT) else {
            panic!(
                "the device-identity feature ships a deployment root: set {DEVICE_ROOT} to the \
                 root.der connetto-demo-stack minted under target/demo-device-ca"
            );
        };
        println!(
            "cargo:rerun-if-changed={}",
            std::path::Path::new(&path).display()
        );
        let root = std::fs::read(&path).expect("read the deployment root");
        let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
        std::fs::write(out.join("device-root.der"), root).expect("write the deployment root");
    }
}
