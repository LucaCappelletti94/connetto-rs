//! Tauri's build step, the dioxus demo's schema translated for the replica,
//! and the deployment root a `device-identity` build ships.

/// The path of the deployment root's `root.der`, which `connetto-demo-stack`
/// mints and names to the program it runs.
const DEVICE_ROOT: &str = "CONNETTO_DEMO_BUILD_DEVICE_ROOT";

fn main() {
    // The same server-side schema as the dioxus demo, so one demo stack serves both.
    connetto_schema::emit::<String, connetto_schema::TextIds>(
        std::path::Path::new("../../dioxus-desktop-demo/schema.sql"),
        std::path::Path::new("../../dioxus-desktop-demo/policies.sql"),
        None,
    )
    .expect("translate the demo's schema");

    if std::env::var_os("CARGO_FEATURE_DEVICE_IDENTITY").is_some() {
        println!("cargo:rerun-if-env-changed={DEVICE_ROOT}");
        let Some(path) = std::env::var_os(DEVICE_ROOT) else {
            panic!("the device-identity feature ships a deployment root: set {DEVICE_ROOT}");
        };
        println!(
            "cargo:rerun-if-changed={}",
            std::path::Path::new(&path).display()
        );
        let root = std::fs::read(&path).expect("read the deployment root");
        let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
        std::fs::write(out.join("device-root.der"), root).expect("write the deployment root");
    }

    tauri_build::build();
}
