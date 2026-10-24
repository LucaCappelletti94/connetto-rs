//! The demo's entry point, one per platform. The browser build also runs the
//! dedicated DB worker when it is spawned as one, and delivers a login code
//! when it is the popup the sign-in opened.

#[cfg(target_arch = "wasm32")]
fn main() {
    connetto_web::logging::init_console();
    // The dedicated DB worker imports this same wasm module: the leader spawns
    // it pointed straight at the dx glue, which auto-initializes and runs this
    // `main`. A worker has no `Window`.
    if web_sys::window().is_none() {
        wasm_bindgen_futures::spawn_local(async {
            if let Err(err) = connetto_dioxus_demo::platform::web::run_db_worker().await {
                tracing::error!(error = ?err, "db worker failed");
            }
        });
        return;
    }
    // A login popup exists only to carry the code home. It must not boot a
    // worker of its own: the login belongs to the opener's worker, which
    // holds the PKCE verifier, and a second worker here would elect itself
    // leader and open the same replica.
    if connetto_dioxus_demo::platform::web::is_login_popup() {
        if let Some((code, state)) = connetto_dioxus_demo::platform::web::page_login_callback() {
            let _ = connetto_web::deliver_login_code(&code, &state);
        }
        let _ = js_sys::eval("window.close()");
        return;
    }
    dioxus::launch(connetto_dioxus_demo::platform::web::App);
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    connetto_dioxus_demo::platform::native::init_phone_logging();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    connetto_core::logging::init_stdout_with_default(
        connetto_dioxus_demo::platform::native::LOG_FILTER,
    );
    // Deliberate process-lifetime runtime: leaked so it outlives `launch`,
    // every session's tasks run on it for the life of the process.
    let runtime: &'static tokio::runtime::Runtime = Box::leak(Box::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime"),
    ));
    let _guard = runtime.enter();
    let builder = dioxus::LaunchBuilder::new();
    #[cfg(feature = "desktop")]
    let builder = builder.with_cfg(
        dioxus::desktop::Config::new()
            .with_icon(
                dioxus::desktop::icon_from_memory(include_bytes!("../../icons/icon.ico"))
                    .expect("decode the window icon"),
            )
            .with_window(
                dioxus::desktop::WindowBuilder::new()
                    .with_title(format!("connetto live demo (pid {})", std::process::id()))
                    .with_inner_size(dioxus::desktop::LogicalSize::new(1024.0, 800.0)),
            ),
    );
    builder.launch(connetto_dioxus_demo::platform::native::Shell);
}

// Declared for `dx`, which bundles `android/`, the module whose manifest turns
// off backup and device transfer. It stands in until Dioxus applies
// `[android.raw] application_attrs` and `[android] resources`, which dx 0.7.10
// parses and drops. Then both settings move into `Dioxus.toml` and this and
// `android/` are deleted.
#[cfg(target_os = "android")]
#[manganis::ffi("android")]
extern "Kotlin" {
    pub type ConnettoDemoBackupPolicy;
}
