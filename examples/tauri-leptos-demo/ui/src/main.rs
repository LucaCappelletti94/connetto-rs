//! The Leptos UI of the connetto Tauri demo. It renders the view the core
//! emits and calls the core's commands, and holds no client state itself.

use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], catch)]
    async fn invoke(command: &str, args: JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "event"])]
    async fn listen(event: &str, handler: &Closure<dyn FnMut(JsValue)>) -> JsValue;
}

/// What the core emits as the `view` event, the core's `View`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
struct View {
    stage: String,
    detail: Option<String>,
    user: String,
    status: String,
    custody: String,
    gate: String,
    device: String,
    count: Option<i64>,
    error: Option<String>,
    wipe: Wipe,
    notice: Option<String>,
}

/// The core's `Wipe`, where signing out stands.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum Wipe {
    #[default]
    Idle,
    ConfirmForce {
        unsynced: usize,
    },
    Failed {
        message: String,
    },
}

/// The payload of a Tauri event.
#[derive(Deserialize)]
struct Event {
    payload: View,
}

/// The `sign_out` command's arguments.
#[derive(Serialize)]
struct SignOut {
    discard_unsynced: bool,
}

fn call(command: &'static str) {
    call_with(command, JsValue::UNDEFINED);
}

fn call_with(command: &'static str, args: JsValue) {
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(err) = invoke(command, args).await {
            web_sys_log(&format!("{command} failed: {err:?}"));
        }
    });
}

fn sign_out(discard_unsynced: bool) {
    // Tauri reads command arguments from a plain object, which the default serializer does not make.
    let serializer = serde_wasm_bindgen::Serializer::json_compatible();
    match (SignOut { discard_unsynced }).serialize(&serializer) {
        Ok(args) => call_with("sign_out", args),
        Err(err) => web_sys_log(&format!("sign_out arguments: {err}")),
    }
}

fn web_sys_log(message: &str) {
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = console)]
        fn error(message: &str);
    }
    error(message);
}

#[component]
fn App() -> impl IntoView {
    let (view, set_view) = signal(View::default());

    // Every view arrives as the `view` event, the first one too, which the
    // `view` command emits once the listener stands.
    wasm_bindgen_futures::spawn_local(async move {
        let handler = Closure::<dyn FnMut(JsValue)>::new(move |event: JsValue| {
            match serde_wasm_bindgen::from_value::<Event>(event) {
                Ok(event) => set_view.set(event.payload),
                Err(err) => web_sys_log(&format!("an unreadable view: {err}")),
            }
        });
        listen("view", &handler).await;
        handler.forget();
        if let Err(err) = invoke("view", JsValue::UNDEFINED).await {
            web_sys_log(&format!("asking for the first view: {err:?}"));
        }
    });

    let line = "font-family: monospace; font-size: 0.85em; color: #555; margin: 0 0 8px 0;";
    view! {
        <div style="font-family: sans-serif; padding: 16px; max-width: 760px;">
            {move || match view.get().stage.as_str() {
                "ready" => view! {
                    <div>
                        <div style="background: #f0f4ff; border: 1px solid #c0c8e8; border-radius: 6px; padding: 10px 14px; margin-bottom: 16px;">
                            <p style=line>"Signed in as: " {move || view.get().user}</p>
                            {move || match view.get().wipe {
                                Wipe::Idle => view! {
                                    <button on:click=move |_| sign_out(false)>
                                        "Sign out (wipe local replica)"
                                    </button>
                                }
                                .into_any(),
                                Wipe::ConfirmForce { unsynced } => view! {
                                    <div>
                                        <p>{unsynced} " write(s) are not yet synced and will be permanently lost."</p>
                                        <button on:click=move |_| sign_out(true)>"Confirm: discard and wipe"</button>
                                        <button on:click=move |_| call("dismiss_wipe")>"Cancel"</button>
                                    </div>
                                }
                                .into_any(),
                                Wipe::Failed { message } => view! {
                                    <div>
                                        <p style="color: #b00;">{message}</p>
                                        <button on:click=move |_| call("dismiss_wipe")>"Dismiss"</button>
                                    </div>
                                }
                                .into_any(),
                            }}
                        </div>
                        <p style=line>"status: " {move || view.get().status}</p>
                        <p style=line>"custody: " {move || view.get().custody}</p>
                        <p style=line>"gate: " {move || view.get().gate}</p>
                        <p style=line>"device: " {move || view.get().device}</p>
                        <Show when=move || view.get().gate != "open">
                            <button on:click=move |_| call("unlock")>"Unlock"</button>
                        </Show>
                        <h1>"connetto live demo"</h1>
                        <p>
                            "COUNT(*) pushed by the server: "
                            <strong>
                                {move || view.get().count.map_or_else(|| "pending".to_owned(), |count| count.to_string())}
                            </strong>
                        </p>
                        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                            <button on:click=move |_| call("insert_backend")>
                                "Insert via Postgres (backend writer)"
                            </button>
                            <button on:click=move |_| call("insert_local")>
                                "Insert locally (client write)"
                            </button>
                        </div>
                        <p style="color: #b00;">{move || view.get().error.unwrap_or_default()}</p>
                    </div>
                }
                .into_any(),
                "failed" => view! {
                    <div>
                        <h2>"connetto demo cannot start"</h2>
                        <p style="color: #a33;">{move || view.get().detail.unwrap_or_default()}</p>
                    </div>
                }
                .into_any(),
                _ => view! {
                    <div>
                        <h2>"Signing in"</h2>
                        <p style="color: #a33;">{move || view.get().notice.unwrap_or_default()}</p>
                        <p>"A browser page opens for the login. Come back here once you have signed in."</p>
                    </div>
                }
                .into_any(),
            }}
        </div>
    }
}

fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(App);
}
