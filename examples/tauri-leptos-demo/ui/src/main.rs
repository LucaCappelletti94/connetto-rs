//! The Leptos UI of the connetto Tauri demo. It renders the view the core
//! emits and calls the core's commands, and holds no client state itself.

use leptos::prelude::*;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], catch)]
    async fn invoke(command: &str) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "event"])]
    async fn listen(event: &str, handler: &Closure<dyn FnMut(JsValue)>) -> JsValue;
}

/// What the core emits as the `view` event, the core's `View`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
struct View {
    stage: String,
    detail: Option<String>,
    status: String,
    custody: String,
    gate: String,
    device: String,
    count: Option<i64>,
    error: Option<String>,
}

/// The payload of a Tauri event.
#[derive(Deserialize)]
struct Event {
    payload: View,
}

fn call(command: &'static str) {
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(err) = invoke(command).await {
            web_sys_log(&format!("{command} failed: {err:?}"));
        }
    });
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

    // The first view, then every change the core emits.
    wasm_bindgen_futures::spawn_local(async move {
        let handler = Closure::<dyn FnMut(JsValue)>::new(move |event: JsValue| {
            match serde_wasm_bindgen::from_value::<Event>(event) {
                Ok(event) => set_view.set(event.payload),
                Err(err) => web_sys_log(&format!("an unreadable view: {err}")),
            }
        });
        listen("view", &handler).await;
        handler.forget();
        match invoke("view")
            .await
            .map(serde_wasm_bindgen::from_value::<View>)
        {
            Ok(Ok(first)) => set_view.set(first),
            other => web_sys_log(&format!("reading the first view: {other:?}")),
        }
    });

    let line = "font-family: monospace; font-size: 0.85em; color: #555; margin: 0 0 8px 0;";
    view! {
        <div style="font-family: sans-serif; padding: 16px; max-width: 760px;">
            {move || match view.get().stage.as_str() {
                "ready" => view! {
                    <div>
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
