//! Browser harness proving the R23 passkey gate end-to-end.
//!
//! The wasm package must be pre-built before running the driver test:
//!
//! ```text
//! wasm-pack build examples/webauthn-unlock --target web
//! ```
//!
//! Then run the driver with:
//!
//! ```text
//! cargo +stable test -p connetto-webauthn-unlock --test webauthn_unlock
//! ```
//!
//! The native target sees an empty rlib. All wasm-bindgen exports are gated
//! with `#[cfg(target_arch = "wasm32")]`.
//!
//! The tab calls `connetto_web::unlock::serve_unlock(&worker)` synchronously
//! right after spawning, before the worker's first async yield, so any unlock
//! or enrol request the worker posts is answered immediately.

// ── wasm-only page and worker surface ──────────────────────────────────────

#[cfg(target_arch = "wasm32")]
mod inner {
    use anyhow::{Context as _, Result, anyhow};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use connetto_core::traits::ReplicaKeyStore as _;
    use connetto_web::{
        auth::{AuthError, IdbKeyStore, LOCKED_MESSAGE, provision_replica_key},
        unlock::serve_unlock,
    };
    use js_sys::Reflect;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;

    // ── constants ─────────────────────────────────────────────────────────

    const HARNESS_CHANNEL: &str = "webauthn-harness";
    const RESULT_EL: &str = "result";

    // ── tab-side thread-locals ────────────────────────────────────────────

    thread_local! {
        static WORKER: std::cell::RefCell<Option<web_sys::Worker>> =
            std::cell::RefCell::new(None);
        static GLUE_URL: std::cell::RefCell<String> =
            std::cell::RefCell::new(String::new());
        // Closures and the channel must stay alive until page unload so JS can
        // call them. Storing in thread-locals means Drop runs normally; no
        // mem::forget or Closure::forget is needed.
        static RESULT_HANDLER: std::cell::RefCell<
            Option<Closure<dyn Fn(web_sys::MessageEvent)>>,
        > = std::cell::RefCell::new(None);
        static RESULT_CHANNEL: std::cell::RefCell<Option<web_sys::BroadcastChannel>> =
            std::cell::RefCell::new(None);
        static RESTART_HANDLER: std::cell::RefCell<Option<Closure<dyn Fn()>>> =
            std::cell::RefCell::new(None);
    }

    // ── JS-error conversion ───────────────────────────────────────────────

    fn js_err(ctx: &str, e: JsValue) -> anyhow::Error {
        anyhow!("{ctx}: {e:?}")
    }

    // ── tab-side helpers ──────────────────────────────────────────────────

    fn spawn_worker(glue_url: &str) -> Result<web_sys::Worker> {
        let url = format!("/db-worker.js?glue={glue_url}");
        let mut opts = web_sys::WorkerOptions::new();
        opts.type_(web_sys::WorkerType::Module);
        web_sys::Worker::new_with_options(&url, &opts).map_err(|e| js_err("Worker::new", e))
    }

    // ── wasm-bindgen exports: tab side ────────────────────────────────────

    /// Spawn the dedicated worker, install the passkey unlock handler
    /// synchronously (before the worker's first await), and expose
    /// `window.restart_worker` for the driver to call between steps.
    ///
    /// `glue_url` must point to the wasm-pack JS glue file, e.g.
    /// `/pkg/connetto_webauthn_unlock.js`.
    #[wasm_bindgen]
    pub fn init_page(glue_url: &str) -> Result<(), JsValue> {
        init_inner(glue_url).map_err(|e| JsValue::from_str(&format!("{e:#}")))
    }

    fn init_inner(glue_url: &str) -> Result<()> {
        GLUE_URL.with(|c| *c.borrow_mut() = glue_url.to_owned());

        let worker = spawn_worker(glue_url)?;
        // Install the unlock handler before the worker's first async yield so
        // any enrol or unlock request the worker posts finds a handler.
        serve_unlock(&worker).map_err(|e| js_err("serve_unlock", e))?;
        WORKER.with(|c| *c.borrow_mut() = Some(worker));

        // Listen for step results on the harness channel. Write each result to
        // `window.__step_result` (the driver reads this) and to the DOM
        // element for manual inspection.
        let ch = web_sys::BroadcastChannel::new(HARNESS_CHANNEL)
            .map_err(|e| js_err("BroadcastChannel::new", e))?;
        let on_result = Closure::wrap(Box::new(|e: web_sys::MessageEvent| {
            let msg = e.data().as_string().unwrap_or_default();
            let global = js_sys::global();
            let _ = Reflect::set(
                &global,
                &JsValue::from_str("__step_result"),
                &JsValue::from_str(&msg),
            );
            if let Some(win) = web_sys::window() {
                if let Some(doc) = win.document() {
                    if let Some(el) = doc.get_element_by_id(RESULT_EL) {
                        el.set_text_content(Some(&msg));
                    }
                }
            }
            web_sys::console::log_1(&JsValue::from_str(&format!("harness: {msg}")));
        }) as Box<dyn Fn(web_sys::MessageEvent)>);
        ch.set_onmessage(Some(on_result.as_ref().unchecked_ref()));
        // Store both in thread-locals so JS can invoke them and Drop runs at
        // page unload rather than here.
        RESULT_HANDLER.with(|c| *c.borrow_mut() = Some(on_result));
        RESULT_CHANNEL.with(|c| *c.borrow_mut() = Some(ch));

        // Expose `window.restart_worker` for the driver.
        let restart = Closure::wrap(Box::new(|| {
            wasm_bindgen_futures::spawn_local(async {
                if let Err(e) = do_restart().await {
                    web_sys::console::error_1(&JsValue::from_str(&format!("{e:#}")));
                }
            });
        }) as Box<dyn Fn()>);
        let global = js_sys::global();
        Reflect::set(
            &global,
            &JsValue::from_str("restart_worker"),
            restart.as_ref().unchecked_ref(),
        )
        .map_err(|e| js_err("Reflect::set restart_worker", e))?;
        RESTART_HANDLER.with(|c| *c.borrow_mut() = Some(restart));

        Ok(())
    }

    /// Terminate the old worker and spawn a fresh one, reinstalling the unlock
    /// handler before the worker's first async yield.
    async fn do_restart() -> Result<()> {
        let glue = GLUE_URL.with(|c| c.borrow().clone());
        WORKER.with(|c| {
            if let Some(w) = c.borrow().as_ref() {
                w.terminate();
            }
            *c.borrow_mut() = None;
        });
        let worker = spawn_worker(&glue)?;
        serve_unlock(&worker).map_err(|e| js_err("serve_unlock (restart)", e))?;
        WORKER.with(|c| *c.borrow_mut() = Some(worker));
        Ok(())
    }

    // ── worker-side state ─────────────────────────────────────────────────

    thread_local! {
        static PENDING_RESOLVE: std::cell::RefCell<Option<js_sys::Function>> =
            std::cell::RefCell::new(None);
    }

    // ── wasm-bindgen exports: worker side ─────────────────────────────────

    /// Called by `db-worker.js` whenever the tab posts a reply to the worker.
    /// Resolves the one-shot promise that `ask_tab` is awaiting.
    #[wasm_bindgen]
    pub fn receive_tab_answer(data: JsValue) {
        PENDING_RESOLVE.with(|c| {
            if let Some(resolve) = c.borrow_mut().take() {
                let _ = resolve.call1(&JsValue::NULL, &data);
            }
        });
    }

    /// Worker entry point: open the key store and run whichever step the
    /// current IDB state calls for.
    ///
    /// Returns `Err(JsValue)` only for unrecoverable infrastructure failures
    /// (the WASM runtime could not post a message, etc.). Test-level outcomes
    /// are reported via the harness `BroadcastChannel` so the driver reads
    /// them from the DOM without relying on JS exceptions.
    #[wasm_bindgen]
    pub async fn boot_worker() -> Result<(), JsValue> {
        boot_inner()
            .await
            .map_err(|e| JsValue::from_str(&format!("{e:#}")))
    }

    // ── worker-side helpers ───────────────────────────────────────────────

    fn str_field(obj: &JsValue, key: &str) -> Result<String> {
        Reflect::get(obj, &JsValue::from_str(key))
            .map_err(|e| js_err(&format!("Reflect::get({key})"), e))?
            .as_string()
            .ok_or_else(|| anyhow!("field '{key}' is not a string"))
    }

    fn key_field(obj: &JsValue, key: &str) -> Result<web_sys::CryptoKey> {
        let val = Reflect::get(obj, &JsValue::from_str(key))
            .map_err(|e| js_err(&format!("Reflect::get({key})"), e))?;
        Ok(val.unchecked_into())
    }

    async fn ask_tab(request: &js_sys::Object) -> Result<JsValue> {
        let scope: web_sys::DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
        scope
            .post_message(&JsValue::from(request.clone()))
            .map_err(|e| js_err("DedicatedWorkerGlobalScope::post_message", e))?;

        let promise = js_sys::Promise::new(&mut |resolve, _reject| {
            PENDING_RESOLVE.with(|c| *c.borrow_mut() = Some(resolve));
        });
        JsFuture::from(promise)
            .await
            .map_err(|e| js_err("JsFuture(tab reply)", e))
    }

    fn report(msg: &str) {
        if let Ok(ch) = web_sys::BroadcastChannel::new(HARNESS_CHANNEL) {
            let _ = ch.post_message(&JsValue::from_str(msg));
        }
        web_sys::console::log_1(&JsValue::from_str(&format!("worker: {msg}")));
    }

    async fn boot_inner() -> Result<()> {
        let store = IdbKeyStore::open().await.context("IdbKeyStore::open")?;
        let enrolled = store.enrolled().await.context("IdbKeyStore::enrolled")?;
        if enrolled.is_empty() {
            run_step1(&store).await
        } else {
            run_step2_or_3(&store, &enrolled).await
        }
    }

    /// First boot: request enrolment, adopt the derived key, write the test
    /// record, report `step1:ok`.
    async fn run_step1(store: &IdbKeyStore) -> Result<()> {
        let req = js_sys::Object::new();
        Reflect::set(
            &req,
            &JsValue::from_str("kind"),
            &JsValue::from_str("enrol"),
        )
        .map_err(|e| js_err("Reflect::set kind", e))?;
        let reply = ask_tab(&req).await?;
        let kind = str_field(&reply, "kind")?;

        if kind == "key" {
            let cred_id = URL_SAFE_NO_PAD
                .decode(str_field(&reply, "credentialId")?)
                .context("decoding credentialId")?;
            let hkdf = key_field(&reply, "key")?;

            store
                .adopt_derived(hkdf, &cred_id)
                .await
                .map_err(|e: AuthError| anyhow!(e))
                .context("adopt_derived")?;

            // Write the test record under the derived KEK. Step 2 reads it
            // back to prove the same key is re-derived on the next boot.
            provision_replica_key(store, "harness-test")
                .await
                .map_err(|e: AuthError| anyhow!(e))
                .context("provision_replica_key")?;

            report("step1:ok");
        } else {
            // Carry the detail: a bare kind hides whether the platform
            // refused or the ceremony threw, which is the difference between a
            // real limitation and a bug in this code.
            let detail = str_field(&reply, "detail").unwrap_or_default();
            report(&format!("step1:declined:{kind}:{detail}"));
        }
        Ok(())
    }

    /// Later boot: request an assertion, use the derived key, load the test
    /// record. When the authenticator is gone (deleted by the driver between
    /// steps), `serve_unlock` catches the WebAuthn `NotAllowedError` and sends
    /// `{ kind: "declined" }`, mapping to `step3:locked`.
    async fn run_step2_or_3(store: &IdbKeyStore, enrolled: &[Vec<u8>]) -> Result<()> {
        let creds_arr = js_sys::Array::new();
        for id in enrolled {
            creds_arr.push(&JsValue::from_str(&URL_SAFE_NO_PAD.encode(id)));
        }
        let req = js_sys::Object::new();
        Reflect::set(
            &req,
            &JsValue::from_str("kind"),
            &JsValue::from_str("unlock"),
        )
        .map_err(|e| js_err("Reflect::set kind", e))?;
        Reflect::set(&req, &JsValue::from_str("credentials"), &creds_arr.into())
            .map_err(|e| js_err("Reflect::set credentials", e))?;

        let reply = ask_tab(&req).await?;
        let kind = str_field(&reply, "kind")?;

        if kind == "key" {
            let cred_id = URL_SAFE_NO_PAD
                .decode(str_field(&reply, "credentialId")?)
                .context("decoding credentialId")?;
            let hkdf = key_field(&reply, "key")?;

            store
                .use_derived(hkdf, &cred_id)
                .await
                .map_err(|e: AuthError| anyhow!(e))
                .context("use_derived")?;

            // Load the record written in step 1. Success proves the PRF output
            // is stable (Q5) and the HKDF derivation reproduces the same
            // AES-GCM KEK across worker restarts.
            match store.load("harness-test").await {
                Ok(_) => report("step2:ok"),
                Err(e) if e.to_string() == LOCKED_MESSAGE => report("step3:locked"),
                Err(e) => report(&format!("step2:err:load:{e}")),
            }
        } else {
            // Authenticator deleted: serve_unlock sent "declined". This is the
            // step-3 outcome the driver asserts on.
            report("step3:locked");
        }
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
pub use inner::{boot_worker, init_page, receive_tab_answer};
