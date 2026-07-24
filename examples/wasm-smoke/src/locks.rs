//! Web Locks liveness for the relay topology.
//!
//! `SharedWorker` ports have no reliable close event, so a dead tab would
//! leave its relay session parked forever. The protocol: a tab that wants
//! dead-tab cleanup holds a browser lock named after its client id BEFORE
//! connecting. At handshake the hub's owner probes the lock, and a free
//! lock means the tab opted out and is never reaped. A held lock is
//! watched, and the watch being granted means the holder (and with it the
//! tab) is gone, since the browser releases web locks when their context
//! dies.

use futures_channel::oneshot;
use js_sys::Promise;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{LockManager, LockOptions, WorkerGlobalScope};

/// The web lock name liveness uses for a given client id.
#[must_use]
pub fn tab_lock_name(client_id: &str) -> String {
    format!("connetto-tab-{client_id}")
}

/// The context's lock manager, from the window or a worker scope.
fn lock_manager() -> LockManager {
    if let Some(window) = web_sys::window() {
        return window.navigator().locks();
    }
    let scope: WorkerGlobalScope = js_sys::global().unchecked_into();
    scope.navigator().locks()
}

/// A held web lock. The browser releases it automatically when the holding
/// context dies, which is exactly the liveness signal.
pub struct HeldLock {
    release: js_sys::Function,
}

impl HeldLock {
    /// Release the lock explicitly, simulating the holder's death for the
    /// watcher side.
    pub fn release(self) {
        let _ = self.release.call0(&JsValue::NULL);
    }
}

/// Acquire and hold the lock `name`. Resolves once the lock is actually
/// held, so a caller can order acquisition strictly before connecting.
pub async fn hold_lock(name: &str) -> HeldLock {
    let (tx, rx) = oneshot::channel::<js_sys::Function>();
    let callback = Closure::once_into_js(move |_lock: JsValue| -> JsValue {
        // The lock is held for as long as the returned promise stays
        // pending. Its resolve function is the release handle.
        let mut release = None;
        let held = Promise::new(&mut |resolve, _reject| release = Some(resolve));
        if let Some(release) = release {
            let _ = tx.send(release);
        }
        held.into()
    });
    let _pending = lock_manager().request_with_callback(name, callback.unchecked_ref());
    let release = rx
        .await
        .expect("the lock grant callback always sends the release function");
    HeldLock { release }
}

/// Whether anything currently holds the lock `name`.
pub async fn lock_is_held(name: &str) -> bool {
    let (tx, rx) = oneshot::channel::<bool>();
    let callback = Closure::once_into_js(move |lock: JsValue| -> JsValue {
        // With ifAvailable the callback receives null when the lock is
        // already held elsewhere, and the grant when it is free.
        let _ = tx.send(lock.is_null());
        JsValue::UNDEFINED
    });
    let options = LockOptions::new();
    options.set_if_available(true);
    let promise =
        lock_manager().request_with_options_and_callback(name, &options, callback.unchecked_ref());
    let _ = JsFuture::from(promise).await;
    rx.await.unwrap_or(false)
}

/// Block until the lock `name` can be acquired, then release it at once.
/// With the holder-owns-the-lock protocol this resolves when the holder is
/// gone.
pub async fn wait_until_free(name: &str) {
    let callback = Closure::once_into_js(|_lock: JsValue| -> JsValue { JsValue::UNDEFINED });
    let promise = lock_manager().request_with_callback(name, callback.unchecked_ref());
    let _ = JsFuture::from(promise).await;
}
