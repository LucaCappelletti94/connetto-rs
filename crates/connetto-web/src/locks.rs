//! Web Locks liveness for the relay topology.
//!
//! A `MessagePort` and a `BroadcastChannel` both have no reliable close event,
//! so a dead tab would leave its relay session parked forever. The protocol: a
//! tab that wants dead-tab cleanup holds a browser lock named after its client
//! id BEFORE connecting. At handshake the hub's owner probes the lock, and a
//! free lock means the tab opted out and is never reaped. A held lock is
//! watched, and the watch being granted means the holder (and with it the tab)
//! is gone, since the browser releases web locks when their context dies.

use futures_channel::oneshot;
use js_sys::Promise;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::JsFuture;
use web_sys::{LockManager, LockOptions, WorkerGlobalScope};

#[wasm_bindgen]
extern "C" {
    type RawLockManager;
    #[wasm_bindgen(method, js_name = request)]
    fn request_lock(this: &RawLockManager, name: &str, callback: &js_sys::Function) -> Promise;

    #[wasm_bindgen(method, js_name = request)]
    fn request_lock_with_options(
        this: &RawLockManager,
        name: &str,
        options: &LockOptions,
        callback: &js_sys::Function,
    ) -> Promise;
}

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
///
/// # Panics
///
/// Panics if the browser's `LockManager.request` callback is invoked but the `Promise` constructor does not call its resolver function synchronously, which cannot occur in any conforming browser environment.
pub async fn hold_lock(name: &str) -> HeldLock {
    let (tx, rx) = oneshot::channel::<js_sys::Function>();
    let callback = Closure::once_into_js(move |_lock: JsValue| -> JsValue {
        // The browser holds the lock while this promise is pending.
        let mut release = None;
        let held = Promise::new(&mut |resolve, _reject| release = Some(resolve));
        if let Some(release) = release {
            let _ = tx.send(release);
        }
        held.into()
    });
    let manager = lock_manager();
    let _pending = manager
        .unchecked_ref::<RawLockManager>()
        .request_lock(name, callback.unchecked_ref());
    let release = rx
        .await
        .expect("the lock grant callback always sends the release function");
    HeldLock { release }
}

/// Whether anything currently holds the lock `name`.
pub async fn lock_is_held(name: &str) -> bool {
    let (tx, rx) = oneshot::channel::<bool>();
    let callback = Closure::once_into_js(move |lock: JsValue| -> JsValue {
        // `ifAvailable` returns `null` while another context holds the lock.
        let _ = tx.send(lock.is_null());
        JsValue::UNDEFINED
    });
    let options = LockOptions::new();
    options.set_if_available(true);
    let manager = lock_manager();
    let promise = manager
        .unchecked_ref::<RawLockManager>()
        .request_lock_with_options(name, &options, callback.unchecked_ref());
    let _ = JsFuture::from(promise).await;
    rx.await.unwrap_or(false)
}

/// Waits until `name` is free.
pub async fn wait_until_free(name: &str) {
    let callback = Closure::once_into_js(|_lock: JsValue| -> JsValue { JsValue::UNDEFINED });
    let manager = lock_manager();
    let promise = manager
        .unchecked_ref::<RawLockManager>()
        .request_lock(name, callback.unchecked_ref());
    let _ = JsFuture::from(promise).await;
}
