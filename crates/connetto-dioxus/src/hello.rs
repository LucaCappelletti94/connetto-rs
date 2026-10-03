//! The window a Windows Hello prompt opens over (R53).
//!
//! The application's desktop window anchors the prompt connetto raises over
//! its gated secrets. Windows disables that window while the prompt is up, so
//! the window cannot be closed under it.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use connetto_client::{HelloCancellation, HelloOwner, HelloWindow};
use dioxus_core::{use_drop, use_hook};
use dioxus_desktop::tao::platform::windows::WindowExtWindows;
use dioxus_desktop::tao::window::Window;
use dioxus_desktop::window;

/// The prompt in flight, if any, and whether the component is gone.
#[derive(Default)]
struct State {
    active: Option<(u64, HelloCancellation)>,
    next: u64,
    unmounted: bool,
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The provider connetto holds. It holds the window weakly.
struct Owner {
    window: Weak<Window>,
    state: Arc<Mutex<State>>,
}

impl HelloOwner for Owner {
    fn lease(&self, cancel: HelloCancellation) -> Option<Arc<dyn HelloWindow>> {
        let window = self.window.upgrade()?;
        let mut state = lock(&self.state);
        if state.unmounted {
            return None;
        }
        state.next = state.next.wrapping_add(1);
        let id = state.next;
        state.active = Some((id, cancel));
        drop(state);
        // Windows shows the prompt only over a window in front, and a login leaves the browser there.
        window.set_focus();
        Some(Arc::new(Lease {
            window,
            id,
            state: Arc::clone(&self.state),
        }))
    }
}

/// A strong hold on the window for one prompt, kept until Windows returns.
struct Lease {
    window: Arc<Window>,
    id: u64,
    state: Arc<Mutex<State>>,
}

impl HelloWindow for Lease {
    fn hwnd(&self) -> *mut core::ffi::c_void {
        std::ptr::with_exposed_provenance_mut(self.window.hwnd().cast_unsigned())
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = lock(&self.state);
        if state
            .active
            .as_ref()
            .is_some_and(|(active, _)| *active == self.id)
        {
            state.active = None;
        }
    }
}

/// The owner a Windows Hello prompt over connetto's gated secrets opens over,
/// this component's desktop window, for
/// [`KeyringAuth::with_hello_owner`](connetto_client::KeyringAuth::with_hello_owner).
///
/// Each prompt holds the window until Windows returns. Unmounting the
/// component cancels a prompt in flight and lends the window to no later one.
pub fn use_hello_owner() -> Arc<dyn HelloOwner> {
    let desktop = window();
    let (owner, state) = use_hook(|| {
        let state = Arc::new(Mutex::new(State::default()));
        let owner: Arc<dyn HelloOwner> = Arc::new(Owner {
            window: Arc::downgrade(&desktop.window),
            state: Arc::clone(&state),
        });
        (owner, state)
    });
    use_drop(move || {
        let mut state = lock(&state);
        state.unmounted = true;
        if let Some((_, cancel)) = &state.active {
            cancel.cancel();
        }
    });
    owner
}
