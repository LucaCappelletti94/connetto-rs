//! Yew adapter for connetto live queries.
//!
//! One hook, [`use_live`], serves both live handle kinds through
//! [`LiveHandle`]: a row query yields state of `Vec<R>`, a scalar aggregate
//! state of `Option<V>`, both chosen at compile time by the query's shape
//! through [`Watchable`]. The subscription is owned by a driver task the hook
//! aborts on unmount, dropping the handle, which unsubscribes server-side:
//! connetto's drop-unsubscribe contract composes with the component lifecycle
//! with no extra wiring.
//!
//! Yew's [`spawn_local`] is detached, unlike a
//! dioxus scope task, so the hook cannot rely on the component dropping the
//! task. It wraps the driver in [`Abortable`] and returns an effect cleanup
//! that aborts it, which drops the live handle at its next await point.

use connetto_client::dsl::Watchable;
use connetto_client::{ConnettoClient, LiveHandle};
use connetto_core::traits::{MaybeSend, Transport};
use futures_util::future::{AbortHandle, Abortable};
use yew::platform::spawn_local;
use yew::prelude::*;

/// A live query bound to a component: the snapshot state and an error slot.
///
/// [`value`](Self::value) is the type's `Default` until the first refresh
/// lands (an empty `Vec` for rows, `None` for a scalar). [`error`](Self::error)
/// becomes `Some` when subscribing failed or the driving client stopped, and
/// the snapshot keeps its last value in that case.
pub struct UseLive<S> {
    value: UseStateHandle<S>,
    error: UseStateHandle<Option<String>>,
}

impl<S: Clone> UseLive<S> {
    /// The current live snapshot.
    #[must_use]
    pub fn value(&self) -> S {
        (*self.value).clone()
    }

    /// The current error, if the subscription or driving client failed.
    #[must_use]
    pub fn error(&self) -> Option<String> {
        (*self.error).clone()
    }
}

/// Subscribe this component to a live query.
///
/// The query and client are captured on first render (re-render with a
/// different query has no effect, remount the component to change it). The
/// subscription lives exactly as long as the component: unmount aborts the
/// driver task, drops the handle, and the client's pump sends the unsubscribe.
///
/// Works for both shapes through the compile-time dispatch: a row query
/// produces `UseLive<Vec<R>>` (annotate `R` as with diesel's `load`), a scalar
/// aggregate produces `UseLive<Option<V>>` with `V` inferred from the query
/// itself.
#[hook]
pub fn use_live<T, Q, R>(
    client: &ConnettoClient<T>,
    query: Q,
) -> UseLive<<Q::Handle as LiveHandle>::Snapshot>
where
    T: Transport + MaybeSend + 'static,
    T::Error: core::fmt::Display,
    Q: Watchable<T, R> + 'static,
    Q::Handle: 'static,
    <Q::Handle as LiveHandle>::Snapshot: Default + Clone + 'static,
{
    let value = use_state(<Q::Handle as LiveHandle>::Snapshot::default);
    let error = use_state(|| None::<String>);
    {
        let value = value.clone();
        let error = error.clone();
        let client = client.clone();
        use_effect_with((), move |()| {
            let (abort, registration) = AbortHandle::new_pair();
            let driver = async move {
                match query.live(&client).await {
                    Ok(mut handle) => {
                        value.set(handle.snapshot());
                        loop {
                            match handle.changed().await {
                                Ok(()) => value.set(handle.snapshot()),
                                Err(err) => {
                                    error.set(Some(err.to_string()));
                                    break;
                                }
                            }
                        }
                    }
                    Err(err) => error.set(Some(err.to_string())),
                }
            };
            spawn_local(async move {
                let _ = Abortable::new(driver, registration).await;
            });
            move || abort.abort()
        });
    }
    UseLive { value, error }
}
