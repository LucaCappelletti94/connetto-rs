//! Dioxus adapter for connetto live queries.
//!
//! One hook, [`use_live`], serves both live handle kinds through
//! [`LiveHandle`]: a row query yields a signal of `Vec<R>`, a scalar
//! aggregate a signal of `Option<V>`, both chosen at compile time by the
//! query's shape through [`Watchable`]. The handle is owned by a
//! component-scoped task, so unmounting the component drops the handle,
//! which unsubscribes server-side: connetto's drop-unsubscribe contract
//! composes with the component lifecycle with no extra wiring.
//!
//! A second hook, [`use_live_fn`], covers boxed (`.into_boxed()`) and
//! dynamically built row queries: they carry no compile-time aggregation
//! marker and are not `Clone`, so they cannot ride [`use_live`]. It takes a
//! query-builder closure instead of a query value and yields the same
//! `UseLive<Vec<R>>`, sharing the identical lifecycle and drop-unsubscribe
//! contract.

use connetto_client::dsl::Watchable;
use connetto_client::{ConnettoClient, LiveHandle};
use connetto_core::traits::{MaybeSend, Transport};
use diesel::SqliteConnection;
use diesel::query_builder::QueryFragment;
use diesel::query_dsl::methods::LoadQuery;
use diesel::sqlite::Sqlite;
use dioxus_core::{spawn, use_hook};
use dioxus_hooks::use_signal;
use dioxus_signals::{ReadSignal, WritableExt};

/// A live query bound to a component: the snapshot signal and an error slot.
///
/// Reading [`value`](Self::value) inside a component subscribes that
/// component to the signal, so only components that read it re-render when
/// the snapshot moves.
pub struct UseLive<S: 'static> {
    value: ReadSignal<S>,
    error: ReadSignal<Option<String>>,
}

impl<S> Clone for UseLive<S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S> Copy for UseLive<S> {}

impl<S: 'static> UseLive<S> {
    /// The live snapshot: the type's `Default` until the first refresh lands
    /// (an empty `Vec` for rows, `None` for a scalar).
    #[must_use]
    pub fn value(&self) -> ReadSignal<S> {
        self.value
    }

    /// The error slot: `Some` when subscribing failed or the driving client
    /// stopped. The snapshot signal keeps its last value in that case.
    #[must_use]
    pub fn error(&self) -> ReadSignal<Option<String>> {
        self.error
    }
}

/// Subscribe this component to a live query.
///
/// The query and client are captured on first render (re-render with a
/// different query has no effect, remount the component to change it). The
/// subscription lives exactly as long as the component: the handle is owned
/// by a scope-bound task, so unmount cancels the task, drops the handle, and
/// the client's pump sends the unsubscribe.
///
/// Works for both shapes through the compile-time dispatch: a row query
/// produces `UseLive<Vec<R>>` (annotate `R` as with diesel's `load`), a
/// scalar aggregate produces `UseLive<Option<V>>` with `V` inferred from the
/// query itself.
pub fn use_live<T, Q, R>(
    client: &ConnettoClient<T>,
    query: Q,
) -> UseLive<<Q::Handle as LiveHandle>::Snapshot>
where
    T: Transport + MaybeSend + 'static,
    T::Error: core::fmt::Display,
    Q: Watchable<T, R> + 'static,
    Q::Handle: 'static,
    <Q::Handle as LiveHandle>::Snapshot: Default + 'static,
{
    let mut value = use_signal(<Q::Handle as LiveHandle>::Snapshot::default);
    let mut error = use_signal(|| None::<String>);
    let client = client.clone();
    use_hook(move || {
        spawn(async move {
            match query.live(&client).await {
                Ok(mut handle) => {
                    value.set(handle.snapshot());
                    loop {
                        match handle.changed().await {
                            Ok(()) => value.set(handle.snapshot()),
                            Err(err) => {
                                error.set(Some(err.to_string()));
                                return;
                            }
                        }
                    }
                }
                Err(err) => error.set(Some(err.to_string())),
            }
        })
    });
    UseLive {
        value: value.into(),
        error: error.into(),
    }
}

/// Subscribe this component to a boxed or dynamically built row query.
///
/// The row-query peer of [`use_live`] for a query that cannot carry the
/// compile-time dispatch marker [`use_live`] needs: a boxed (`.into_boxed()`)
/// or otherwise dynamically built query, which is also not `Clone`. In place
/// of a query value it takes `build`, a closure that yields a fresh query
/// instance on each call, and drives it through
/// [`ConnettoClient::watch_fn`](connetto_client::ConnettoClient::watch_fn).
///
/// `build` is captured on first render and re-invoked for the initial read and
/// every refresh, so it MUST be pure and stable: each call has to build an
/// equivalent query with the same SQL, tables, and binds. The subscription
/// lives exactly as long as the component, unmount cancels the scope-bound
/// task, drops the handle, and the client's pump sends the unsubscribe.
///
/// This is the row path only. A boxed aggregate query has no row answer here,
/// drive it through
/// [`watch_value_with`](connetto_client::ConnettoClient::watch_value_with).
pub fn use_live_fn<T, F, Q, R>(client: &ConnettoClient<T>, build: F) -> UseLive<Vec<R>>
where
    T: Transport + MaybeSend + 'static,
    T::Error: core::fmt::Display,
    F: Fn() -> Q + Send + 'static,
    Q: QueryFragment<Sqlite> + for<'query> LoadQuery<'query, SqliteConnection, R>,
    R: Clone + PartialEq + Send + Sync + 'static,
{
    let mut value = use_signal(Vec::<R>::new);
    let mut error = use_signal(|| None::<String>);
    let client = client.clone();
    use_hook(move || {
        spawn(async move {
            match client.watch_fn(build).await {
                Ok(mut handle) => {
                    value.set(handle.snapshot());
                    loop {
                        match handle.changed().await {
                            Ok(()) => value.set(handle.snapshot()),
                            Err(err) => {
                                error.set(Some(err.to_string()));
                                return;
                            }
                        }
                    }
                }
                Err(err) => error.set(Some(err.to_string())),
            }
        })
    });
    UseLive {
        value: value.into(),
        error: error.into(),
    }
}
