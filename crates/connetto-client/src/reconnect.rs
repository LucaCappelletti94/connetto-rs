//! Seams for the shared reconnect driver.
//!
//! The reconnect loop itself lives in the client pump (see
//! [`ConnettoClient::with_reconnect`](crate::ConnettoClient::with_reconnect)):
//! on a transport drop it backs off, asks the [`TransportFactory`] for a
//! fresh connection, resumes the session with the highest applied cursor,
//! and re-declares every live subscription, all without dropping a single
//! [`LiveQuery`](crate::LiveQuery) or [`LiveValue`](crate::LiveValue)
//! handle. The server then replays what its oplog retained past the cursor
//! as ordinary live patches, or orders a full resync.
//!
//! This module holds only the platform seams, so the one state machine
//! serves native and wasm alike: the factory makes connections, the
//! [`Sleeper`] waits between attempts, and the driving mode is whatever
//! spawns the pump future. No tokio types appear in any signature, and the
//! futures are bound by [`MaybeSend`], vacuous on wasm.

use core::fmt::Display;
use core::time::Duration;

use connetto_core::traits::{MaybeSend, Transport};

/// Backoff and retry policy for the reconnect driver.
#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    /// Wait before the first attempt. Doubles per failed attempt.
    pub initial_backoff: Duration,
    /// Ceiling for the doubling backoff.
    pub max_backoff: Duration,
    /// Give up after this many attempts, `None` keeps trying forever. On
    /// giving up the pump broadcasts
    /// [`ClientEvent::Closed`](crate::ClientEvent) and exits, exactly like a
    /// pump built without reconnect.
    pub max_attempts: Option<u32>,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(5),
            max_attempts: None,
        }
    }
}

/// Makes fresh transports for the reconnect driver.
///
/// Implemented for any `FnMut` closure returning a connect future, which is
/// the common form: a closure capturing the server address on native, or
/// the WebSocket URL on wasm.
pub trait TransportFactory {
    /// The transport this factory produces.
    type Transport: Transport + MaybeSend + 'static;
    /// Connect failure, retried under the policy.
    type Error: Display;

    /// Open a fresh connection to the server.
    fn connect(&mut self)
    -> impl Future<Output = Result<Self::Transport, Self::Error>> + MaybeSend;
}

impl<F, Fut, T, E> TransportFactory for F
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>> + MaybeSend,
    T: Transport + MaybeSend + 'static,
    E: Display,
{
    type Transport = T;
    type Error = E;

    fn connect(&mut self) -> impl Future<Output = Result<T, E>> + MaybeSend {
        self()
    }
}

/// Platform sleep injected into the backoff loop.
///
/// Implemented for any `FnMut(Duration)` closure returning a future, and by
/// [`TokioSleeper`] on native. Wasm injects a `setTimeout` wrapper.
pub trait Sleeper {
    /// Resolve after roughly `duration`.
    fn sleep(&mut self, duration: Duration) -> impl Future<Output = ()> + MaybeSend;
}

impl<F, Fut> Sleeper for F
where
    F: FnMut(Duration) -> Fut,
    Fut: Future<Output = ()> + MaybeSend,
{
    fn sleep(&mut self, duration: Duration) -> impl Future<Output = ()> + MaybeSend {
        self(duration)
    }
}

/// [`Sleeper`] over the ambient tokio runtime's timer.
#[cfg(feature = "native-transport")]
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioSleeper;

#[cfg(feature = "native-transport")]
impl Sleeper for TokioSleeper {
    async fn sleep(&mut self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// Factory type for pumps configured without reconnect. Never invoked: the
/// pump only consults the factory when a reconnect driver is present. The
/// pending future keeps even a misuse panic-free.
pub(crate) struct NoReconnect<T>(core::marker::PhantomData<fn() -> T>);

impl<T> TransportFactory for NoReconnect<T>
where
    T: Transport + MaybeSend + 'static,
{
    type Transport = T;
    type Error = core::convert::Infallible;

    fn connect(
        &mut self,
    ) -> impl Future<Output = Result<Self::Transport, Self::Error>> + MaybeSend {
        core::future::pending()
    }
}

/// Sleeper type for pumps configured without reconnect. Never invoked.
pub(crate) struct NoSleep;

impl Sleeper for NoSleep {
    fn sleep(&mut self, _duration: Duration) -> impl Future<Output = ()> + MaybeSend {
        core::future::ready(())
    }
}
