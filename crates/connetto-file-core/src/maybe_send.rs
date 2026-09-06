//! Platform-adaptive `Send` bound for async chunk-store futures.
//!
//! Mirrors the definition in `connetto-core` so the two crates stay in sync
//! without a dependency edge between them.

/// `Send` on native targets, unconstrained on wasm.
///
/// Chunk-store futures are `Send` on native so callers can hold them across
/// `spawn` on multi-threaded runtimes. On wasm the runtime is single-threaded
/// and futures hold browser values that cannot be `Send`, so the bound is a
/// blanket no-op. On native this trait has `Send` as a supertrait with a
/// blanket impl, making `+ MaybeSend` exactly `+ Send`. Never implement it
/// by hand.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub trait MaybeSend: Send {}
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
impl<T: Send> MaybeSend for T {}

/// `Send` on native targets, unconstrained on wasm. See the native docs.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub trait MaybeSend {}
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
impl<T> MaybeSend for T {}
