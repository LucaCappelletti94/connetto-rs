//! The HTTP seam the content protocol rides, and its native implementation.
//!
//! The seam exists because the negotiation is shared with R68 and the two
//! platforms cannot share a client: the native side is `reqwest` over rustls,
//! and a browser worker has `fetch`. Everything above this trait, including
//! every status-code decision, lives once above it in the upload negotiation.
//! A transport decides only two failures, its own and the redirect refusal,
//! because only a transport holds the address a reply landed on.

use connetto_file_core::MaybeSend;

/// What one content request answered.
pub struct HttpReply {
    /// The HTTP status code.
    pub status: u16,
    /// The response body, empty when the answer carried none.
    pub body: Vec<u8>,
}

/// Why one content request has no reply for the negotiation to read.
#[derive(Debug, thiserror::Error)]
pub enum HttpFailure<E: core::error::Error + 'static> {
    /// The transport failed before a reply arrived.
    #[error(transparent)]
    Transport(E),
    /// A redirect was followed or refused, which the content protocol treats
    /// as an answer about the server. The mint issues exact addresses, so no
    /// hop belongs to a transfer.
    #[error("redirected to {}", origin.as_deref().unwrap_or("an undisclosed address"))]
    Redirected {
        /// The origin of the reply that landed, absent when no reply landed.
        origin: Option<String>,
    },
}

/// The idle bound a transfer is aborted after, per chapter 18.
pub(crate) const DEFAULT_IDLE_BOUND: core::time::Duration = core::time::Duration::from_secs(30);

/// The three request shapes the content protocol uses.
pub trait ContentHttp {
    /// The transport's own failure type, for a request that never got a status.
    type Error: core::error::Error + 'static;

    /// `POST` to `url`, with `json` as an `application/json` body when present.
    ///
    /// The absent case is the commit, which carries no body.
    fn post(
        &self,
        url: &str,
        json: Option<Vec<u8>>,
    ) -> impl Future<Output = Result<HttpReply, HttpFailure<Self::Error>>> + MaybeSend;

    /// `PUT` `body` to `url` as `application/octet-stream`.
    fn put(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<HttpReply, HttpFailure<Self::Error>>> + MaybeSend;

    /// `GET` `url`, optionally as an inclusive byte range.
    ///
    /// The answer is read as it arrives and collected, which the deployment's
    /// read ceiling already bounds: the file server refuses a response past
    /// the ticket's ceiling, so no answer here is larger than the deployment
    /// permits.
    fn get(
        &self,
        url: &str,
        range: Option<(u64, u64)>,
    ) -> impl Future<Output = Result<HttpReply, HttpFailure<Self::Error>>> + MaybeSend;
}

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
mod native;

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub use native::{ReqwestHttp, ReqwestHttpError};

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod browser;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub use browser::{BrowserHttp, BrowserHttpError};
