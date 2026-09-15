//! The native content transport, bounded by silence rather than by time.

use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use futures_util::StreamExt;
use reqwest::{Client, RequestBuilder, Url, redirect};
use thiserror::Error;

use super::{ContentHttp, DEFAULT_IDLE_BOUND, HttpFailure, HttpReply};

/// How many bytes of a request body go out per pull.
///
/// Small enough that a moving upload reports often, large enough that a chunk
/// costs a few hundred pulls rather than a few hundred thousand.
const SEND_FRAME: usize = 64 * 1024;

/// A native content request failure before any reply could be read.
#[derive(Debug, Error)]
pub enum ReqwestHttpError {
    /// The client failed the request.
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    /// Nothing moved in either direction for the idle bound.
    #[error("no byte moved in either direction for {bound:?}")]
    Idle {
        /// The bound that elapsed in silence.
        bound: Duration,
    },
}

/// The native content transport, bounded by silence rather than by elapsed
/// time.
///
/// A transfer is aborted when no byte has moved in either direction for the
/// idle bound, thirty seconds by default, and a moving transfer is never
/// aborted however long it runs. The bound covers every phase of a request,
/// including the wait for the status line while the server verifies a chunk or
/// runs a commit.
///
/// The bound is the transport's own rather than the client's, because
/// `reqwest`'s read timeout is one sleep started at `send` and polled until
/// the status line arrives, with no reset while the request body goes out, so
/// on a client that uploads it is a total deadline on the send of a chunk.
/// This transport feeds one watchdog per request from the two signals a client
/// does expose, every pull of the streamed request body and every chunk of the
/// streamed reply.
///
/// A pull is a buffer ahead of the wire, because a connection pulls a frame
/// when its own write buffer has room and the TLS and kernel send buffers sit
/// below that, a few megabytes together. After the last pull those bytes drain
/// unseen, so the silence measured before the status line is the buffered tail
/// over the link rate plus the server's verify, and a link slower than the
/// buffered bytes over the bound has its upload tail aborted while it is still
/// moving. That is the one floor on link speed this transport keeps, about a
/// megabit per second at the default bound.
#[derive(Debug, Clone)]
pub struct ReqwestHttp {
    client: Client,
    idle_bound: Duration,
}

impl Default for ReqwestHttp {
    fn default() -> Self {
        Self::new()
    }
}

impl ReqwestHttp {
    /// Builds a transport over a fresh client with no timeout of any kind and
    /// no redirect following, under the default thirty second idle bound.
    ///
    /// Following nothing is the protocol's rule rather than a preference. The
    /// mint issues exact addresses, `reqwest` replays no streamed body to a
    /// redirect target, and its redirect layer hands back the reply of a `307`
    /// on an unreplayable body before any policy runs, so a policy could not
    /// see the hop on a chunk upload at all.
    ///
    /// # Panics
    ///
    /// When the platform's TLS backend cannot initialize, which is what
    /// [`reqwest::Client::new`] panics on as well.
    #[must_use]
    pub fn new() -> Self {
        let client = Client::builder()
            .redirect(redirect::Policy::none())
            .build()
            .expect("a client with no timeout and no redirect policy");
        Self {
            client,
            idle_bound: DEFAULT_IDLE_BOUND,
        }
    }

    /// Builds a transport over a client the application already configured,
    /// so a deployment's proxy and certificate settings carry over.
    ///
    /// The client is untouched and runs under the same idle bound. A client
    /// that set its own `read_timeout` or `timeout` still carries `reqwest`'s
    /// deadline on its uploads, which is that client's own setting. A client
    /// whose redirect policy follows lands its reply elsewhere, and this
    /// transport refuses that reply by comparing the address it landed on.
    #[must_use]
    pub fn with_client(client: Client) -> Self {
        Self {
            client,
            idle_bound: DEFAULT_IDLE_BOUND,
        }
    }

    /// Sets how long a transfer may stay silent before it is aborted.
    ///
    /// The bound covers every phase of a request, including the wait for the
    /// status line while the server verifies a chunk or runs a commit, so a
    /// deployment with a slow commit raises this rather than gaining a second
    /// number.
    #[must_use]
    pub const fn with_idle_bound(mut self, idle_bound: Duration) -> Self {
        self.idle_bound = idle_bound;
        self
    }

    /// Sends one request under the idle bound and collects its reply.
    async fn run(
        &self,
        request: RequestBuilder,
        target: &str,
        activity: &Activity,
    ) -> Result<HttpReply, HttpFailure<ReqwestHttpError>> {
        let wanted = Url::parse(target).ok();
        let exchange = async {
            let response = request.send().await.map_err(transport)?;
            // The status line is movement, and the reply body's window starts here.
            activity.moved();
            let landed = response.url();
            if wanted.as_ref().is_some_and(|wanted| landed != wanted) {
                return Err(HttpFailure::Redirected {
                    origin: Some(landed.origin().ascii_serialization()),
                });
            }
            let status = response.status().as_u16();
            let mut body = Vec::new();
            let mut chunks = response.bytes_stream();
            while let Some(chunk) = chunks.next().await {
                let chunk = chunk.map_err(transport)?;
                activity.moved();
                body.extend_from_slice(&chunk);
            }
            Ok(HttpReply { status, body })
        };
        tokio::select! {
            reply = exchange => reply,
            () = activity.silence(self.idle_bound) => Err(HttpFailure::Transport(
                ReqwestHttpError::Idle { bound: self.idle_bound },
            )),
        }
    }
}

impl ContentHttp for ReqwestHttp {
    type Error = ReqwestHttpError;

    async fn post(
        &self,
        url: &str,
        json: Option<Vec<u8>>,
    ) -> Result<HttpReply, HttpFailure<Self::Error>> {
        let activity = Activity::new();
        let mut request = self.client.post(url);
        if let Some(body) = json {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(streamed(body, &activity));
        }
        self.run(request, url, &activity).await
    }

    async fn put(&self, url: &str, body: Vec<u8>) -> Result<HttpReply, HttpFailure<Self::Error>> {
        let activity = Activity::new();
        let request = self
            .client
            .put(url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(streamed(body, &activity));
        self.run(request, url, &activity).await
    }

    async fn get(
        &self,
        url: &str,
        range: Option<(u64, u64)>,
    ) -> Result<HttpReply, HttpFailure<Self::Error>> {
        let activity = Activity::new();
        let mut request = self.client.get(url);
        if let Some((first, last)) = range {
            request = request.header(reqwest::header::RANGE, format!("bytes={first}-{last}"));
        }
        self.run(request, url, &activity).await
    }
}

/// Sends `body` as a stream whose every pull is a write the connection took.
fn streamed(body: Vec<u8>, activity: &Activity) -> reqwest::Body {
    let frames = futures_util::stream::unfold(
        (Bytes::from(body), 0, activity.handle()),
        |(body, sent, activity)| async move {
            activity.moved();
            if sent == body.len() {
                return None;
            }
            let end = sent.saturating_add(SEND_FRAME).min(body.len());
            let frame = body.slice(sent..end);
            Some((Ok::<Bytes, std::io::Error>(frame), (body, end, activity)))
        },
    );
    reqwest::Body::wrap_stream(frames)
}

/// Every failure the client reports is the transport's own.
fn transport(error: reqwest::Error) -> HttpFailure<ReqwestHttpError> {
    HttpFailure::Transport(ReqwestHttpError::Request(error))
}

/// When one request last moved a byte in either direction.
#[derive(Debug)]
struct Activity {
    start: Instant,
    /// Milliseconds after `start` of the last movement.
    last: Arc<AtomicU64>,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last: Arc::new(AtomicU64::new(0)),
        }
    }

    /// A second view of the same record, for the body stream the client owns.
    fn handle(&self) -> Self {
        Self {
            start: self.start,
            last: Arc::clone(&self.last),
        }
    }

    /// Records that a byte moved.
    fn moved(&self) {
        let elapsed = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        // Relaxed: the value is the whole state, and nothing is ordered against it.
        self.last.store(elapsed, Ordering::Relaxed);
    }

    /// Resolves once nothing has moved for `bound`, and never while bytes move.
    async fn silence(&self, bound: Duration) {
        loop {
            let last = self.last.load(Ordering::Relaxed);
            let deadline = self.start + Duration::from_millis(last) + bound;
            tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
            if self.last.load(Ordering::Relaxed) == last {
                return;
            }
        }
    }
}
