//! Browser display handles for resolved content.

use core::fmt::Display;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use crate::content_wire::{ContentFrame, WirePins, WireResolve, mime_code};
use crate::frames::{InternalLane, MessageSink, MessageTransport};
use crate::workers::helpers::sleep_ms;
use connetto_client::live::ConnettoClient;
use connetto_core::traits::{MaybeSend, Transport};
use connetto_file_client::{
    BrowserHttp, BrowserStore, BrowserStoreError, ContentClient, ContentError, FileId,
    FileIdHasher, MimeClass, Resolved,
};
use diesel::SqliteConnection;
use futures_channel::oneshot;
use futures_util::StreamExt;
use js_sys::{Array, Uint8Array};
use thiserror::Error;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

/// Failure to attach browser file handling.
#[derive(Debug, Error)]
pub enum BrowserContentError {
    /// Persistent browser content belongs to a dedicated worker.
    #[error("browser content must be attached from a dedicated worker")]
    NotWorker,
    /// The persistent store namespace is invalid.
    #[error(transparent)]
    Store(#[from] BrowserStoreError),
    /// The shared content client could not attach.
    #[error(transparent)]
    Content(#[from] ContentError),
}

/// A content client using the browser worker's storage and transport.
pub type BrowserContentClient<T> = ContentClient<T, BrowserStore, BrowserHttp>;

/// Attaches worker-owned browser content whose transfers run under `http`,
/// which carries the idle bound this device aborts a silent transfer after.
///
/// # Errors
///
/// [`BrowserContentError`] when called outside a worker or when storage or content setup fails.
pub async fn attach_browser_content<T>(
    client: ConnettoClient<T>,
    namespace: impl Into<String>,
    root_key: [u8; 32],
    http: BrowserHttp,
) -> Result<BrowserContentClient<T>, BrowserContentError>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
{
    let worker = js_sys::global()
        .dyn_into::<web_sys::DedicatedWorkerGlobalScope>()
        .map_err(|_value: js_sys::Object| BrowserContentError::NotWorker)?;
    let store = BrowserStore::install(&worker, namespace).await?;
    ContentClient::attach(client, store, root_key, http)
        .await
        .map_err(Into::into)
}
use web_sys::{Blob, BlobPropertyBag, Url};

/// Failure to expose local bytes as a browser URL.
#[derive(Debug, Error)]
pub enum ObjectUrlError {
    /// The browser rejected blob or object URL creation.
    #[error("create browser object URL: {0}")]
    Browser(String),
}

/// A reference-counted browser object URL revoked with its last owner.
#[derive(Clone, Debug)]
pub struct ObjectUrl {
    inner: Arc<ObjectUrlInner>,
}

#[derive(Debug)]
struct ObjectUrlInner {
    value: String,
}

impl ObjectUrl {
    /// Creates an object URL for `bytes` with the given media type.
    ///
    /// # Errors
    ///
    /// [`ObjectUrlError`] when the browser rejects blob or URL creation.
    pub fn new(bytes: &[u8], media_type: &str) -> Result<Self, ObjectUrlError> {
        let parts = Array::of1(&Uint8Array::from(bytes));
        let options = BlobPropertyBag::new();
        options.set_type(media_type);
        let blob = Blob::new_with_u8_array_sequence_and_options(&parts, &options)
            .map_err(|value| object_url_error(&value))?;
        let value =
            Url::create_object_url_with_blob(&blob).map_err(|value| object_url_error(&value))?;
        Ok(Self {
            inner: Arc::new(ObjectUrlInner { value }),
        })
    }

    /// The URL passed to browser media elements.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.inner.value
    }

    /// Creates an object URL for a blob the browser already holds.
    ///
    /// # Errors
    ///
    /// [`ObjectUrlError`] when the browser rejects URL creation.
    pub fn from_blob(blob: &Blob) -> Result<Self, ObjectUrlError> {
        let value =
            Url::create_object_url_with_blob(blob).map_err(|value| object_url_error(&value))?;
        Ok(Self {
            inner: Arc::new(ObjectUrlInner { value }),
        })
    }
}

impl AsRef<str> for ObjectUrl {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Drop for ObjectUrlInner {
    fn drop(&mut self) {
        let _ = Url::revoke_object_url(&self.value);
    }
}

/// A content resolution ready for a browser display element.
#[derive(Clone, Debug)]
pub enum BrowserResolved {
    /// Local bytes exposed through an owned object URL.
    Local {
        /// The local source that served the bytes.
        source: &'static str,
        /// The browser URL and its lifetime.
        url: ObjectUrl,
    },
    /// A short-lived signed server URL.
    Remote {
        /// The granted address.
        url: String,
    },
    /// Neither local storage nor the server can serve the content.
    Unavailable,
}

impl BrowserResolved {
    /// Converts a platform-neutral resolution into a browser display handle.
    ///
    /// # Errors
    ///
    /// [`ObjectUrlError`] when local bytes cannot become an object URL.
    pub fn from_resolved(resolved: Resolved, media_type: &str) -> Result<Self, ObjectUrlError> {
        match resolved {
            Resolved::Local { source, bytes } => Ok(Self::Local {
                source,
                url: ObjectUrl::new(&bytes, media_type)?,
            }),
            Resolved::Remote { url } => Ok(Self::Remote { url }),
            Resolved::Unavailable => Ok(Self::Unavailable),
        }
    }
}

fn object_url_error(value: &wasm_bindgen::JsValue) -> ObjectUrlError {
    ObjectUrlError::Browser(value.as_string().unwrap_or_else(|| format!("{value:?}")))
}

/// The longest a tab waits for the worker's resolve answer. The hub bounds
/// its own wait sooner, so this only fires when the hub has stopped
/// answering entirely.
const TAB_RESOLVE_WAIT_MS: i32 = 16_000;

/// The bytes one staging hash read takes from the blob. The identity is the
/// hash of the whole file, but the file goes through one window of this size
/// at a time, so the tab's peak holds a window rather than two copies of the
/// largest file it can upload.
const STAGE_READ_BYTES: f64 = 4.0 * 1024.0 * 1024.0;

/// Where a file's bytes are to be had, as answered by the worker hub over
/// the tab's content lane.
#[derive(Debug)]
pub enum TabResolved {
    /// The server granted a read at this URL.
    Remote {
        /// The granted URL.
        url: String,
    },
    /// The worker held the bytes itself.
    Local {
        /// The file's bytes.
        blob: Blob,
    },
    /// Neither the worker nor the server can produce the bytes right now.
    Unavailable,
}

impl TabResolved {
    /// Exposes a local answer as an object URL. A remote answer is already a
    /// URL, and `Unavailable` has no bytes; both answer `None`.
    ///
    /// # Errors
    ///
    /// [`ObjectUrlError`] when the browser rejects URL creation.
    pub fn into_object_url(self) -> Result<Option<ObjectUrl>, ObjectUrlError> {
        match self {
            Self::Local { blob } => ObjectUrl::from_blob(&blob).map(Some),
            Self::Remote { .. } | Self::Unavailable => Ok(None),
        }
    }
}

/// Why a tab-side stage did not complete.
#[derive(Debug, Error)]
pub enum TabStageError<E: Display> {
    /// The blob's bytes could not be read for hashing.
    #[error("the staged blob could not be read: {0}")]
    Read(String),
    /// The content lane refused the announcement.
    #[error("the staged content could not be announced: {0}")]
    Post(String),
    /// The caller's row failed. The announced blob ages out at the worker on
    /// its own; nothing needs unwinding.
    #[error("the staged row failed: {0}")]
    Row(E),
}

/// One answer to a `Resolve`, with the bytes a `Local` answer carries.
type ResolveAnswer = (WireResolve, Option<Blob>);

/// One reply the hub sends on a tab's content lane, keyed by its request.
enum LaneAnswer {
    Resolve(ResolveAnswer),
    Pins(WirePins),
}

/// Why a tab's pin request did not take effect.
#[derive(Debug, thiserror::Error)]
pub enum TabPinError {
    /// The worker refused, with its reason.
    #[error("the worker refused the pin request: {0}")]
    Refused(String),
    /// No answer arrived in time, or the lane is closed.
    #[error("the worker did not answer the pin request")]
    Unanswered,
}

/// A tab's content lane: stage files through the worker and ask where bytes
/// live, while the tab's client owns the transport itself.
///
/// Staging pairs with the mutation that names the file.
/// [`stage`](Self::stage) announces the blob before the caller's transaction
/// commits, and message ports deliver in order, so the worker holds the
/// bytes by the time the mutation arrives; the worker then commits the
/// file's manifest, its upload queue entry and the rows as one mutation,
/// checking that the bytes hash to the identity the row names.
pub struct TabContent<S: MessageSink + Clone + 'static> {
    lane: InternalLane<S>,
    replies: Rc<RefCell<HashMap<u64, oneshot::Sender<LaneAnswer>>>>,
    next_request: Rc<Cell<u64>>,
}

impl<S: MessageSink + Clone + 'static> TabContent<S> {
    /// Split the content lane off a tab transport, before handing that
    /// transport to the tab's client.
    #[must_use]
    pub fn new(transport: &mut MessageTransport<S>) -> Self {
        let lane = transport.internal_lane();
        let replies: Rc<RefCell<HashMap<u64, oneshot::Sender<LaneAnswer>>>> =
            Rc::new(RefCell::new(HashMap::new()));
        if let Some(mut inbox) = transport.take_internal_inbox() {
            let waiting = Rc::clone(&replies);
            wasm_bindgen_futures::spawn_local(async move {
                while let Some(inbound) = inbox.next().await {
                    let (request_id, answer) = match ContentFrame::from_json(&inbound.json) {
                        Some(ContentFrame::ResolveReply { request_id, answer }) => {
                            (request_id, LaneAnswer::Resolve((answer, inbound.blob)))
                        }
                        Some(ContentFrame::PinReply { request_id, answer }) => {
                            (request_id, LaneAnswer::Pins(answer))
                        }
                        _ => continue,
                    };
                    if let Some(sender) = waiting.borrow_mut().remove(&request_id) {
                        let _ = sender.send(answer);
                    }
                }
            });
        }
        Self {
            lane,
            replies,
            next_request: Rc::new(Cell::new(0)),
        }
    }

    /// Announce `blob` to the worker and run `row`, so the file, its upload
    /// and the rows naming it reach the hub as one mutation.
    ///
    /// The identity handed to `row` is what the blob's bytes hash to; the
    /// worker recomputes it and refuses the mutation if the rows name
    /// anything else. A `row` that fails leaves the announced blob to age
    /// out at the worker, which costs the bytes and nothing else.
    ///
    /// # Errors
    ///
    /// [`TabStageError::Read`] when the blob cannot be hashed,
    /// [`TabStageError::Post`] when the lane refuses the announcement, and
    /// whatever `row` returns as [`TabStageError::Row`].
    pub async fn stage<T, F, O, E>(
        &self,
        blob: &Blob,
        mime: MimeClass,
        client: &ConnettoClient<T>,
        row: F,
    ) -> Result<(FileId, O), TabStageError<E>>
    where
        T: Transport + MaybeSend + 'static,
        T::Error: Display,
        F: FnOnce(&mut SqliteConnection, FileId) -> Result<O, E>,
        E: Display,
    {
        let mut hasher = FileIdHasher::new();
        let size = blob.size();
        let mut offset: f64 = 0.0;
        while offset < size {
            let end = (offset + STAGE_READ_BYTES).min(size);
            let window = match blob.slice_with_f64_and_f64(offset, end) {
                Ok(window) => window,
                Err(err) => return Err(TabStageError::Read(format!("{err:?}"))),
            };
            let bytes = match blob_bytes(&window).await {
                Ok(bytes) => bytes,
                Err(err) => return Err(TabStageError::Read(format!("{err:?}"))),
            };
            hasher.update(&bytes);
            offset = end;
        }
        let file_id = hasher.finalize();
        let frame = ContentFrame::Stage {
            file_id: *file_id.as_bytes(),
            mime: mime_code(mime),
        };
        self.lane
            .post_internal(&frame.to_json(), Some(blob))
            .map_err(|err| TabStageError::Post(err.to_string()))?;
        client
            .with_conn(|conn| row(conn.conn(), file_id))
            .await
            .map(|outcome| (file_id, outcome))
            .map_err(TabStageError::Row)
    }

    /// Where this file's bytes are to be had, answered by the worker.
    pub async fn resolve(&self, file_id: FileId) -> TabResolved {
        let answer = self
            .ask(|request_id| ContentFrame::Resolve {
                request_id,
                file_id: *file_id.as_bytes(),
            })
            .await;
        match answer {
            Some(LaneAnswer::Resolve((WireResolve::Remote { url }, _))) => {
                TabResolved::Remote { url }
            }
            Some(LaneAnswer::Resolve((WireResolve::Local, Some(blob)))) => {
                TabResolved::Local { blob }
            }
            _ => TabResolved::Unavailable,
        }
    }

    /// Keeps the files `query` names in `file_id_column` on this device under `name`,
    /// as the native content client's `pin_content` does.
    ///
    /// # Errors
    ///
    /// [`TabPinError::Refused`] when the worker refuses, for a query not returning the
    /// named column among other reasons, and [`TabPinError::Unanswered`] when no answer comes.
    pub async fn pin_content(
        &self,
        name: &str,
        query: &str,
        file_id_column: &str,
    ) -> Result<(), TabPinError> {
        self.pin_request(|request_id| ContentFrame::Pin {
            request_id,
            name: name.to_owned(),
            query: query.to_owned(),
            file_id_column: file_id_column.to_owned(),
        })
        .await
        .map(|_| ())
    }

    /// Ends the pin under `name`. Unknown names are a no-op.
    ///
    /// # Errors
    ///
    /// As [`pin_content`](Self::pin_content).
    pub async fn unpin_content(&self, name: &str) -> Result<(), TabPinError> {
        self.pin_request(|request_id| ContentFrame::Unpin {
            request_id,
            name: name.to_owned(),
        })
        .await
        .map(|_| ())
    }

    /// Every content pin, as name, query and file-id column, in name order.
    ///
    /// # Errors
    ///
    /// As [`pin_content`](Self::pin_content).
    pub async fn content_pins(&self) -> Result<Vec<(String, String, String)>, TabPinError> {
        match self
            .pin_request(|request_id| ContentFrame::ListPins { request_id })
            .await?
        {
            WirePins::Pins(pins) => Ok(pins),
            WirePins::Done | WirePins::Refused(_) => Err(TabPinError::Unanswered),
        }
    }

    async fn pin_request(
        &self,
        frame: impl FnOnce(u64) -> ContentFrame,
    ) -> Result<WirePins, TabPinError> {
        match self.ask(frame).await {
            Some(LaneAnswer::Pins(WirePins::Refused(reason))) => Err(TabPinError::Refused(reason)),
            Some(LaneAnswer::Pins(answer)) => Ok(answer),
            Some(LaneAnswer::Resolve(_)) | None => Err(TabPinError::Unanswered),
        }
    }

    /// Posts the frame `frame` builds under a fresh request id and waits, bounded, for its reply.
    async fn ask(&self, frame: impl FnOnce(u64) -> ContentFrame) -> Option<LaneAnswer> {
        let request_id = {
            let next = self.next_request.get() + 1;
            self.next_request.set(next);
            next
        };
        let (sender, answer) = oneshot::channel();
        self.replies.borrow_mut().insert(request_id, sender);
        if self
            .lane
            .post_internal(&frame(request_id).to_json(), None)
            .is_err()
        {
            self.replies.borrow_mut().remove(&request_id);
            return None;
        }
        let answered = tokio::select! {
            answer = answer => answer.ok(),
            () = sleep_ms(TAB_RESOLVE_WAIT_MS) => None,
        };
        self.replies.borrow_mut().remove(&request_id);
        answered
    }
}

/// Read a whole blob through the browser's file reader, which works from any
/// context, page or worker.
async fn blob_bytes(blob: &Blob) -> Result<Vec<u8>, wasm_bindgen::JsValue> {
    let buffer = JsFuture::from(blob.array_buffer()).await?;
    Ok(Uint8Array::new(&buffer).to_vec())
}
