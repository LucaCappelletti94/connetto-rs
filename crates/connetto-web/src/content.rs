//! Browser display handles for resolved content.

use core::fmt::Display;
use std::sync::Arc;

use connetto_client::live::ConnettoClient;
use connetto_core::traits::{MaybeSend, Transport};
use connetto_file_client::{BrowserHttp, BrowserStore, ContentClient, ContentError, Resolved};
use js_sys::{Array, Uint8Array};
use thiserror::Error;
use wasm_bindgen::JsCast;

/// Failure to attach browser file handling.
#[derive(Debug, Error)]
pub enum BrowserContentError {
    /// Persistent browser content belongs to a dedicated worker.
    #[error("browser content must be attached from a dedicated worker")]
    NotWorker,
    /// The shared content client could not attach.
    #[error(transparent)]
    Content(#[from] ContentError),
}

/// A content client using the browser worker's storage and transport.
pub type BrowserContentClient<T> = ContentClient<T, BrowserStore, BrowserHttp>;

/// Attaches worker-owned browser content or returns a scope or content failure.
pub async fn attach_browser_content<T>(
    client: ConnettoClient<T>,
    namespace: impl Into<String>,
    root_key: [u8; 32],
) -> Result<BrowserContentClient<T>, BrowserContentError>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
{
    let worker = js_sys::global()
        .dyn_into::<web_sys::DedicatedWorkerGlobalScope>()
        .map_err(|_value: js_sys::Object| BrowserContentError::NotWorker)?;
    let store = BrowserStore::install(&worker, namespace).await;
    ContentClient::attach(client, store, root_key, BrowserHttp::new())
        .await
        .map_err(Into::into)
}
use web_sys::{Blob, BlobPropertyBag, Url};

/// Failure to expose local bytes as a browser URL.
#[derive(Debug, Error)]
#[error("create browser object URL: {message}")]
pub struct ObjectUrlError {
    /// The browser exception text.
    message: String,
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
    /// Converts the platform-neutral resolution into a browser display handle.
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
    ObjectUrlError {
        message: value.as_string().unwrap_or_else(|| format!("{value:?}")),
    }
}
