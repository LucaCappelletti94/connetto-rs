//! The platform seam: the transport type, the content wrapper and the photo
//! staging, each with a `cfg`-selected body so only the compiled platform's
//! code exists. There is no trait, since only one platform is ever compiled
//! in.

#[cfg(not(target_arch = "wasm32"))]
pub mod native;
#[cfg(target_arch = "wasm32")]
pub mod web;
#[cfg(not(target_arch = "wasm32"))]
pub use native::Ops;
#[cfg(target_arch = "wasm32")]
pub use web::Ops;
#[cfg(target_arch = "wasm32")]
mod inner {
    use std::rc::Rc;

    use connetto_client::ConnettoClient;

    /// The tab-to-worker transport the window's client rides.
    pub type Transport = connetto_web::MessageTransport<web_sys::BroadcastChannel>;

    pub type Client = ConnettoClient<Transport>;

    /// The tab's content lane, split off the transport before the client took it.
    pub struct DemoContent(pub(super) Rc<connetto_web::TabContent<web_sys::BroadcastChannel>>);

    impl Clone for DemoContent {
        fn clone(&self) -> Self {
            Self(Rc::clone(&self.0))
        }
    }

    impl DemoContent {
        pub fn new(content: Rc<connetto_web::TabContent<web_sys::BroadcastChannel>>) -> Self {
            Self(content)
        }

        pub fn tab(&self) -> &connetto_web::TabContent<web_sys::BroadcastChannel> {
            &self.0
        }
    }

    /// Why a tab-side content request did not take effect.
    #[derive(Debug)]
    pub enum ContentError {
        /// The worker refused the request, or no answer came.
        Refused(connetto_web::TabContentError),
    }

    impl std::fmt::Display for ContentError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Refused(err) => err.fmt(f),
            }
        }
    }

    impl std::error::Error for ContentError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Refused(err) => Some(err),
            }
        }
    }

    impl From<connetto_web::TabContentError> for ContentError {
        fn from(err: connetto_web::TabContentError) -> Self {
            Self::Refused(err)
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod inner {
    use std::sync::Arc;

    use connetto_client::{ConnettoClient, NativeTransport};
    use connetto_file_client::{ContentClient, FsStore, ReqwestHttp};

    /// The native WebSocket transport.
    pub type Transport = NativeTransport;

    pub type Client = ConnettoClient<Transport>;

    /// The durable content client beside the replica.
    pub struct DemoContent(pub(super) Arc<ContentClient<Transport, FsStore, ReqwestHttp>>);

    impl Clone for DemoContent {
        fn clone(&self) -> Self {
            Self(Arc::clone(&self.0))
        }
    }

    impl DemoContent {
        pub fn new(content: Arc<ContentClient<Transport, FsStore, ReqwestHttp>>) -> Self {
            Self(content)
        }

        pub fn client(&self) -> &ContentClient<Transport, FsStore, ReqwestHttp> {
            &self.0
        }
    }

    /// Why a native content request did not take effect.
    #[derive(Debug)]
    pub enum ContentError {
        /// The content client refused the request.
        Refused(connetto_file_client::ContentError),
    }

    impl std::fmt::Display for ContentError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Refused(err) => err.fmt(f),
            }
        }
    }

    impl std::error::Error for ContentError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Refused(err) => Some(err),
            }
        }
    }

    impl From<connetto_file_client::ContentError> for ContentError {
        fn from(err: connetto_file_client::ContentError) -> Self {
            Self::Refused(err)
        }
    }
}

pub use inner::{Client, ContentError, DemoContent, Transport};

use crate::mime_from_extension;
use crate::{Photo, photo_file_id, stage_photo_row};
use connetto_file_core::FileId;
use dioxus::prelude::*;
use rosetta_uuid::Uuid;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;

/// A photo's display source and, for local bytes, the object URL that keeps it valid.
#[derive(Clone, Debug)]
pub struct PhotoSrc {
    /// The value passed to the image element.
    pub display: String,
    /// The object URL owning `display`, revoked when the last owner drops.
    #[cfg(target_arch = "wasm32")]
    pub owner: Option<connetto_web::ObjectUrl>,
}

impl DemoContent {
    /// The display source of each row, keyed by the photo row's id. Local bytes show at
    /// every state, since a staged file answers as Local while unsent, and a signed URL
    /// is used once the server says the row's content is available.
    pub async fn sources(&self, photos: &[Photo]) -> std::collections::HashMap<Uuid, PhotoSrc> {
        #[cfg(target_arch = "wasm32")]
        {
            use connetto_web::TabResolved;

            let mut srcs: std::collections::HashMap<Uuid, PhotoSrc> =
                std::collections::HashMap::new();
            for photo in photos {
                let Some(fid) = photo_file_id(&photo.content_id) else {
                    continue;
                };
                let available = photo.content_state.as_deref() == Some("available");
                let resolved = self.0.resolve(fid).await;
                match resolved {
                    TabResolved::Remote { url } if available => {
                        srcs.insert(
                            photo.id,
                            PhotoSrc {
                                display: url,
                                owner: None,
                            },
                        );
                    }
                    TabResolved::Local { .. } => {
                        let Ok(Some(object_url)) = resolved.into_object_url() else {
                            continue;
                        };
                        srcs.insert(
                            photo.id,
                            PhotoSrc {
                                display: object_url.as_str().to_owned(),
                                owner: Some(object_url),
                            },
                        );
                    }
                    _ => {}
                }
            }
            srcs
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            use base64::Engine as _;
            use connetto_file_client::Resolved;

            let mut srcs: std::collections::HashMap<Uuid, PhotoSrc> =
                std::collections::HashMap::new();
            for photo in photos {
                let Some(fid) = photo_file_id(&photo.content_id) else {
                    continue;
                };
                let available = photo.content_state.as_deref() == Some("available");
                match self.0.resolve(fid).await {
                    Ok(Resolved::Local { bytes, .. }) => {
                        let enc = base64::engine::general_purpose::STANDARD.encode(&bytes);
                        srcs.insert(
                            photo.id,
                            PhotoSrc {
                                display: format!("data:image/jpeg;base64,{enc}"),
                            },
                        );
                    }
                    Ok(Resolved::Remote { url }) if available => {
                        srcs.insert(photo.id, PhotoSrc { display: url });
                    }
                    _ => {}
                }
            }
            srcs
        }
    }

    /// Every refused outbox entry with its permanent refusal detail.
    #[must_use]
    pub async fn refused(&self) -> Vec<(FileId, String)> {
        self.0.refused_content().await.unwrap_or_default()
    }

    /// Files whose unsent bytes were lost and whose loss is unacknowledged.
    #[must_use]
    pub async fn retired(&self) -> Vec<FileId> {
        self.0.retired_content().await.unwrap_or_default()
    }

    /// Clears one refusal so the next upload walk attempts it again.
    pub async fn retry(&self, file_id: FileId) -> Result<(), ContentError> {
        self.0.retry_refused(file_id).await.map_err(Into::into)
    }

    /// Drops the losses the application has dealt with.
    pub async fn forget(&self, ids: &[FileId]) -> Result<(), ContentError> {
        self.0.forget_retired_content(ids).await.map_err(Into::into)
    }

    /// Keeps the photos' files on this device under `photos`.
    pub async fn pin(&self) -> String {
        self.0
            .pin_content("photos", "SELECT content_id FROM photos", "content_id")
            .await
            .map_or_else(
                |err| format!("pin failed: {err}"),
                |_| "pinned photos".to_owned(),
            )
    }

    /// Ends the photos' pin.
    pub async fn unpin(&self) -> String {
        self.0.unpin_content("photos").await.map_or_else(
            |err| format!("unpin failed: {err}"),
            |_| "unpinned photos".to_owned(),
        )
    }

    /// Fetches every pinned file the local store is missing.
    pub async fn fetch_pinned(&self) -> String {
        self.0.fetch_pinned().await.map_or_else(
            |err| format!("fetch failed: {err}"),
            |ids| format!("fetched {} pinned file(s)", ids.len()),
        )
    }

    /// Evicts the unpinned, unreferenced content files.
    pub async fn tidy(&self) -> String {
        #[cfg(target_arch = "wasm32")]
        let evicted = self.0.tidy().await;
        #[cfg(not(target_arch = "wasm32"))]
        let evicted = self.0.tidy_content().await;
        evicted.map_or_else(
            |err| format!("content tidy failed: {err}"),
            |n| format!("content tidy: {n} file(s) evicted"),
        )
    }
}

/// Stages one picked file as a photo, answering with the line the pane shows.
/// The inserts omit `created_at`, which the orders table's `now()` default
/// mints; the photos row has no such column.
#[cfg(target_arch = "wasm32")]
pub async fn stage_picked(
    content: &DemoContent,
    client: &Client,
    blob: &web_sys::Blob,
    name: &str,
    identity: String,
) -> String {
    let Some(mime) = mime_from_extension(std::path::Path::new(name)) else {
        return "not an image: only .jpg .jpeg .png are accepted".to_owned();
    };
    match content
        .0
        .stage(blob, mime, client, move |conn, file_id| {
            stage_photo_row(conn, file_id, &identity)
        })
        .await
    {
        Ok(_) => {
            // Push the staged mutation up now, as the browser build has always done.
            client.replay_pending().await.ok();
            "photo staged".to_owned()
        }
        Err(err) => format!("stage failed: {err}"),
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn stage_picked(
    content: &DemoContent,
    name: &str,
    bytes: Result<Vec<u8>, String>,
    identity: String,
) -> String {
    let Some(mime) = mime_from_extension(std::path::Path::new(name)) else {
        return "not an image: only .jpg .jpeg .png are accepted".to_owned();
    };
    let Ok(bytes) = bytes else {
        return "could not read the file".to_owned();
    };
    match content
        .0
        .stage(bytes.as_slice(), mime, move |conn, file_id| {
            stage_photo_row(conn, file_id, &identity)
        })
        .await
    {
        Ok(_) => format!("staged: {name}"),
        Err(err) => format!("stage failed: {err}"),
    }
}

/// Export this device's local data to an archive, answering with the line the
/// pane shows.
#[cfg(target_arch = "wasm32")]
pub async fn export_data(_content: &DemoContent) -> String {
    web::export_data().await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn export_data(content: &DemoContent) -> String {
    native::export_data(content).await
}

/// Subscribe to the content lane's live events and update the given signals.
/// The web lane has no such events, so this is a no-op there.
#[cfg(not(target_arch = "wasm32"))]
pub fn watch_content_events(
    content: &DemoContent,
    mut feed_status: Signal<Option<String>>,
    mut refused: Signal<Vec<(FileId, String)>>,
    mut retired: Signal<Vec<FileId>>,
) {
    let cc = content.clone();
    spawn(async move {
        let mut rx = cc.client().events();
        while let Ok(event) = rx.recv().await {
            feed_status.set(Some(native::content_label(&event)));
            match event {
                connetto_file_client::ContentEvent::UploadRefused { file_id, detail } => {
                    if !refused.read().iter().any(|(id, _)| *id == file_id) {
                        refused.write().push((file_id, detail));
                    }
                }
                connetto_file_client::ContentEvent::BytesLost { file_id, .. }
                    if !retired.read().contains(&file_id) =>
                {
                    retired.write().push(file_id);
                }
                _ => {}
            }
        }
    });
}

#[cfg(target_arch = "wasm32")]
pub fn watch_content_events(
    _content: &DemoContent,
    _feed_status: Signal<Option<String>>,
    _refused: Signal<Vec<(FileId, String)>>,
    _retired: Signal<Vec<FileId>>,
) {
}

/// The onchange handler for the photo file input, the platform's file reading
/// and the staging folded in.
#[cfg(target_arch = "wasm32")]
pub fn photo_onchange(
    content: DemoContent,
    client: Client,
    identity: String,
    msg: Signal<Option<String>>,
) -> impl FnMut(FormEvent) {
    move |_: FormEvent| {
        let window = web_sys::window().expect("window");
        let input: web_sys::HtmlInputElement = window
            .document()
            .expect("document")
            .get_element_by_id("photo-file-input")
            .expect("photo input")
            .unchecked_into();
        if let Some(files) = input.files()
            && let Some(file) = files.get(0)
        {
            let name = file.name();
            let cc = content.clone();
            let cl = client.clone();
            let identity = identity.clone();
            spawn(async move {
                let mut msg = msg;
                let blob: web_sys::Blob = file.into();
                msg.set(Some(stage_picked(&cc, &cl, &blob, &name, identity).await));
            });
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn photo_onchange(
    content: DemoContent,
    _client: Client,
    identity: String,
    msg: Signal<Option<String>>,
) -> impl FnMut(FormEvent) {
    move |evt: FormEvent| {
        let files = evt.files();
        let cc = content.clone();
        let identity = identity.clone();
        spawn(async move {
            let mut msg = msg;
            let Some(file) = files.into_iter().next() else {
                return;
            };
            let name = file.name();
            let bytes = file
                .read_bytes()
                .await
                .map(|b| b.to_vec())
                .map_err(|err| err.to_string());
            msg.set(Some(stage_picked(&cc, &name, bytes, identity).await));
        });
    }
}

/// The onchange handler for the import file input, the platform's file reading
/// and the archive restore folded in.
#[cfg(target_arch = "wasm32")]
pub fn import_onchange(
    _content: DemoContent,
    msg: Signal<Option<String>>,
) -> impl FnMut(FormEvent) {
    move |_: FormEvent| {
        let window = web_sys::window().expect("window");
        let input: web_sys::HtmlInputElement = window
            .document()
            .expect("document")
            .get_element_by_id("import-file-input")
            .expect("import input")
            .unchecked_into();
        if let Some(files) = input.files()
            && let Some(file) = files.get(0)
        {
            let blob: web_sys::Blob = file.into();
            let mut msg = msg;
            spawn(async move {
                msg.set(Some(web::import_data(&blob).await));
            });
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn import_onchange(content: DemoContent, msg: Signal<Option<String>>) -> impl FnMut(FormEvent) {
    move |evt: FormEvent| {
        let files = evt.files();
        let cc = content.clone();
        let mut msg = msg;
        spawn(async move {
            let Some(file) = files.into_iter().next() else {
                return;
            };
            let bytes = file
                .read_bytes()
                .await
                .map(|b| b.to_vec())
                .map_err(|err| err.to_string());
            msg.set(Some(native::import_data(&cc, bytes).await));
        });
    }
}
