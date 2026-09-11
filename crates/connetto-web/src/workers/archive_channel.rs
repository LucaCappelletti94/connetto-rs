use core::fmt::Display;
use core::future::Future;
use std::cell::RefCell;
use std::rc::Rc;

use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{BroadcastChannel, File, MessageEvent};

use connetto_client::{ExportScope, ImportOutcome};

use super::helpers::sleep_ms;

const EXPORT_REPLY_OK: &str = "export";
const EXPORT_REPLY_FAILED: &str = "export-failed";
const EXPORT_GENERATION_REPLY: &str = "export-generation";
const IMPORT_REPLY_OK: &str = "import";
const IMPORT_REPLY_FAILED: &str = "import-failed";

/// Poll step while waiting for a channel reply.
const POLL_MS: i32 = 25;

type ExportReply = Result<Vec<u8>, String>;

#[derive(Default)]
struct ExportWait {
    generation: Option<String>,
    replaced: bool,
    result: Option<ExportReply>,
}

type ExportSlot = Rc<RefCell<ExportWait>>;
type ImportReply = Result<(ImportOutcome, usize), String>;
type ImportSlot = Rc<RefCell<Option<ImportReply>>>;

/// Addresses one export exchange by worker generation and caller id.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct ExportTag {
    pub(super) generation: String,
    pub(super) request: String,
}

impl ExportTag {
    fn read(data: &JsValue) -> Option<Self> {
        Some(Self {
            generation: export_message_field(data, "generation")?,
            request: export_message_field(data, "request")?,
        })
    }

    fn write(&self, message: &js_sys::Object) -> Result<(), JsValue> {
        set_export_generation(message, &self.generation)?;
        js_sys::Reflect::set(
            message,
            &JsValue::from_str("request"),
            &JsValue::from_str(&self.request),
        )?;
        Ok(())
    }
}

fn export_message_kind(data: &JsValue) -> Option<String> {
    js_sys::Reflect::get(data, &JsValue::from_str("kind"))
        .ok()?
        .as_string()
}

fn export_message_field(data: &JsValue, key: &str) -> Option<String> {
    js_sys::Reflect::get(data, &JsValue::from_str(key))
        .ok()?
        .as_string()
}

fn export_message_generation(data: &JsValue) -> Option<String> {
    export_message_field(data, "generation")
}

fn is_export_generation_request(data: &JsValue) -> bool {
    export_message_kind(data).as_deref() == Some("generation?")
}

fn decode_export_generation(data: &JsValue) -> Option<String> {
    (export_message_kind(data).as_deref() == Some(EXPORT_GENERATION_REPLY))
        .then(|| export_message_generation(data))
        .flatten()
}

fn build_export_generation_request() -> JsValue {
    let request = js_sys::Object::new();
    let _ = js_sys::Reflect::set(
        &request,
        &JsValue::from_str("kind"),
        &JsValue::from_str("generation?"),
    );
    request.into()
}

pub(super) fn decode_export_request(data: &JsValue) -> Option<(ExportTag, ExportScope)> {
    if export_message_kind(data).as_deref() != Some("export?") {
        return None;
    }
    let tag = ExportTag::read(data)?;
    let scope = match export_message_field(data, "scope")?.as_str() {
        "everything" => ExportScope::Everything,
        "unsynced" => ExportScope::Unsynced,
        _ => return None,
    };
    Some((tag, scope))
}

fn build_export_request(scope: ExportScope, tag: &ExportTag) -> JsValue {
    let request = js_sys::Object::new();
    let scope = match scope {
        ExportScope::Everything => "everything",
        ExportScope::Unsynced => "unsynced",
    };
    let _ = js_sys::Reflect::set(
        &request,
        &JsValue::from_str("kind"),
        &JsValue::from_str("export?"),
    );
    let _ = tag.write(&request);
    let _ = js_sys::Reflect::set(
        &request,
        &JsValue::from_str("scope"),
        &JsValue::from_str(scope),
    );
    request.into()
}

fn decode_export_reply(data: &JsValue) -> Option<(ExportTag, ExportReply)> {
    let tag = ExportTag::read(data)?;
    let reply = match export_message_kind(data)?.as_str() {
        EXPORT_REPLY_OK => {
            let bytes = js_sys::Reflect::get(data, &JsValue::from_str("bytes")).ok()?;
            Ok(js_sys::Uint8Array::new(&bytes).to_vec())
        }
        EXPORT_REPLY_FAILED => {
            let error = js_sys::Reflect::get(data, &JsValue::from_str("error"))
                .ok()
                .and_then(|value| value.as_string())
                .unwrap_or_else(|| "the worker gave no reason".to_owned());
            Err(error)
        }
        _ => return None,
    };
    Some((tag, reply))
}

fn decode_import_reply(data: &JsValue) -> Option<ImportReply> {
    let kind = js_sys::Reflect::get(data, &JsValue::from_str("kind"))
        .ok()?
        .as_string()?;
    match kind.as_str() {
        IMPORT_REPLY_OK => {
            let get_count = |key: &str| -> Option<usize> {
                let v = js_sys::Reflect::get(data, &JsValue::from_str(key)).ok()?;
                count_from_js(&v)
            };
            let outcome = ImportOutcome {
                rows_restored: get_count("rows_restored")?,
                rows_kept: get_count("rows_kept")?,
                writes_restored: get_count("writes_restored")?,
            };
            let collisions = get_count("collisions")?;
            Some(Ok((outcome, collisions)))
        }
        IMPORT_REPLY_FAILED => {
            let error = js_sys::Reflect::get(data, &JsValue::from_str("error"))
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_else(|| "the worker gave no reason".to_owned());
            Some(Err(error))
        }
        _ => None,
    }
}

/// A JS number used as a count: finite, non-negative, integer, at most `u32::MAX`.
fn count_from_js(value: &JsValue) -> Option<usize> {
    let number = value.as_f64()?;
    if !number.is_finite() || number < 0.0 || number.fract() != 0.0 || number > f64::from(u32::MAX)
    {
        return None;
    }
    // no TryFrom<f64> for u32 exists; guard above proves finite, non-negative, whole, within u32
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "guard above proves the cast is exact and non-negative"
    )]
    let count = number as u32;
    usize::try_from(count).ok()
}

pub(super) fn export_generation_reply(generation: &str) -> Result<JsValue, JsValue> {
    let reply = js_sys::Object::new();
    js_sys::Reflect::set(
        &reply,
        &JsValue::from_str("kind"),
        &JsValue::from_str(EXPORT_GENERATION_REPLY),
    )?;
    set_export_generation(&reply, generation)?;
    Ok(reply.into())
}

fn set_export_generation(reply: &js_sys::Object, generation: &str) -> Result<bool, JsValue> {
    js_sys::Reflect::set(
        reply,
        &JsValue::from_str("generation"),
        &JsValue::from_str(generation),
    )
}

pub(super) fn export_reply_ok(tag: &ExportTag, bytes: &[u8]) -> Result<JsValue, JsValue> {
    let reply = js_sys::Object::new();
    js_sys::Reflect::set(
        &reply,
        &JsValue::from_str("kind"),
        &JsValue::from_str(EXPORT_REPLY_OK),
    )?;
    tag.write(&reply)?;
    js_sys::Reflect::set(
        &reply,
        &JsValue::from_str("bytes"),
        &js_sys::Uint8Array::from(bytes),
    )?;
    Ok(reply.into())
}

fn export_reply_failed(tag: &ExportTag, error: &str) -> Result<JsValue, JsValue> {
    let reply = js_sys::Object::new();
    js_sys::Reflect::set(
        &reply,
        &JsValue::from_str("kind"),
        &JsValue::from_str(EXPORT_REPLY_FAILED),
    )?;
    tag.write(&reply)?;
    js_sys::Reflect::set(
        &reply,
        &JsValue::from_str("error"),
        &JsValue::from_str(error),
    )?;
    Ok(reply.into())
}

fn import_reply_ok(outcome: &ImportOutcome, collisions: usize) -> Result<JsValue, JsValue> {
    let reply = js_sys::Object::new();
    js_sys::Reflect::set(
        &reply,
        &JsValue::from_str("kind"),
        &JsValue::from_str(IMPORT_REPLY_OK),
    )?;
    let set = |key: &str, count: usize| -> Result<bool, JsValue> {
        // counts fit u32 on every wasm target; saturate rather than fail on the impossible overflow
        js_sys::Reflect::set(
            &reply,
            &JsValue::from_str(key),
            &JsValue::from(u32::try_from(count).unwrap_or(u32::MAX)),
        )
    };
    set("rows_restored", outcome.rows_restored)?;
    set("rows_kept", outcome.rows_kept)?;
    set("writes_restored", outcome.writes_restored)?;
    set("collisions", collisions)?;
    Ok(reply.into())
}

fn import_reply_failed(error: &str) -> Result<JsValue, JsValue> {
    let reply = js_sys::Object::new();
    js_sys::Reflect::set(
        &reply,
        &JsValue::from_str("kind"),
        &JsValue::from_str(IMPORT_REPLY_FAILED),
    )?;
    js_sys::Reflect::set(
        &reply,
        &JsValue::from_str("error"),
        &JsValue::from_str(error),
    )?;
    Ok(reply.into())
}

async fn poll_for_export_generation(
    channel: &BroadcastChannel,
    state: &ExportSlot,
    generation_request: &JsValue,
) -> Option<String> {
    let mut posted = channel.post_message(generation_request);
    while posted.is_ok()
        && state.borrow().generation.is_none()
        && !state.borrow().replaced
        && crate::locks::lock_is_held(super::DB_ALIVE_LOCK).await
    {
        sleep_ms(POLL_MS).await;
        if state.borrow().generation.is_none() {
            posted = channel.post_message(generation_request);
        }
    }
    state.borrow().generation.clone()
}

async fn poll_for_export_reply(
    channel: &BroadcastChannel,
    state: &ExportSlot,
    generation_request: &JsValue,
    scope: ExportScope,
    tag: ExportTag,
) {
    let posted = channel.post_message(&build_export_request(scope, &tag));
    while posted.is_ok()
        && state.borrow().result.is_none()
        && !state.borrow().replaced
        && crate::locks::lock_is_held(super::DB_ALIVE_LOCK).await
    {
        let _ = channel.post_message(generation_request);
        sleep_ms(POLL_MS).await;
    }
}

/// Serve [`super::EXPORT_CHANNEL`] for this worker's life.
///
/// [`super::boot_db_worker`] calls this itself; call directly when assembling a worker by hand.
///
/// # Errors
///
/// The `BroadcastChannel` error when the channel cannot be opened.
pub fn serve_export_requests(hub: crate::relay::RelayHub) -> Result<(), JsValue> {
    serve_exports(move |scope| {
        let hub = hub.clone();
        async move { hub.export_local_data(scope).await }
    })
}

fn serve_exports<F, Fut, E>(export: F) -> Result<(), JsValue>
where
    F: Fn(ExportScope) -> Fut + 'static,
    Fut: Future<Output = Result<Vec<u8>, E>> + 'static,
    E: Display + 'static,
{
    let channel = BroadcastChannel::new(super::EXPORT_CHANNEL)
        .map_err(|err| JsValue::from_str(&format!("export channel: {err:?}")))?;
    let generation = Rc::new(rosetta_uuid::Uuid::new_v4().to_string());
    let export = Rc::new(export);
    let listener = {
        let channel = channel.clone();
        let generation = Rc::clone(&generation);
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if is_export_generation_request(&event.data()) {
                if let Ok(reply) = export_generation_reply(&generation) {
                    let _ = channel.post_message(&reply);
                }
                return;
            }
            let Some((tag, scope)) = decode_export_request(&event.data()) else {
                return;
            };
            if tag.generation != *generation {
                return;
            }
            let channel = channel.clone();
            let export = Rc::clone(&export);
            spawn_local(async move {
                let reply = match export(scope).await {
                    Ok(bytes) => export_reply_ok(&tag, &bytes),
                    Err(err) => export_reply_failed(&tag, &err.to_string()),
                };
                match reply {
                    Ok(reply) => {
                        let _ = channel.post_message(&reply);
                    }
                    Err(err) => {
                        tracing::error!(error = ?err, "db worker: building an export reply failed");
                    }
                }
            });
        })
    };
    channel.set_onmessage(Some(listener.as_ref().unchecked_ref()));
    listener.forget();
    Ok(())
}

/// Serve [`super::IMPORT_CHANNEL`] for this worker's life.
///
/// [`super::boot_db_worker`] calls this itself; call directly when assembling a worker by hand.
///
/// # Errors
///
/// The `BroadcastChannel` error when the channel cannot be opened.
pub fn serve_import_requests(hub: crate::relay::RelayHub) -> Result<(), JsValue> {
    serve_imports(move |bytes| {
        let hub = hub.clone();
        async move { hub.import_local_data(bytes).await }
    })
}

fn serve_imports<F, Fut, E>(import: F) -> Result<(), JsValue>
where
    F: Fn(Vec<u8>) -> Fut + 'static,
    Fut: Future<Output = Result<(ImportOutcome, usize), E>> + 'static,
    E: Display + 'static,
{
    let channel = BroadcastChannel::new(super::IMPORT_CHANNEL)
        .map_err(|err| JsValue::from_str(&format!("import channel: {err:?}")))?;
    let import = Rc::new(import);
    let listener = {
        let channel = channel.clone();
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let Ok(file) = event.data().dyn_into::<File>() else {
                return;
            };
            let channel = channel.clone();
            let import = Rc::clone(&import);
            spawn_local(async move {
                let buffer = match JsFuture::from(file.array_buffer()).await {
                    Ok(buffer) => buffer,
                    Err(err) => {
                        tracing::error!(error = ?err, "db worker: reading import file failed");
                        return;
                    }
                };
                let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
                let reply = match import(bytes).await {
                    Ok((outcome, collisions)) => import_reply_ok(&outcome, collisions),
                    Err(err) => import_reply_failed(&err.to_string()),
                };
                match reply {
                    Ok(reply) => {
                        let _ = channel.post_message(&reply);
                    }
                    Err(err) => {
                        tracing::error!(error = ?err, "db worker: building an import reply failed");
                    }
                }
            });
        })
    };
    channel.set_onmessage(Some(listener.as_ref().unchecked_ref()));
    listener.forget();
    Ok(())
}

/// Page side: ask the DB worker for a zip archive of this device's local data.
///
/// # Errors
///
/// [`crate::relay::ExportRefused::Gone`] when no DB worker is running,
/// [`crate::relay::ExportRefused::Failed`] when the worker answered without an archive.
pub async fn request_export(scope: ExportScope) -> Result<Vec<u8>, crate::relay::ExportRefused> {
    let channel = BroadcastChannel::new(super::EXPORT_CHANNEL)
        .map_err(|err| crate::relay::ExportRefused::Failed(format!("export channel: {err:?}")))?;
    let state: ExportSlot = Rc::new(RefCell::new(ExportWait::default()));
    let request = rosetta_uuid::Uuid::new_v4().to_string();
    let on_message = {
        let state = Rc::clone(&state);
        let request = request.clone();
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if let Some(generation) = decode_export_generation(&event.data()) {
                let mut state = state.borrow_mut();
                match &state.generation {
                    Some(expected) if expected != &generation => state.replaced = true,
                    None => state.generation = Some(generation),
                    Some(_) => {}
                }
                return;
            }
            let Some((tag, reply)) = decode_export_reply(&event.data()) else {
                return;
            };
            let mut state = state.borrow_mut();
            if tag.request == request
                && state.generation.as_deref() == Some(tag.generation.as_str())
            {
                state.result.get_or_insert(reply);
            }
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    let generation_request = build_export_generation_request();
    let generation = poll_for_export_generation(&channel, &state, &generation_request).await;
    if let Some(generation) = generation
        && !state.borrow().replaced
    {
        let tag = ExportTag {
            generation,
            request,
        };
        poll_for_export_reply(&channel, &state, &generation_request, scope, tag).await;
    }
    channel.set_onmessage(None);
    channel.close();
    drop(on_message);
    let mut state = state.borrow_mut();
    match state.result.take() {
        Some(Ok(bytes)) if !state.replaced => Ok(bytes),
        Some(Err(err)) if !state.replaced => Err(crate::relay::ExportRefused::Failed(err)),
        _ => Err(crate::relay::ExportRefused::Gone(crate::relay::HubGone)),
    }
}

/// Page side: hand the DB worker a `File` to import and wait for the outcome.
///
/// # Errors
///
/// [`crate::relay::ImportRefused::Gone`] when no DB worker is running,
/// [`crate::relay::ImportRefused::Failed`] when the worker refused the import.
pub async fn request_import(
    file: File,
) -> Result<(ImportOutcome, usize), crate::relay::ImportRefused> {
    let channel = BroadcastChannel::new(super::IMPORT_CHANNEL)
        .map_err(|err| crate::relay::ImportRefused::Failed(format!("import channel: {err:?}")))?;
    let result: ImportSlot = Rc::new(RefCell::new(None));
    let on_message = {
        let result = Rc::clone(&result);
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if let Some(reply) = decode_import_reply(&event.data()) {
                result.borrow_mut().get_or_insert(reply);
            }
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    let posted = channel.post_message(file.as_ref());
    while posted.is_ok()
        && result.borrow().is_none()
        && crate::locks::lock_is_held(super::DB_ALIVE_LOCK).await
    {
        sleep_ms(POLL_MS).await;
    }
    channel.set_onmessage(None);
    channel.close();
    drop(on_message);
    match result.borrow_mut().take() {
        Some(Ok((outcome, collisions))) => Ok((outcome, collisions)),
        Some(Err(err)) => Err(crate::relay::ImportRefused::Failed(err)),
        None => Err(crate::relay::ImportRefused::Gone(crate::relay::HubGone)),
    }
}
