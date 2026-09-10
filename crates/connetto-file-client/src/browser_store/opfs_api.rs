use js_sys::{AsyncIterator, Function, Promise, Reflect};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    DomException, FileSystemDirectoryHandle, FileSystemFileHandle, FileSystemGetDirectoryOptions,
    FileSystemGetFileOptions, FileSystemWritableFileStream,
};

use super::BrowserStoreError;

pub(super) async fn write_file(
    handle: &FileSystemFileHandle,
    data: &[u8],
) -> Result<(), BrowserStoreError> {
    let writable = JsFuture::from(handle.create_writable())
        .await
        .map_err(|value| browser_error("create writable chunk", &value))?
        .dyn_into::<FileSystemWritableFileStream>()
        .map_err(|value| type_error("decode writable chunk", &value))?;
    let write = writable
        .write_with_u8_array(data)
        .map_err(|value| browser_error("begin chunk write", &value))?;
    if let Err(value) = JsFuture::from(write).await {
        let _ = JsFuture::from(writable.abort()).await;
        return Err(browser_error("write chunk", &value));
    }
    JsFuture::from(writable.close())
        .await
        .map_err(|value| browser_error("commit chunk write", &value))?;
    Ok(())
}

pub(super) async fn move_file(
    handle: &FileSystemFileHandle,
    directory: &FileSystemDirectoryHandle,
    name: &str,
) -> Result<(), BrowserStoreError> {
    let function = Reflect::get(handle.as_ref(), &JsValue::from_str("move"))
        .map_err(|value| browser_error("find atomic move", &value))?
        .dyn_into::<Function>()
        .map_err(|value| type_error("decode atomic move", &value))?;
    let value = function
        .call2(
            handle.as_ref(),
            directory.as_ref(),
            &JsValue::from_str(name),
        )
        .map_err(|value| browser_error("begin atomic move", &value))?;
    let promise = value
        .dyn_into::<Promise>()
        .map_err(|value| type_error("decode atomic move result", &value))?;
    JsFuture::from(promise)
        .await
        .map_err(|value| browser_error("land chunk", &value))?;
    Ok(())
}

pub(super) async fn directory_handle(
    parent: &FileSystemDirectoryHandle,
    name: &str,
    create: bool,
) -> Result<Option<FileSystemDirectoryHandle>, BrowserStoreError> {
    let options = FileSystemGetDirectoryOptions::new();
    options.set_create(create);
    match JsFuture::from(parent.get_directory_handle_with_options(name, &options)).await {
        Ok(value) => value
            .dyn_into::<FileSystemDirectoryHandle>()
            .map(Some)
            .map_err(|value| type_error("decode directory handle", &value)),
        Err(value) if !create && (is_not_found(&value) || is_type_mismatch(&value)) => Ok(None),
        Err(value) => Err(browser_error("open directory", &value)),
    }
}

pub(super) async fn file_handle(
    parent: &FileSystemDirectoryHandle,
    name: &str,
    create: bool,
) -> Result<Option<FileSystemFileHandle>, BrowserStoreError> {
    let options = FileSystemGetFileOptions::new();
    options.set_create(create);
    match JsFuture::from(parent.get_file_handle_with_options(name, &options)).await {
        Ok(value) => value
            .dyn_into::<FileSystemFileHandle>()
            .map(Some)
            .map_err(|value| type_error("decode file handle", &value)),
        Err(value) if !create && is_not_found(&value) => Ok(None),
        Err(value) if !create && is_type_mismatch(&value) => Err(type_error("open chunk", &value)),
        Err(value) => Err(browser_error("open chunk", &value)),
    }
}

pub(super) async fn next_key(
    iterator: &AsyncIterator,
) -> Result<Option<String>, BrowserStoreError> {
    let promise = iterator
        .next()
        .map_err(|value| browser_error("list directory", &value))?;
    let result = JsFuture::from(promise)
        .await
        .map_err(|value| browser_error("list directory", &value))?;
    let done = Reflect::get(&result, &JsValue::from_str("done"))
        .map_err(|value| browser_error("read directory iterator state", &value))?
        .as_bool()
        .unwrap_or(false);
    if done {
        return Ok(None);
    }
    Ok(Reflect::get(&result, &JsValue::from_str("value"))
        .map_err(|value| browser_error("read directory entry", &value))?
        .as_string())
}

pub(super) fn is_not_found(value: &JsValue) -> bool {
    value
        .dyn_ref::<DomException>()
        .is_some_and(|exception| exception.name() == "NotFoundError")
}

fn is_type_mismatch(value: &JsValue) -> bool {
    value
        .dyn_ref::<DomException>()
        .is_some_and(|exception| exception.name() == "TypeMismatchError")
}

pub(super) fn browser_error(operation: &'static str, value: &JsValue) -> BrowserStoreError {
    BrowserStoreError::Browser {
        operation,
        message: error_message(value),
    }
}

pub(super) fn type_error(operation: &'static str, value: &JsValue) -> BrowserStoreError {
    BrowserStoreError::UnexpectedType {
        operation,
        message: error_message(value),
    }
}

fn error_message(value: &JsValue) -> String {
    value
        .dyn_ref::<DomException>()
        .map(|exception| format!("{}: {}", exception.name(), exception.message()))
        .or_else(|| value.as_string())
        .unwrap_or_else(|| format!("{value:?}"))
}
