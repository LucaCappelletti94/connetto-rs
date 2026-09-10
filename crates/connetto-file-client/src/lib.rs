#![doc = include_str!("../README.md")]

mod archive;
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod browser_store;
mod client;
mod db;
mod error;
pub mod http;
pub mod resolve;
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
mod store;
mod ticket;
mod upload;
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub use browser_store::{BrowserStore, BrowserStoreError};

pub use client::{
    ContentArchive, ContentClient, ContentEvent, ContentFlush, ContentFlushState, ContentImportPlan,
};
pub use error::ContentError;
pub use resolve::{BoxedSource, ChunkStoreSource, LocalContentSource, Resolved, SourceFuture};
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub use store::{FsStore, FsStoreError};

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub use http::ReqwestHttp;
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub use http::{BrowserHttp, BrowserHttpError};
pub use http::{ContentHttp, HttpReply};
