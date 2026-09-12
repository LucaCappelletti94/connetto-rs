#![doc = include_str!("../README.md")]

mod archive;
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod browser_store;
mod client;
mod db;
mod error;
pub mod http;
mod import;
pub mod resolve;
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
mod store;
mod ticket;
mod upload;
mod worker;
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub use browser_store::{BrowserStore, BrowserStoreError};

pub use client::{ContentClient, ContentEvent};
pub use connetto_file_core::FileId;
pub use error::ContentError;
pub use import::ContentImportPlan;
pub use resolve::{BoxedSource, ChunkStoreSource, LocalContentSource, Resolved, SourceFuture};
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub use store::{FsStore, FsStoreError};
pub use worker::{
    ChunkScan, ContentArchive, ContentFlush, ContentFlushStart, ContentFlushState, ContentUpload,
    FlushCursor, ScanStep,
};

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub use http::ReqwestHttp;
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub use http::{BrowserHttp, BrowserHttpError};
pub use http::{ContentHttp, HttpReply};
