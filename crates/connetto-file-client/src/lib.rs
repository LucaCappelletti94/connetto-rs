#![doc = include_str!("../README.md")]

mod client;
mod db;
mod error;
pub mod http;
pub mod resolve;
mod store;
mod ticket;
mod upload;

pub use client::{ContentClient, ContentEvent};
pub use error::ContentError;
pub use resolve::{BoxedSource, ChunkStoreSource, LocalContentSource, Resolved, SourceFuture};
pub use store::{FsStore, FsStoreError};

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub use http::ReqwestHttp;
pub use http::{ContentHttp, HttpReply};
