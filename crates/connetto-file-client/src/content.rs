//! The content piece the builder attaches, carrying the transfer idle bound
//! and the lost-file heal queries, and the running client it builds.

use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;

use connetto_client::live::ConnettoClient;
use connetto_client::{AttachContent, ClientError, ContentPlace, TokioSleeper};
use connetto_core::Transport;
use connetto_core::traits::MaybeSend;
use connetto_file_core::MemStore;

use crate::http::{DEFAULT_IDLE_BOUND, ReqwestHttp};
use crate::{ContentClient, FsStore};

/// The content piece a build attaches.
///
/// `Default` is the 30 s transfer idle bound and no heal queries.
#[derive(Clone, Debug)]
pub struct Content {
    idle_bound: Duration,
    heal_queries: Vec<(String, String)>,
}

impl Default for Content {
    fn default() -> Self {
        Self {
            idle_bound: DEFAULT_IDLE_BOUND,
            heal_queries: Vec::new(),
        }
    }
}

impl Content {
    /// An empty piece, the 30 s idle bound and no heal queries.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The idle bound a stalled chunk transfer gives up at.
    #[must_use]
    pub fn with_transfer_idle_bound(mut self, bound: Duration) -> Self {
        self.idle_bound = bound;
        self
    }

    /// A heal query, the `query` that names the files the server marked lost
    /// and the `file_id_column` holding their file ids. Repeatable.
    #[must_use]
    pub fn with_heal_lost(mut self, query: impl Into<String>, column: impl Into<String>) -> Self {
        self.heal_queries.push((query.into(), column.into()));
        self
    }
}

/// The running content client a piece builds, placed durable or in memory.
pub enum ContentHandle<T: Transport> {
    /// Durable, at the content directory beside the replica file.
    Durable(Arc<ContentClient<T, FsStore, ReqwestHttp>>),
    /// In memory, nothing at rest.
    InMemory(Arc<ContentClient<T, MemStore, ReqwestHttp>>),
}

impl<T: Transport + MaybeSend + 'static> AttachContent<T> for Content
where
    T::Error: Display,
{
    type Handle = ContentHandle<T>;

    async fn attach(
        self,
        client: ConnettoClient<T>,
        root_key: [u8; 32],
        place: ContentPlace,
    ) -> Result<ContentHandle<T>, ClientError> {
        let http = ReqwestHttp::new().with_idle_bound(self.idle_bound);
        let heal_queries = self.heal_queries;
        let content = match place {
            ContentPlace::Durable(dir) => {
                let mut content = ContentClient::attach(client, FsStore::new(dir), root_key, http)
                    .await
                    .map_err(|err| ClientError::Content(err.to_string()))?;
                for (query, column) in &heal_queries {
                    content = content
                        .heal_lost(query, column)
                        .await
                        .map_err(|err| ClientError::Content(err.to_string()))?;
                }
                let content = Arc::new(content);
                tokio::spawn({
                    let content = Arc::clone(&content);
                    async move {
                        content.drive_outbox(TokioSleeper).await;
                    }
                });
                ContentHandle::Durable(content)
            }
            ContentPlace::InMemory => {
                let mut content = ContentClient::attach(client, MemStore::new(), root_key, http)
                    .await
                    .map_err(|err| ClientError::Content(err.to_string()))?;
                for (query, column) in &heal_queries {
                    content = content
                        .heal_lost(query, column)
                        .await
                        .map_err(|err| ClientError::Content(err.to_string()))?;
                }
                let content = Arc::new(content);
                tokio::spawn({
                    let content = Arc::clone(&content);
                    async move {
                        content.drive_outbox(TokioSleeper).await;
                    }
                });
                ContentHandle::InMemory(content)
            }
        };
        Ok(content)
    }
}
