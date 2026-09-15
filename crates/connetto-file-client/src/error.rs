//! The one error type the content surface returns.

use connetto_file_core::{ChunkHash, FileId};
use thiserror::Error;

/// Errors produced by the content client.
#[derive(Debug, Error)]
pub enum ContentError {
    /// A replica read or write failed.
    #[error("replica: {0}")]
    Replica(#[from] diesel::result::Error),
    /// The sync client refused an operation.
    #[error("client: {0}")]
    Client(#[from] connetto_client::ClientError),
    /// Reading the file being staged, or a chunk store operation, failed.
    #[error("chunk store: {0}")]
    Store(String),
    /// Content attachments in a device archive are malformed or incomplete.
    #[error("content archive: {0}")]
    Archive(String),
    /// The HTTP transport failed before any status was seen.
    #[error("content transport: {0}")]
    Transport(String),
    /// The server refused a content ticket. Byte-identical for an invisible
    /// file and an over-budget request, by design: see chapter 18.
    #[error("content ticket refused for {file_id}")]
    TicketRefused {
        /// The file the refused request named.
        file_id: FileId,
    },
    /// The server could not mint a ticket. A retry may work.
    #[error("content ticket could not be minted for {file_id}")]
    TicketSignerError {
        /// The file the request named.
        file_id: FileId,
    },
    /// The caller asked for tickets too often.
    #[error("content ticket rate limited, retry in {retry_after_ms} ms")]
    TicketRateLimited {
        /// How long the server asked the caller to wait.
        retry_after_ms: u64,
    },
    /// The connection ended before the ticket answer arrived.
    #[error("connection ended before the content ticket answer arrived")]
    TicketAbandoned,
    /// The event stream dropped the answer because this caller fell behind.
    #[error("the client event stream lagged past the content ticket answer")]
    TicketLagged,
    /// A granted URL was not in the shape the file server mints.
    #[error("granted content url is malformed: {0}")]
    MalformedGrant(String),
    /// The file server answered a status the protocol does not use here.
    #[error("content server answered {status} at {stage}")]
    Http {
        /// The stage of the negotiation that failed.
        stage: &'static str,
        /// The HTTP status code.
        status: u16,
    },
    /// A content request was redirected, which the protocol refuses on every
    /// path. The mint issues exact addresses, so no hop belongs to a transfer.
    #[error("content request at {stage} was redirected to {}", origin.as_deref().unwrap_or("an undisclosed address"))]
    Redirected {
        /// The stage of the negotiation that was redirected.
        stage: &'static str,
        /// The origin of the reply that landed, absent when the redirect was
        /// refused before a reply landed. The origin rather than the whole
        /// address, because a landed address can carry the ticket.
        origin: Option<String>,
    },
    /// The file server's answer could not be decoded.
    #[error("content server answer at {stage} could not be decoded: {source}")]
    Decode {
        /// The stage of the negotiation whose answer was undecodable.
        stage: &'static str,
        /// The decoding failure.
        #[source]
        source: serde_json::Error,
    },
    /// This device holds no manifest for the file, so its chunks cannot be
    /// named. Nothing else can be said about it locally.
    #[error("no local manifest for {file_id}")]
    NoManifest {
        /// The file with no manifest here.
        file_id: FileId,
    },
    /// A chunk the manifest names is unreadable in a way no later attempt clears.
    #[error("content for {file_id} names a chunk this device cannot read: {detail}")]
    LostChunk {
        /// The file whose bytes are gone.
        file_id: FileId,
        /// The chunk the manifest names that the store cannot read.
        hash: ChunkHash,
        /// What the store reported about the unreadable chunk.
        detail: String,
    },
    /// Downloaded bytes did not hash to the identity that was asked for.
    #[error("downloaded bytes are not {expected}")]
    IdentityMismatch {
        /// The identity the caller asked for.
        expected: FileId,
        /// The identity the bytes actually carry.
        actual: FileId,
    },
    /// A pin query did not answer with the column it named.
    #[error("pin {name} names column {column}, which its query does not return")]
    PinColumnMissing {
        /// The pin's application-chosen name.
        name: String,
        /// The column the pin named.
        column: String,
    },
}

/// What the outbox walk does with a failed upload attempt, decided by where the fact came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// Keep the entry and walk it again later.
    Retry,
    /// Keep the entry in the outbox, marked with its refusal detail.
    Refused,
    /// Retire the entry, because its bytes are gone from this device.
    Lost,
}

impl ContentError {
    /// How the outbox walk deals with this failure, per chapter 18's two-event rule.
    #[must_use]
    pub fn outcome(&self) -> AttemptOutcome {
        match self {
            Self::NoManifest { .. } | Self::LostChunk { .. } => AttemptOutcome::Lost,
            Self::Http {
                status: 400 | 413 | 422,
                ..
            }
            | Self::Decode { .. }
            | Self::Redirected { .. }
            | Self::MalformedGrant(_)
            | Self::IdentityMismatch { .. }
            | Self::Archive(_)
            | Self::PinColumnMissing { .. } => AttemptOutcome::Refused,
            Self::Http { .. }
            | Self::Replica(_)
            | Self::Client(_)
            | Self::Store(_)
            | Self::Transport(_)
            | Self::TicketRefused { .. }
            | Self::TicketSignerError { .. }
            | Self::TicketRateLimited { .. }
            | Self::TicketAbandoned
            | Self::TicketLagged => AttemptOutcome::Retry,
        }
    }
}

#[cfg(test)]
mod tests {
    use connetto_file_core::FileId;

    use super::{AttemptOutcome, ContentError};

    fn file() -> FileId {
        FileId::from_bytes([7; 32])
    }

    /// A device loss, a server refusal and a keep-and-retry failure are told apart.
    #[test]
    fn losses_refusals_and_retryable_failures_are_told_apart() {
        assert_eq!(
            ContentError::NoManifest { file_id: file() }.outcome(),
            AttemptOutcome::Lost,
        );
        assert_eq!(
            ContentError::LostChunk {
                file_id: file(),
                hash: connetto_file_core::ChunkHash::from_bytes([9; 32]),
                detail: "chunk gone".to_owned(),
            }
            .outcome(),
            AttemptOutcome::Lost,
        );
        for status in [400, 413, 422] {
            assert_eq!(
                ContentError::Http {
                    stage: "commit",
                    status,
                }
                .outcome(),
                AttemptOutcome::Refused,
                "HTTP {status} is a server refusal",
            );
        }
        assert_eq!(
            ContentError::MalformedGrant("no token".to_owned()).outcome(),
            AttemptOutcome::Refused,
        );
        let undecodable = serde_json::from_slice::<serde_json::Value>(b"not json").unwrap_err();
        assert_eq!(
            ContentError::Decode {
                stage: "intent",
                source: undecodable,
            }
            .outcome(),
            AttemptOutcome::Refused,
        );
        for origin in [None, Some("https://elsewhere.invalid".to_owned())] {
            assert_eq!(
                ContentError::Redirected {
                    stage: "chunk",
                    origin,
                }
                .outcome(),
                AttemptOutcome::Refused,
                "a redirect is an answer about the server",
            );
        }
        assert_eq!(
            ContentError::Http {
                stage: "commit",
                status: 503,
            }
            .outcome(),
            AttemptOutcome::Retry,
        );
        assert_eq!(
            ContentError::Transport("stalled".to_owned()).outcome(),
            AttemptOutcome::Retry,
        );
        assert_eq!(
            ContentError::Store("store unavailable".to_owned()).outcome(),
            AttemptOutcome::Retry,
        );
        assert_eq!(
            ContentError::TicketRefused { file_id: file() }.outcome(),
            AttemptOutcome::Retry,
        );
    }
}
