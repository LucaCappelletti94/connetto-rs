//! The one error type the content surface returns.

use connetto_file_core::FileId;
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

impl ContentError {
    /// Whether the outbox walk should keep the entry and try again later.
    ///
    /// The bias is deliberate: an unsent write cannot be refetched, so every
    /// ambiguous failure keeps the entry. A refused ticket is retryable for
    /// exactly that reason, since chapter 18 makes an invisible file and an
    /// over-budget request byte-identical on the wire, and the over-budget
    /// half clears as the rolling window moves.
    ///
    /// The permanent cases are the ones no later attempt changes: bytes past
    /// the deployment's ceiling, bytes that disagree with their own hashes, a
    /// request the server calls malformed, and an answer this client cannot
    /// parse.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http { status, .. } => !matches!(status, 400 | 413 | 422),
            Self::Decode { .. }
            | Self::MalformedGrant(_)
            | Self::NoManifest { .. }
            | Self::IdentityMismatch { .. }
            | Self::Archive(_)
            | Self::PinColumnMissing { .. } => false,
            Self::Replica(_)
            | Self::Client(_)
            | Self::Store(_)
            | Self::Transport(_)
            | Self::TicketRefused { .. }
            | Self::TicketSignerError { .. }
            | Self::TicketRateLimited { .. }
            | Self::TicketAbandoned
            | Self::TicketLagged => true,
        }
    }
}
