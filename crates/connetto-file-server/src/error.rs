//! Error types for the file server.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

/// Errors produced by file server handlers and internal operations.
#[derive(Debug, Error)]
pub enum ServerError {
    /// File absent, uncommitted, or access denied.  Answers 404 on the wire
    /// regardless of cause, per R38: callers cannot distinguish absence from
    /// denial through the response code.
    #[error("not found")]
    NotFound,

    /// Ticket invalid, expired, or wrong verb.
    #[error("ticket: {0}")]
    Ticket(#[from] crate::ticket::TicketError),

    /// Chunk body hash did not match the URL hash.
    #[error("chunk hash mismatch")]
    HashMismatch,

    /// Commit rejected: not all declared chunks were stored by this upload, or
    /// the reassembled bytes do not reconstruct to the declared file identity.
    /// Always 409; callers must not learn which condition was tripped.
    #[error("commit refused")]
    CommitRefused,

    /// PUT would push the upload past the ticket's byte ceiling.
    #[error("upload ceiling exceeded")]
    CeilingExceeded,

    /// A declared chunk hash is in `deleting` state in the registry.
    ///
    /// The client should retry the intent after the current sweep cycle finishes
    /// and the hash's registry row is removed.
    #[error("registry conflict: hash is being deleted")]
    RegistryConflict,

    /// A second intent for the same file id declares a different manifest.
    #[error("manifest conflict: re-declaration does not match stored manifest")]
    ManifestConflict,

    /// Intent declares more chunks than the ceiling permits.
    #[error("too many chunks declared")]
    TooManyChunks,

    /// Range request outside the file's bounds.
    #[error("range not satisfiable")]
    RangeNotSatisfiable,

    /// Diesel query error.
    #[error("database: {0}")]
    Db(#[from] diesel::result::Error),

    /// Connection pool error.
    #[error("pool: {0}")]
    Pool(String),

    /// Chunk store I/O error.
    #[error("store: {0}")]
    Store(#[from] crate::store::StoreError),

    /// Request body too large for the configured limit.
    #[error("body too large")]
    BodyTooLarge,

    /// Malformed path parameter (hex decode or wrong length).
    #[error("bad path parameter: {0}")]
    BadParam(String),
}

impl<E: 'static> From<bb8::RunError<E>> for ServerError
where
    E: std::error::Error,
{
    fn from(e: bb8::RunError<E>) -> Self {
        Self::Pool(e.to_string())
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::NotFound | Self::Ticket(_) => StatusCode::NOT_FOUND,
            Self::RangeNotSatisfiable => StatusCode::RANGE_NOT_SATISFIABLE,
            Self::CeilingExceeded | Self::BodyTooLarge | Self::TooManyChunks => {
                StatusCode::PAYLOAD_TOO_LARGE
            }
            Self::HashMismatch => StatusCode::UNPROCESSABLE_ENTITY,
            Self::CommitRefused | Self::ManifestConflict => StatusCode::CONFLICT,
            // 503: transient condition; the client should retry after a delay.
            Self::RegistryConflict => StatusCode::SERVICE_UNAVAILABLE,
            Self::BadParam(_) => StatusCode::BAD_REQUEST,
            Self::Db(_) | Self::Pool(_) | Self::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        status.into_response()
    }
}
