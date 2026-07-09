//! Shared error types for the codec and I/O traits.
//!
//! Kept in one module so consumer crates can pattern-match cleanly against a
//! single `use` line. The variants are deliberately conservative. They carry
//! only the strings the underlying libraries produce, plus enough structure to
//! distinguish encode from decode and framing from payload.

use core::fmt;

/// Failure modes for `MessagePack` encoding, decoding, and framing.
#[derive(Debug)]
pub enum CodecError {
    /// `MessagePack` serializer refused the value.
    Encode(rmp_serde::encode::Error),
    /// `MessagePack` deserializer refused the bytes.
    Decode(rmp_serde::decode::Error),
    /// Framing header claims a payload larger than the caller allowed.
    FrameTooLarge {
        /// Length advertised by the header.
        header_len: u32,
        /// Ceiling the caller configured.
        limit: usize,
    },
    /// Input buffer ended before the framed payload finished.
    FrameTruncated {
        /// Expected length according to the header.
        expected: u32,
        /// Bytes actually available after the header.
        got: usize,
    },
    /// Input buffer is too short to hold even the four-byte length header.
    FrameHeaderTruncated {
        /// Bytes actually available.
        got: usize,
    },
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(e) => write!(f, "MessagePack encode failed: {e}"),
            Self::Decode(e) => write!(f, "MessagePack decode failed: {e}"),
            Self::FrameTooLarge { header_len, limit } => write!(
                f,
                "frame length header ({header_len}) exceeds configured limit ({limit})"
            ),
            Self::FrameTruncated { expected, got } => write!(
                f,
                "framed payload truncated: header advertised {expected} bytes, buffer has {got}"
            ),
            Self::FrameHeaderTruncated { got } => {
                write!(f, "frame header truncated: need 4 bytes, buffer has {got}")
            }
        }
    }
}

impl std::error::Error for CodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encode(e) => Some(e),
            Self::Decode(e) => Some(e),
            Self::FrameTooLarge { .. }
            | Self::FrameTruncated { .. }
            | Self::FrameHeaderTruncated { .. } => None,
        }
    }
}

impl From<rmp_serde::encode::Error> for CodecError {
    fn from(value: rmp_serde::encode::Error) -> Self {
        Self::Encode(value)
    }
}

impl From<rmp_serde::decode::Error> for CodecError {
    fn from(value: rmp_serde::decode::Error) -> Self {
        Self::Decode(value)
    }
}
