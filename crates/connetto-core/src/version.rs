//! Protocol version wire constant.
//!
//! Clients send [`PROTOCOL_VERSION`] inside [`crate::messages::Handshake`].
//! Servers hard-reject on mismatch with a [`crate::messages::FatalError`] carrying
//! [`crate::messages::FatalErrorReason::ProtocolVersionMismatch`]. No negotiation.
//! Decision recorded as Q2.3 in `docs/architecture/open-questions.md`.

/// Current wire protocol version.
///
/// Bump on any breaking change to `ControlMessage`, `BulkMessage`, framing, or
/// compression discipline. Compatible additive changes (new optional fields on
/// an existing struct) do not require a bump because MessagePack-encoded named
/// structs tolerate unknown/missing fields at the serde layer.
pub const PROTOCOL_VERSION: u32 = 1;
