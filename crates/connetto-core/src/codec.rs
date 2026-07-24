//! `MessagePack` encode/decode and length-prefixed framing.
//!
//! The wire protocol layers responsibilities as follows.
//!
//! * `MessagePack` (`rmp-serde`) serialises [`ControlMessage`] and
//!   [`BulkMessage`] into byte payloads. Q2.1.
//! * A length-prefixed frame (`u32` big-endian header plus payload) wraps each
//!   payload for use over transports that lack their own message boundary
//!   (raw TCP, HTTP long-poll). §02 "Message Framing".
//! * `WebSocket` transports skip the framing header because the `WebSocket`
//!   protocol already delimits messages. Send the raw `MessagePack` payload
//!   directly.
//!
//! Compression discipline (Q2.5): control payloads are never compressed. Bulk
//! payloads carry `Zstd` bytes in their `*_zstd` fields. The codec never
//! touches that content, it just moves it.

use crate::{
    error::CodecError,
    messages::{BulkMessage, ControlMessage},
};

/// Sensible ceiling for framed reads: 64 MiB. Individual servers can lower this
/// with the `_with_limit` variants when they know their traffic profile.
pub const DEFAULT_MAX_FRAME_LEN: usize = 64 * 1024 * 1024;

/// Header size for length-prefixed framing.
pub const FRAME_HEADER_LEN: usize = 4;

/// Wire tag prefixed to a control-plane frame on message-delimited
/// transports (`WebSocket` binary frames, browser or native alike).
pub const TAG_CONTROL: u8 = 0;
/// Wire tag prefixed to a bulk-plane frame on message-delimited transports.
pub const TAG_BULK: u8 = 1;

// ---------- MessagePack payload encoders ----------

/// Encode a control-plane message as a raw `MessagePack` payload (no framing).
///
/// Use this over transports that already delimit messages (`WebSocket` binary
/// frames).
pub fn encode_control(message: &ControlMessage) -> Result<Vec<u8>, CodecError> {
    Ok(rmp_serde::to_vec_named(message)?)
}

/// Decode a raw `MessagePack` payload as a control-plane message (no framing).
pub fn decode_control(payload: &[u8]) -> Result<ControlMessage, CodecError> {
    Ok(rmp_serde::from_slice(payload)?)
}

/// Encode a bulk-plane message as a raw `MessagePack` payload (no framing).
pub fn encode_bulk(message: &BulkMessage) -> Result<Vec<u8>, CodecError> {
    Ok(rmp_serde::to_vec_named(message)?)
}

/// Decode a raw `MessagePack` payload as a bulk-plane message (no framing).
pub fn decode_bulk(payload: &[u8]) -> Result<BulkMessage, CodecError> {
    Ok(rmp_serde::from_slice(payload)?)
}

// ---------- Length-prefixed framing helpers ----------

/// Encode a control message with a `u32` big-endian length header.
///
/// The output is `[4 bytes: BE length][payload]`. Bytes returned to the caller
/// are ready to write directly to a byte-stream transport.
pub fn encode_control_framed(message: &ControlMessage) -> Result<Vec<u8>, CodecError> {
    let payload = encode_control(message)?;
    Ok(prepend_length(&payload))
}

/// Encode a bulk message with a `u32` big-endian length header.
pub fn encode_bulk_framed(message: &BulkMessage) -> Result<Vec<u8>, CodecError> {
    let payload = encode_bulk(message)?;
    Ok(prepend_length(&payload))
}

/// Decode a control message from a length-prefixed buffer.
///
/// On success returns the decoded message and the number of bytes consumed
/// (`4 + payload_len`). The caller can advance its buffer by that amount.
/// Fails cleanly on truncated headers, truncated payloads, or payloads larger
/// than [`DEFAULT_MAX_FRAME_LEN`].
pub fn decode_control_framed(buffer: &[u8]) -> Result<(ControlMessage, usize), CodecError> {
    decode_control_framed_with_limit(buffer, DEFAULT_MAX_FRAME_LEN)
}

/// Decode a control message from a length-prefixed buffer with an explicit
/// upper bound on payload length.
pub fn decode_control_framed_with_limit(
    buffer: &[u8],
    limit: usize,
) -> Result<(ControlMessage, usize), CodecError> {
    let (payload, consumed) = split_framed(buffer, limit)?;
    let message = decode_control(payload)?;
    Ok((message, consumed))
}

/// Decode a bulk message from a length-prefixed buffer.
pub fn decode_bulk_framed(buffer: &[u8]) -> Result<(BulkMessage, usize), CodecError> {
    decode_bulk_framed_with_limit(buffer, DEFAULT_MAX_FRAME_LEN)
}

/// Decode a bulk message from a length-prefixed buffer with an explicit
/// upper bound on payload length.
pub fn decode_bulk_framed_with_limit(
    buffer: &[u8],
    limit: usize,
) -> Result<(BulkMessage, usize), CodecError> {
    let (payload, consumed) = split_framed(buffer, limit)?;
    let message = decode_bulk(payload)?;
    Ok((message, consumed))
}

// ---------- Internals ----------

fn prepend_length(payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("payload length exceeds u32::MAX");
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn split_framed(buffer: &[u8], limit: usize) -> Result<(&[u8], usize), CodecError> {
    if buffer.len() < FRAME_HEADER_LEN {
        return Err(CodecError::FrameHeaderTruncated { got: buffer.len() });
    }
    let mut header = [0_u8; FRAME_HEADER_LEN];
    header.copy_from_slice(&buffer[..FRAME_HEADER_LEN]);
    let header_len = u32::from_be_bytes(header);
    let payload_len = header_len as usize;
    if payload_len > limit {
        return Err(CodecError::FrameTooLarge { header_len, limit });
    }
    let end = FRAME_HEADER_LEN + payload_len;
    if buffer.len() < end {
        return Err(CodecError::FrameTruncated {
            expected: header_len,
            got: buffer.len() - FRAME_HEADER_LEN,
        });
    }
    Ok((&buffer[FRAME_HEADER_LEN..end], end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cursor::Cursor,
        messages::{Handshake, HandshakeAck},
        schema::SchemaVersion,
        version::PROTOCOL_VERSION,
    };

    fn sample_control() -> ControlMessage {
        ControlMessage::HandshakeAck(HandshakeAck {
            session_id: "sess-abc".into(),
            session_token: "tok-abc".into(),
            current_cursor: Cursor::new(vec![9, 8, 7]),
            schema_version: SchemaVersion::new("v1", vec![0xab, 0xcd]),
            initial_credits: 64,
            last_applied_seq: Some(7),
        })
    }

    #[test]
    fn payload_round_trip_matches() {
        let msg = sample_control();
        let bytes = encode_control(&msg).unwrap();
        let back = decode_control(&bytes).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn framed_round_trip_matches() {
        let msg = ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "client-a", "tok").with_session_token("prev"),
        );
        let framed = encode_control_framed(&msg).unwrap();
        assert!(framed.len() > FRAME_HEADER_LEN);
        let (back, consumed) = decode_control_framed(&framed).unwrap();
        assert_eq!(consumed, framed.len());
        assert_eq!(msg, back);
    }

    #[test]
    fn framed_decoder_advances_past_a_single_message() {
        let msg = sample_control();
        let framed = encode_control_framed(&msg).unwrap();
        // Append an unrelated tail. The decoder must stop exactly at the frame boundary.
        let mut buffer = framed.clone();
        buffer.extend_from_slice(&[0xff, 0xee, 0xdd]);
        let (_, consumed) = decode_control_framed(&buffer).unwrap();
        assert_eq!(consumed, framed.len());
    }

    #[test]
    fn framed_decoder_reports_truncated_header() {
        let err = decode_control_framed(&[1, 2, 3]).unwrap_err();
        assert!(matches!(err, CodecError::FrameHeaderTruncated { got: 3 }));
    }

    #[test]
    fn framed_decoder_reports_truncated_payload() {
        let msg = sample_control();
        let framed = encode_control_framed(&msg).unwrap();
        // Drop the last byte of the payload so the header outruns the buffer.
        let short = &framed[..framed.len() - 1];
        let err = decode_control_framed(short).unwrap_err();
        assert!(matches!(err, CodecError::FrameTruncated { .. }));
    }

    #[test]
    fn framed_decoder_enforces_limit() {
        let msg = sample_control();
        let framed = encode_control_framed(&msg).unwrap();
        let err = decode_control_framed_with_limit(&framed, 1).unwrap_err();
        assert!(matches!(err, CodecError::FrameTooLarge { limit: 1, .. }));
    }
}
