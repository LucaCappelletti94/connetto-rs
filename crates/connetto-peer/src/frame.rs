//! The link's frame protocol, a four-byte big-endian length ahead of a
//! messagepack `PeerFrame`.

use std::io;

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::CloseReason;

/// The frame length ceiling, four megabytes.
pub(crate) const MAX_FRAME_LEN: u32 = 4 * 1024 * 1024;
/// The frame version this crate speaks.
pub(crate) const PROTOCOL_VERSION: u16 = 1;

/// A frame on the peer link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerFrame {
    /// The first frame from each side, naming the version, the dial the side
    /// made, and the revocation list numbers the side keeps.
    Hello {
        /// The frame version the side speaks.
        version: u16,
        /// The dial counter of the side that opened the connection, 0 from
        /// the listener.
        dial: u64,
        /// The kept lists, as `(issuer key id, number)` pairs.
        numbers: Vec<(ByteBuf, u64)>,
    },
    /// A revocation list the peer lacks.
    List {
        /// The list, DER.
        list: ByteBuf,
        /// The signer's certificate, DER.
        signer: ByteBuf,
    },
    /// A deliberate close the sender reports, so both ends name the same
    /// reason.
    Close {
        /// The reason the sender closes with.
        reason: CloseReason,
    },
    /// A liveness probe.
    Ping,
    /// The answer to a liveness probe.
    Pong,
}

/// A frame decode or I/O failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FrameError {
    /// The link's I/O failed or ended.
    #[error("the link's I/O failed")]
    Io(#[source] io::Error),
    /// The peer's frame exceeds the ceiling.
    #[error("the frame exceeds the ceiling")]
    TooLong,
    /// The frame is not a `PeerFrame`.
    #[error("the frame does not decode")]
    Malformed,
}

/// Read one frame, or `None` when the link ends cleanly.
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    rd: &mut R,
) -> Result<Option<PeerFrame>, FrameError> {
    let mut len = [0u8; 4];
    match rd.read_exact(&mut len).await {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(FrameError::Io(err)),
    }
    let len = u32::from_be_bytes(len);
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLong);
    }
    let mut body = vec![0u8; usize::try_from(len).expect("a u32 length fits a usize")];
    rd.read_exact(&mut body).await.map_err(FrameError::Io)?;
    let frame = rmp_serde::from_slice(&body).map_err(|_| FrameError::Malformed)?;
    Ok(Some(frame))
}

/// Frames read off a stream across calls, keeping a partly arrived frame
/// when a `select!` drops the read, so a frame loop never loses its place.
#[derive(Debug, Default)]
pub(crate) struct FrameReader {
    /// The bytes read and not yet decoded.
    pending: Vec<u8>,
}

impl FrameReader {
    /// The next frame, or `None` when the link ends cleanly between frames.
    /// Dropping the future before it completes loses no bytes.
    pub(crate) async fn next<R: AsyncRead + Unpin>(
        &mut self,
        rd: &mut R,
    ) -> Result<Option<PeerFrame>, FrameError> {
        let mut chunk = [0u8; 16 * 1024];
        loop {
            if let Some(frame) = self.decode()? {
                return Ok(Some(frame));
            }
            let read = rd.read(&mut chunk).await.map_err(FrameError::Io)?;
            if read == 0 {
                return if self.pending.is_empty() {
                    Ok(None)
                } else {
                    Err(FrameError::Io(io::ErrorKind::UnexpectedEof.into()))
                };
            }
            self.pending.extend_from_slice(&chunk[..read]);
        }
    }

    /// Decode one whole frame from the pending bytes, if they hold one.
    fn decode(&mut self) -> Result<Option<PeerFrame>, FrameError> {
        let Some(len) = self.pending.first_chunk::<4>() else {
            return Ok(None);
        };
        let len = u32::from_be_bytes(*len);
        if len > MAX_FRAME_LEN {
            return Err(FrameError::TooLong);
        }
        let end = 4 + usize::try_from(len).expect("a u32 length fits a usize");
        if self.pending.len() < end {
            return Ok(None);
        }
        let frame = rmp_serde::from_slice(&self.pending[4..end]).map_err(|_| FrameError::Malformed);
        self.pending.drain(..end);
        frame.map(Some)
    }
}

/// Write one frame.
pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
    wr: &mut W,
    frame: &PeerFrame,
) -> Result<(), FrameError> {
    let body = rmp_serde::to_vec_named(frame).map_err(|_| FrameError::Malformed)?;
    if body.len() > usize::try_from(MAX_FRAME_LEN).expect("a 32-bit constant") {
        return Err(FrameError::TooLong);
    }
    let len = u32::try_from(body.len()).expect("checked against the ceiling");
    wr.write_all(&len.to_be_bytes())
        .await
        .map_err(FrameError::Io)?;
    wr.write_all(&body).await.map_err(FrameError::Io)?;
    wr.flush().await.map_err(FrameError::Io)?;
    Ok(())
}
