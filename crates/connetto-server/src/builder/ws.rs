//! The adapter from axum's `WebSocket` to connetto's `Transport`, and the
//! one sync route it serves.

use std::sync::Arc;

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::routing::any;
use thiserror::Error;

use crate::builder::ServerManager;
use connetto_core::codec::{
    TAG_BULK, TAG_CONTROL, decode_bulk, decode_control, encode_bulk, encode_control,
};
use connetto_core::error::CodecError;
use connetto_core::messages::{BulkMessage, ControlMessage};
use connetto_core::traits::{IncomingFrame, Transport};

/// The path the sync route answers on.
pub const SYNC_PATH: &str = "/sync";

/// Why an axum-backed transport could not speak a frame.
#[derive(Debug, Error)]
pub enum AxumTransportError {
    /// The WebSocket itself failed.
    #[error("websocket error: {0}")]
    Ws(#[from] axum::Error),
    /// A frame did not carry the codec's bytes.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// A binary frame carried no tag byte.
    #[error("empty websocket frame")]
    EmptyFrame,
    /// A binary frame's tag is neither control nor bulk.
    #[error("unknown websocket frame tag {0}")]
    UnknownTag(u8),
}

/// A connetto transport over an axum `WebSocket`.
pub struct AxumWebSocketTransport {
    socket: WebSocket,
}

impl Transport for AxumWebSocketTransport {
    type Error = AxumTransportError;

    async fn send_control(
        &mut self,
        message: ControlMessage,
    ) -> Result<(), <Self as Transport>::Error> {
        let mut framed = Vec::with_capacity(1 + 64);
        framed.push(TAG_CONTROL);
        framed.extend_from_slice(&encode_control(&message)?);
        self.socket.send(Message::Binary(framed.into())).await?;
        Ok(())
    }

    async fn send_bulk(&mut self, message: BulkMessage) -> Result<(), <Self as Transport>::Error> {
        let mut framed = Vec::with_capacity(1 + 64);
        framed.push(TAG_BULK);
        framed.extend_from_slice(&encode_bulk(&message)?);
        self.socket.send(Message::Binary(framed.into())).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<IncomingFrame>, <Self as Transport>::Error> {
        loop {
            match self.socket.recv().await {
                Some(Ok(Message::Binary(buf))) => {
                    let (tag, payload) = buf
                        .split_first()
                        .map(|(tag, payload)| (*tag, payload))
                        .ok_or(AxumTransportError::EmptyFrame)?;
                    return Ok(Some(match tag {
                        TAG_CONTROL => IncomingFrame::Control(decode_control(payload)?),
                        TAG_BULK => IncomingFrame::Bulk(decode_bulk(payload)?),
                        other => return Err(AxumTransportError::UnknownTag(other)),
                    }));
                }
                None | Some(Ok(Message::Close(_))) => return Ok(None),
                Some(Ok(_)) => {}
                Some(Err(err)) => return Err(AxumTransportError::Ws(err)),
            }
        }
    }

    async fn close(&mut self) -> Result<(), <Self as Transport>::Error> {
        self.socket.send(Message::Close(None)).await?;
        Ok(())
    }
}

/// The one sync route: a WebSocket upgrade at [`SYNC_PATH`] that serves one
/// session over the upgraded socket.
pub(crate) fn sync_routes(manager: Arc<ServerManager>) -> Router {
    Router::new().route(
        SYNC_PATH,
        any(move |ws: WebSocketUpgrade| {
            let manager = Arc::clone(&manager);
            async move {
                ws.on_upgrade(move |socket| async move {
                    let transport = AxumWebSocketTransport { socket };
                    if let Err(err) = manager.serve(transport).await {
                        tracing::warn!(error = %err, "session ended with an error");
                    }
                })
            }
        }),
    )
}
