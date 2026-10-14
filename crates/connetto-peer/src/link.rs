//! The frame loop a live link runs on, until it closes and the close is
//! emitted.

use std::io;
use std::sync::Arc;

use connetto_core::device_cert::KeyId;
use serde_bytes::ByteBuf;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::error::CloseReason;
use crate::event::PeerEvent;
use crate::frame::{FrameError, FrameReader, PeerFrame, write_frame};
use crate::node::{HELLO_TIMEOUT, LinkCommand, NodeState, WRITE_BOUND};

/// Drive the link's frames until it closes, emitting the close once.
pub(crate) async fn run<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    state: Arc<NodeState>,
    mut io: S,
    mut commands: mpsc::UnboundedReceiver<LinkCommand>,
    key: KeyId,
    seq: u64,
) {
    let ping_every = state.ping_every;
    let silence_limit = state.silence_limit;
    let mut ping = tokio::time::interval(ping_every);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_seen = tokio::time::Instant::now();
    let mut reader = FrameReader::default();
    loop {
        let silence = tokio::time::sleep_until(last_seen + silence_limit);
        let close = tokio::select! {
            () = silence => Some(CloseReason::PeerLost),
            _ = ping.tick() => match bounded_write(&mut io, &PeerFrame::Ping).await {
                Ok(()) => None,
                Err(_) => Some(CloseReason::Closed),
            },
            frame = reader.next(&mut io) => match frame {
                Err(err) => Some(match err {
                    FrameError::TooLong | FrameError::Malformed => CloseReason::Protocol,
                    FrameError::Io(_) => CloseReason::Closed,
                }),
                Ok(None) => Some(CloseReason::Closed),
                Ok(Some(PeerFrame::Ping)) => {
                    last_seen = tokio::time::Instant::now();
                    match bounded_write(&mut io, &PeerFrame::Pong).await {
                        Ok(()) => None,
                        Err(_) => Some(CloseReason::Closed),
                    }
                }
                Ok(Some(PeerFrame::Pong)) => {
                    last_seen = tokio::time::Instant::now();
                    None
                }
                Ok(Some(PeerFrame::List { list, signer })) => {
                    last_seen = tokio::time::Instant::now();
                    state
                        .events
                        .send(PeerEvent::ListReceived {
                            list: list.to_vec(),
                            signer: signer.to_vec(),
                        })
                        .ok();
                    None
                }
                // Only a duplicate keeps the sender's reason, since every other
                // reason names the sender's view of this end.
                Ok(Some(PeerFrame::Close { reason })) => Some(if reason == CloseReason::Duplicate {
                    CloseReason::Duplicate
                } else {
                    CloseReason::Closed
                }),
                Ok(Some(PeerFrame::Hello { .. })) => Some(CloseReason::Protocol),
            },
            command = commands.recv() => match command {
                Some(LinkCommand::Close(reason)) => {
                    // The sender names the close, so both ends keep it.
                    let _ = bounded_write(&mut io, &PeerFrame::Close { reason }).await;
                    Some(reason)
                }
                Some(LinkCommand::List { list, signer, issuer, number }) => {
                    let frame = PeerFrame::List {
                        list: ByteBuf::from(list),
                        signer: ByteBuf::from(signer),
                    };
                    match bounded_write(&mut io, &frame).await {
                        Ok(()) => {
                            // The peer has the list now, so a later forward
                            // does not resend it.
                            let mut links = state.links.lock();
                            if let Some(crate::node::SlotState::Live(slot)) =
                                links.get_mut(&key)
                                && slot.seq == seq
                            {
                                slot.numbers.insert(*issuer.as_bytes(), number);
                            }
                            None
                        }
                        Err(_) => Some(CloseReason::Closed),
                    }
                }
                None => Some(CloseReason::Closed),
            },
        };
        if let Some(reason) = close {
            finish(&state, key, seq, reason);
            break;
        }
    }
    drop(io);
}

/// A frame write, given its bound so a stalled peer cannot wedge the loop.
async fn bounded_write<W: AsyncWrite + Unpin>(
    io: &mut W,
    frame: &PeerFrame,
) -> Result<(), FrameError> {
    match tokio::time::timeout(WRITE_BOUND, write_frame(io, frame)).await {
        Ok(result) => result,
        Err(_) => Err(FrameError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "the write bound ran out",
        ))),
    }
}

/// Remove the link's slot and emit the close. A `Duplicate` close leaves the
/// peer reported as linked and waits, under the same lock as the kept link's
/// registration, up to the hello timeout for the keeper to register.
fn finish(state: &Arc<NodeState>, key: KeyId, seq: u64, reason: CloseReason) {
    use crate::node::SlotState;
    let peer = {
        let mut links = state.links.lock();
        match links.get(&key) {
            Some(SlotState::Live(slot)) if slot.seq == seq => {
                let peer = slot.peer.clone();
                links.remove(&key);
                if reason == CloseReason::Duplicate {
                    links.insert(key, SlotState::AwaitingKeeper(peer.clone()));
                }
                Some(peer)
            }
            _ => None,
        }
    };
    let Some(peer) = peer else {
        // Not the current slot, a replaced or gone link, so nothing to emit.
        return;
    };
    if reason == CloseReason::Duplicate {
        let state = Arc::clone(state);
        tokio::spawn(async move {
            tokio::time::sleep(HELLO_TIMEOUT).await;
            let mut links = state.links.lock();
            // A live slot is the keeper, and no slot means a stop or another
            // close resolved the wait.
            if let Some(SlotState::AwaitingKeeper(peer)) = links.get(&key) {
                let peer = peer.clone();
                links.remove(&key);
                drop(links);
                state
                    .events
                    .send(PeerEvent::Unlinked {
                        peer,
                        reason: CloseReason::Duplicate,
                    })
                    .ok();
            }
        });
    } else {
        state.events.send(PeerEvent::Unlinked { peer, reason }).ok();
    }
}
