//! The frame loop a live link runs on, until it closes and the close is
//! emitted.

use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use connetto_core::device_cert::{DeviceCertificate, KeyId};
use rustls::pki_types::CertificateDer;
use serde_bytes::ByteBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::error::{CloseReason, Refusal};
use crate::event::PeerEvent;
use crate::frame::{FrameError, FrameReader, PeerFrame, write_frame};
use crate::node::{HELLO_TIMEOUT, LinkCommand, NodeState, WRITE_BOUND};
use crate::verify::TOLERANCE;

/// How long a link whose write failed reads on for a close the peer queued.
/// The frames sit in the receive buffer already, so the bound only matters
/// when the write failed on a stall instead of a reset.
const DRAIN_BOUND: Duration = Duration::from_secs(1);

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
    let clock = state.verifier.clock();
    // When the peer's certificate passes its end plus the tolerance, so the
    // link closes with `PeerExpired`.
    let mut deadline = {
        let links = state.links.lock();
        match links.get(&key) {
            Some(crate::node::SlotState::Live(slot)) if slot.seq == seq => {
                DeviceCertificate::parse(&slot.leaf)
                    .expect("the peer's leaf was verified at the handshake")
                    .not_after()
                    + TOLERANCE
            }
            _ => return,
        }
    };
    loop {
        let deadline_sleep =
            tokio::time::sleep(deadline.duration_since(clock.now()).unwrap_or_default());
        let silence = tokio::time::sleep_until(last_seen + silence_limit);
        let stop = tokio::select! {
            () = deadline_sleep => {
                // A back-jumped wall clock re-arms the sleep, and a real expiry
                // closes the link.
                if clock.now() >= deadline {
                    Some(Stop::Close(CloseReason::PeerExpired))
                } else {
                    None
                }
            }
            () = silence => Some(Stop::Close(CloseReason::PeerLost)),
            _ = ping.tick() => match bounded_write(&mut io, &PeerFrame::Ping).await {
                Ok(()) => None,
                Err(_) => Some(Stop::WriteFailed),
            },
            frame = reader.next(&mut io) => {
                on_frame(&state, &mut io, key, seq, frame, &mut last_seen, &mut deadline).await
            }
            command = commands.recv() => on_command(&state, &mut io, key, seq, command).await,
        };
        if let Some(stop) = stop {
            let reason = match stop {
                Stop::Close(reason) => reason,
                Stop::WriteFailed => queued_close(&mut reader, &mut io).await,
            };
            finish(&state, key, seq, reason);
            break;
        }
    }
    hang_up(&mut io).await;
}

/// Hang up without a reset. A socket closed with bytes unread resets the
/// connection, and the reset discards what the kernel has not sent yet, a
/// `Close` written just before among it. So the write side shuts down, and
/// the peer's bytes are read and dropped until the peer hangs up too or
/// `WRITE_BOUND` passes.
pub(crate) async fn hang_up<S: AsyncRead + AsyncWrite + Unpin>(io: &mut S) {
    let drain = async {
        if io.shutdown().await.is_err() {
            return;
        }
        let mut sink = [0; 1024];
        while matches!(io.read(&mut sink).await, Ok(1..)) {}
    };
    let _ = tokio::time::timeout(WRITE_BOUND, drain).await;
}

/// Why the frame loop stops.
enum Stop {
    /// The link closes with the reason.
    Close(CloseReason),
    /// A write to the peer failed, which a reset after the peer's own close
    /// also causes, so the frames the peer already sent decide the reason.
    WriteFailed,
}

/// The close a peer queued before its end went away. A `Duplicate` close
/// keeps its reason, and any other close, the stream's end, a broken frame
/// or `DRAIN_BOUND` without one reads as `Closed`.
async fn queued_close<S: AsyncRead + Unpin>(reader: &mut FrameReader, io: &mut S) -> CloseReason {
    let read = async {
        loop {
            match Box::pin(reader.next(io)).await {
                Ok(Some(PeerFrame::Close {
                    reason: CloseReason::Duplicate,
                })) => return CloseReason::Duplicate,
                Ok(Some(PeerFrame::Close { .. }) | None) | Err(_) => return CloseReason::Closed,
                Ok(Some(_)) => {}
            }
        }
    };
    tokio::time::timeout(DRAIN_BOUND, read)
        .await
        .unwrap_or(CloseReason::Closed)
}

/// What a received frame does to the link, `Some` when it stops it.
async fn on_frame<S: AsyncRead + AsyncWrite + Unpin>(
    state: &Arc<NodeState>,
    io: &mut S,
    key: KeyId,
    seq: u64,
    frame: Result<Option<PeerFrame>, FrameError>,
    last_seen: &mut tokio::time::Instant,
    deadline: &mut SystemTime,
) -> Option<Stop> {
    match frame {
        Err(err) => Some(Stop::Close(match err {
            FrameError::TooLong | FrameError::Malformed => CloseReason::Protocol,
            FrameError::Io(_) => CloseReason::Closed,
        })),
        Ok(None) => Some(Stop::Close(CloseReason::Closed)),
        Ok(Some(PeerFrame::Ping)) => {
            *last_seen = tokio::time::Instant::now();
            match bounded_write(io, &PeerFrame::Pong).await {
                Ok(()) => None,
                Err(_) => Some(Stop::WriteFailed),
            }
        }
        Ok(Some(PeerFrame::Pong)) => {
            *last_seen = tokio::time::Instant::now();
            None
        }
        Ok(Some(PeerFrame::List { list, signer })) => {
            *last_seen = tokio::time::Instant::now();
            state
                .events
                .send(PeerEvent::ListReceived {
                    list: list.to_vec(),
                    signer: signer.to_vec(),
                })
                .ok();
            None
        }
        // The renewed chain verifies as at the handshake and must
        // name the same key, so the link's deadline moves.
        Ok(Some(PeerFrame::Certificate { leaf, issuer })) => {
            *last_seen = tokio::time::Instant::now();
            renew(state, key, seq, &leaf[..], &issuer[..], deadline)
                .err()
                .map(Stop::Close)
        }
        // Only a duplicate keeps the sender's reason, since every other
        // reason names the sender's view of this end.
        Ok(Some(PeerFrame::Close { reason })) => {
            Some(Stop::Close(if reason == CloseReason::Duplicate {
                CloseReason::Duplicate
            } else {
                CloseReason::Closed
            }))
        }
        // A hello or an offer past the exchange is a protocol break.
        Ok(Some(PeerFrame::Hello { .. } | PeerFrame::Offer { .. })) => {
            Some(Stop::Close(CloseReason::Protocol))
        }
    }
}

/// What a command from the node does to the link, `Some` when it stops it.
async fn on_command<S: AsyncRead + AsyncWrite + Unpin>(
    state: &Arc<NodeState>,
    io: &mut S,
    key: KeyId,
    seq: u64,
    command: Option<LinkCommand>,
) -> Option<Stop> {
    match command {
        Some(LinkCommand::Close(reason)) => {
            // The sender names the close, so both ends keep it.
            let _ = bounded_write(io, &PeerFrame::Close { reason }).await;
            Some(Stop::Close(reason))
        }
        Some(LinkCommand::List {
            list,
            signer,
            issuer,
            number,
        }) => {
            let frame = PeerFrame::List {
                list: ByteBuf::from(list),
                signer: ByteBuf::from(signer),
            };
            match bounded_write(io, &frame).await {
                Ok(()) => {
                    // The peer has the list now, so a later forward
                    // does not resend it.
                    let mut links = state.links.lock();
                    if let Some(crate::node::SlotState::Live(slot)) = links.get_mut(&key)
                        && slot.seq == seq
                    {
                        slot.numbers.insert(*issuer.as_bytes(), number);
                    }
                    None
                }
                Err(_) => Some(Stop::WriteFailed),
            }
        }
        // Hand the renewed chain to the link still holding the old one.
        Some(LinkCommand::Certificate { leaf, issuer }) => {
            let frame = PeerFrame::Certificate {
                leaf: ByteBuf::from(leaf),
                issuer: ByteBuf::from(issuer),
            };
            match bounded_write(io, &frame).await {
                Ok(()) => None,
                Err(_) => Some(Stop::WriteFailed),
            }
        }
        None => Some(Stop::Close(CloseReason::Closed)),
    }
}

/// Verify a peer's renewed chain as at the handshake. When it names the same
/// key the link proved, replace the link's chain and move its deadline.
fn renew(
    state: &Arc<NodeState>,
    key: KeyId,
    seq: u64,
    leaf: &[u8],
    issuer: &[u8],
    deadline: &mut SystemTime,
) -> Result<(), CloseReason> {
    // The device profile always holds both the serverAuth and the clientAuth
    // usage, so the usage does not change the outcome, and the chain verifies
    // as on the dial side.
    let leaf_der = CertificateDer::from(leaf);
    let issuer_der = CertificateDer::from(issuer);
    let certificate = state
        .verifier
        .verify_chain(&leaf_der, &[issuer_der], webpki::KeyUsage::server_auth())
        .map_err(|refusal| match refusal {
            Refusal::Revoked => CloseReason::PeerRevoked,
            Refusal::Expired | Refusal::NotYetValid => CloseReason::PeerExpired,
            _ => CloseReason::Protocol,
        })?;
    // The renewed chain must name the key the handshake proved.
    if certificate.identity().key() != key {
        return Err(CloseReason::Protocol);
    }
    *deadline = certificate.not_after() + TOLERANCE;
    let mut links = state.links.lock();
    if let Some(crate::node::SlotState::Live(slot)) = links.get_mut(&key)
        && slot.seq == seq
    {
        slot.leaf = leaf.to_vec();
        slot.issuer = issuer.to_vec();
        // The renewed chain changes the leaf discovery fingerprints.
        #[cfg(feature = "discovery")]
        state
            .peer_fingerprints
            .lock()
            .insert(key, crate::fingerprint::Fingerprint::of(leaf));
    }
    Ok(())
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
