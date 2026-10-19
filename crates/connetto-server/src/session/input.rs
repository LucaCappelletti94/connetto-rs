//! Byte-bounded peer input held during catch-up.

use std::collections::VecDeque;

use connetto_core::traits::{IncomingFrame, Transport};

use super::SessionError;

#[derive(Default)]
pub(super) struct HeldInput {
    queue: VecDeque<(IncomingFrame, usize)>,
    held: usize,
}

impl HeldInput {
    pub(super) fn pop(&mut self) -> Option<IncomingFrame> {
        let (frame, charge) = self.queue.pop_front()?;
        self.held -= charge;
        Some(frame)
    }

    pub(super) async fn recv<T: Transport>(
        &mut self,
        transport: &mut T,
    ) -> Result<Option<IncomingFrame>, T::Error> {
        if let Some(frame) = self.pop() {
            return Ok(Some(frame));
        }
        transport.recv().await
    }

    pub(super) fn push(&mut self, frame: IncomingFrame, limit: usize) -> Result<(), SessionError> {
        let remaining = limit
            .checked_sub(self.held)
            .and_then(|bytes| bytes.checked_sub(1))
            .ok_or_else(|| overflow(limit))?;
        let mut counter = CountedWriter {
            remaining,
            written: 0,
            exceeded: false,
        };
        let measured = match &frame {
            IncomingFrame::Control(message) => {
                rmp_serde::encode::write_named(&mut counter, message)
            }
            IncomingFrame::Bulk(message) => rmp_serde::encode::write_named(&mut counter, message),
        };
        if let Err(error) = measured {
            return Err(if counter.exceeded {
                overflow(limit)
            } else {
                SessionError::Protocol(format!("cannot measure held input ({error})"))
            });
        }
        let charge = counter.written + 1;
        self.held += charge;
        self.queue.push_back((frame, charge));
        Ok(())
    }
}

fn overflow(limit: usize) -> SessionError {
    SessionError::Protocol(format!(
        "held input exceeds the {limit}-byte catch-up input budget"
    ))
}

struct CountedWriter {
    remaining: usize,
    written: usize,
    exceeded: bool,
}

impl std::io::Write for CountedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(std::io::ErrorKind::QuotaExceeded.into());
        }
        self.remaining -= bytes.len();
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{HeldInput, SessionError};
    use connetto_core::codec::{encode_bulk, encode_control};
    use connetto_core::messages::{BulkMessage, ControlMessage, LivePatch, Ping};
    use connetto_core::traits::{IncomingFrame, Transport};
    use connetto_core::{Cursor, loopback};

    fn wire_size(frame: &IncomingFrame) -> usize {
        match frame {
            IncomingFrame::Control(message) => encode_control(message).unwrap().len() + 1,
            IncomingFrame::Bulk(message) => encode_bulk(message).unwrap().len() + 1,
        }
    }

    fn control(nonce: u64) -> IncomingFrame {
        IncomingFrame::Control(ControlMessage::Ping(Ping { nonce }))
    }

    fn bulk(sub_id: &str, bytes: usize) -> IncomingFrame {
        let patch = LivePatch::new(sub_id, Cursor::new(vec![0; 12]), vec![0; bytes]);
        IncomingFrame::Bulk(BulkMessage::LivePatch(patch))
    }

    #[test]
    fn a_frame_of_exactly_the_budget_is_held_and_the_next_is_refused() {
        let frame = control(1);
        let budget = wire_size(&frame);
        let mut held = HeldInput::default();
        held.push(frame, budget).expect("the exact budget fits");
        assert!(matches!(
            held.push(control(2), budget),
            Err(SessionError::Protocol(_))
        ));
        assert_eq!(held.pop(), Some(control(1)));
        assert!(held.pop().is_none());
    }

    #[test]
    fn a_frame_one_byte_over_the_budget_is_refused() {
        let frame = control(1);
        let mut held = HeldInput::default();
        let budget = wire_size(&frame) - 1;
        assert!(matches!(
            held.push(frame, budget),
            Err(SessionError::Protocol(_))
        ));
        assert!(held.pop().is_none());
    }

    #[test]
    fn the_cap_adds_up_across_the_queue() {
        let first = control(1);
        let second = bulk("sub-a", 64);
        let budget = wire_size(&first) + wire_size(&second);
        let mut held = HeldInput::default();
        held.push(first, budget).expect("first frame fits");
        held.push(second, budget).expect("both frames fit");
        assert!(matches!(
            held.push(control(2), budget),
            Err(SessionError::Protocol(_))
        ));
        assert_eq!(held.pop(), Some(control(1)));
        assert_eq!(held.pop(), Some(bulk("sub-a", 64)));
        assert!(held.pop().is_none());
    }

    #[test]
    fn a_consumed_frame_gives_its_charge_back() {
        let budget = wire_size(&control(1)) + wire_size(&control(2));
        let mut held = HeldInput::default();
        held.push(control(1), budget).expect("first frame fits");
        held.push(control(2), budget).expect("both frames fit");
        assert_eq!(held.pop(), Some(control(1)));
        held.push(control(3), budget)
            .expect("released charge is reusable");
        assert_eq!(held.pop(), Some(control(2)));
        assert_eq!(held.pop(), Some(control(3)));
        assert!(held.pop().is_none());
    }

    #[test]
    fn a_zero_budget_refuses_every_frame() {
        let mut held = HeldInput::default();
        assert!(matches!(
            held.push(control(1), 0),
            Err(SessionError::Protocol(_))
        ));
        assert!(held.pop().is_none());
    }

    #[tokio::test]
    async fn recv_serves_held_frames_in_order_before_fresh_input() {
        let (mut peer, mut server) = loopback();
        let budget = wire_size(&control(1)) + wire_size(&bulk("sub-a", 512));
        let mut held = HeldInput::default();
        held.push(control(1), budget).expect("control fits");
        held.push(bulk("sub-a", 512), budget).expect("bulk fits");
        peer.send_bulk(BulkMessage::LivePatch(LivePatch::new(
            "sub-b",
            Cursor::new(vec![0; 12]),
            vec![0; 16],
        )))
        .await
        .expect("send fresh input");
        drop(peer);
        for expected in [control(1), bulk("sub-a", 512), bulk("sub-b", 16)] {
            assert_eq!(held.recv(&mut server).await.unwrap(), Some(expected));
        }
        assert!(held.recv(&mut server).await.unwrap().is_none());
    }
}
