//! The drain of the writes and files an older application schema major
//! captured (R31).
//!
//! An older major's queued write stays in its writer's chain under the major
//! it was captured with, and leaves only over a second wire beside the
//! connection's own, presenting that major, its bundle hash and the write's
//! writer, with no subscription and no resume state. The server keeps each
//! writer's frontier in the deployment's Postgres across majors, so the drain
//! and the connection's own wire settle one chain between them, each sending
//! only its own major's entries and neither passing an earlier entry of the
//! other's. The connection owns the drain and the replica it reads from,
//! because the browser's storage pool allows one handle per file. The
//! connection owns no dialer, so it says when a dial is owed through
//! [`DrainTimer`] and whoever pumps it dials with the factory it already
//! holds, exactly as it arms the resend of a deferred write.
//!
//! The oldest held major drains first, one writer at a time. A writer the old
//! major no longer knows, or one no server ever issued, hands its entries of
//! that major to a number the drain is issued, and the rest of its tail to
//! the live writer. A batch ends when every write and file of its major is
//! settled, or at once when its major is gone, and then the next one starts.

use std::collections::{BTreeMap, BTreeSet};

use connetto_core::messages::{
    ContentTicketRequest, ContentVerb, ControlMessage, FatalErrorReason, HeldWork, HeldWrite,
    MutationRejectReason, Provenance, WriterAnswer, WriterOutcome, WriterRef, WriterRequest,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Backoff, Major, RetryPolicy, SchemaVersion};
use core::time::Duration;
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;

use crate::majors::held_batch;
use crate::{
    ClientError, ClientEvent, ConnettoConnection, EntryRecord, HandshakeInput, HandshakeOk,
    SuspendedCapture, WriterQueue, clock, delete_pending, delete_writer_pending,
    exchange_handshake, is_real_writer, persist_pending, persist_retire, persist_writer_state,
    unissued,
};

/// How a drain dial backs off, the reconnect loop's own shape: 200 ms first,
/// doubling to 5 s, for ever.
static DRAIN_POLICY: std::sync::LazyLock<RetryPolicy> = std::sync::LazyLock::new(RetryPolicy::new);

/// A dial the drain owes, identified so a stale one is recognized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainTimer {
    armed: u64,
    wait: Duration,
}

impl DrainTimer {
    /// How long to wait before dialing.
    #[must_use]
    pub const fn wait(&self) -> Duration {
        self.wait
    }
}

/// The older major whose work is draining, with the bundle hash its server
/// was built from.
struct HeldBatch {
    major: Major,
    version: SchemaVersion,
}

/// A device bind the drain sent and the old major has not answered, bounded
/// by a monotonic deadline.
#[cfg(feature = "device-identity")]
struct DrainBind {
    request_id: String,
    key_id: [u8; 32],
    deadline: Duration,
}

/// The drain's state beside the connection's own wire.
pub(crate) struct Drain<T> {
    batch: Option<HeldBatch>,
    wire: Option<T>,
    /// The writer the drain wire writes as, once the old major bound it.
    writer: Option<WriterRef>,
    /// The sequences sent on the drain wire and not yet answered.
    in_flight: BTreeSet<u64>,
    #[cfg(feature = "device-identity")]
    bind: Option<DrainBind>,
    /// Writers the old major refused, whose entries a number the drain is
    /// issued takes over.
    dead: BTreeSet<WriterRef>,
    timer: Option<DrainTimer>,
    episode: Backoff<'static>,
    armed: u64,
}

impl<T> Drain<T> {
    /// No held work.
    pub(crate) fn idle() -> Self {
        Self {
            batch: None,
            wire: None,
            writer: None,
            in_flight: BTreeSet::new(),
            #[cfg(feature = "device-identity")]
            bind: None,
            dead: BTreeSet::new(),
            timer: None,
            episode: DRAIN_POLICY.start(),
            armed: 0,
        }
    }

    /// The live drain wire, if any.
    pub(crate) fn wire_mut(&mut self) -> Option<&mut T> {
        self.wire.as_mut()
    }

    /// Owe a dial after `wait`.
    fn arm(&mut self, wait: Duration) {
        self.armed += 1;
        self.timer = Some(DrainTimer {
            armed: self.armed,
            wait,
        });
    }

    /// Owe the next dial on the backoff.
    fn back_off(&mut self) {
        let wait = self
            .episode
            .next_wait()
            .unwrap_or_else(|| DRAIN_POLICY.max_backoff());
        self.arm(wait);
    }

    /// Forget what the drain wire was bound to and had in flight.
    fn unbind(&mut self) {
        self.writer = None;
        self.in_flight.clear();
        #[cfg(feature = "device-identity")]
        {
            self.bind = None;
        }
    }
}

/// The oldest major a rebuild left work for.
fn oldest_batch(db: &mut SqliteConnection) -> Result<Option<HeldBatch>, ClientError> {
    if !crate::majors::has_held(db)? {
        return Ok(None);
    }
    let Some((major, version)) = held_batch::table
        .select((held_batch::major, held_batch::version))
        .order(held_batch::major)
        .first::<(i64, Vec<u8>)>(db)
        .optional()?
    else {
        return Ok(None);
    };
    let major = u32::try_from(major)
        .ok()
        .and_then(Major::new)
        .ok_or_else(|| ClientError::Session(format!("a held batch records major {major}")))?;
    Ok(Some(HeldBatch {
        major,
        version: SchemaVersion::from_hash(version),
    }))
}

impl<T> ConnettoConnection<T>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    /// Load the oldest held batch and owe a dial for it at once.
    pub(crate) fn load_drain(&mut self) -> Result<(), ClientError> {
        self.drain.batch = oldest_batch(&mut self.db)?;
        self.drain.timer = None;
        if self.drain.batch.is_some() {
            self.drain.episode = DRAIN_POLICY.start();
            self.drain.arm(Duration::ZERO);
        }
        Ok(())
    }

    /// The dial the drain owes, if any (R31). Whoever pumps the connection
    /// sleeps [`DrainTimer::wait`], dials with its factory, and hands the
    /// transport to [`attach_drain`](Self::attach_drain), or reports a failed
    /// dial to [`drain_dial_failed`](Self::drain_dial_failed).
    #[must_use]
    pub const fn drain_timer(&self) -> Option<DrainTimer> {
        self.drain.timer
    }

    /// The major whose held work is draining, if any.
    #[must_use]
    pub fn draining_major(&self) -> Option<Major> {
        self.drain.batch.as_ref().map(|batch| batch.major)
    }

    /// A dial for `timer` failed, so the drain backs off.
    pub fn drain_dial_failed(&mut self, timer: DrainTimer) {
        if self.drain.timer == Some(timer) {
            self.drain.back_off();
        }
    }

    /// The writer the draining major's next write is queued under: the one
    /// holding its entry of the lowest append position.
    fn drain_writer(&self, major: Major) -> Option<WriterRef> {
        self.writers
            .iter()
            .flat_map(|(writer, queue)| {
                queue
                    .pending
                    .values()
                    .filter(|entry| entry.major == Some(major))
                    .map(move |entry| (entry.position, *writer))
            })
            .min_by_key(|(position, _)| *position)
            .map(|(_, writer)| writer)
    }

    /// Whether any writer still queues an entry `major` captured.
    fn holds_major(&self, major: Major) -> bool {
        self.writers.values().any(|queue| {
            queue
                .pending
                .values()
                .any(|entry| entry.major == Some(major))
        })
    }

    /// The lowest append position among the queued entries captured under a
    /// major other than `major`. A wire for `major` sends nothing queued at
    /// or after it, so no write lands ahead of an earlier one only another
    /// major can apply (R31).
    pub(crate) fn lowest_position_outside(&self, major: Option<Major>) -> Option<u64> {
        self.writers
            .values()
            .flat_map(|queue| queue.pending.values())
            .filter(|entry| entry.major != major)
            .map(|entry| entry.position)
            .min()
    }

    /// What the drain presents for `writer`, or `None` while it is a device
    /// whose bind cannot be signed yet.
    fn drain_request(
        &mut self,
        writer: Option<WriterRef>,
    ) -> Result<Option<WriterRequest>, ClientError> {
        let Some(writer) = writer else {
            // Files alone ride a wire that names no writer, which a device
            // request does until a bind follows it, and none does.
            return Ok(Some(WriterRequest::Device));
        };
        if self.drain.dead.contains(&writer) || !is_real_writer(&writer) {
            return Ok(Some(WriterRequest::Issue));
        }
        match writer {
            WriterRef::Number(number) => Ok(Some(WriterRequest::Number(number))),
            WriterRef::Device(key_id) => self.drain_device_request(key_id),
        }
    }

    /// The request for a device writer: a bind when this device still holds
    /// that key in standing, an issued number when the key is gone, and a
    /// wait while the certificate is outside its window.
    #[cfg(feature = "device-identity")]
    fn drain_device_request(
        &mut self,
        key_id: [u8; 32],
    ) -> Result<Option<WriterRequest>, ClientError> {
        if self.retired_keys.contains(&key_id) {
            return Ok(Some(WriterRequest::Issue));
        }
        let Some(held) = self.device_certificate()? else {
            return Ok(Some(WriterRequest::Issue));
        };
        if *held.leaf.identity().key().as_bytes() != key_id {
            return Ok(Some(WriterRequest::Issue));
        }
        let standing = crate::enrolment::Standing::of(Some(&held), std::time::SystemTime::now());
        let bindable = self.writer_keys.is_some()
            && matches!(
                standing,
                crate::enrolment::Standing::Fresh | crate::enrolment::Standing::Aging
            );
        Ok(bindable.then_some(WriterRequest::Device))
    }

    /// A build without a device identity holds no device writer to bind, so
    /// an entry under one moves to an issued number.
    #[cfg(not(feature = "device-identity"))]
    #[expect(
        clippy::unnecessary_wraps,
        clippy::unused_self,
        reason = "the device build's body reads the certificate and can fail"
    )]
    fn drain_device_request(
        &mut self,
        _key_id: [u8; 32],
    ) -> Result<Option<WriterRequest>, ClientError> {
        Ok(Some(WriterRequest::Issue))
    }

    /// Present the held major over `transport`, bound to the writer of its
    /// oldest write, and upload that writer's writes of the major.
    ///
    /// A stale `timer` drops the transport unused. A refusal saying the held
    /// major is gone, or a server at that major built from another schema,
    /// ends the batch with [`HeldWork::Lost`]. A refused writer hands its
    /// entries to a number the next dial is issued. A revoked session stops
    /// the drain and keeps the rows for teardown. Anything else backs off and
    /// dials again.
    ///
    /// # Errors
    ///
    /// A failure to read or write the queued rows.
    pub async fn attach_drain(
        &mut self,
        timer: DrainTimer,
        mut transport: T,
    ) -> Result<(), ClientError> {
        if self.drain.timer != Some(timer) {
            return Ok(());
        }
        self.drain.timer = None;
        let Some((major, version)) = self
            .drain
            .batch
            .as_ref()
            .map(|batch| (batch.major, batch.version.clone()))
        else {
            return Ok(());
        };
        let writer = self.drain_writer(major);
        let Some(request) = self.drain_request(writer)? else {
            // The device's certificate is outside its window, so the bind
            // waits for the enrolment to stand again.
            let _ = transport.close().await;
            self.drain.back_off();
            return Ok(());
        };
        let settled_through = match request {
            WriterRequest::Number(number) => Some(self.settled_through(&WriterRef::Number(number))),
            WriterRequest::Issue | WriterRequest::Device => None,
        };
        let now = clock::now_secs(&mut self.db)?;
        let presented = self
            .config
            .clone()
            .with_schema_major(Some(major))
            .with_schema_version(Some(version));
        let outcome = exchange_handshake(
            &mut transport,
            HandshakeInput {
                config: &presented,
                token_source: self.token_source.as_ref(),
                resume: None,
                resume_token: None,
                writer: request,
                settled_through,
                now,
                cursor_subjects: None,
            },
        )
        .await;
        match outcome {
            Ok(ack) => {
                self.drain.wire = Some(transport);
                self.drain.unbind();
                self.drain.episode = DRAIN_POLICY.start();
                self.drain_bound(major, writer, request, ack).await
            }
            Err(
                ClientError::UpdateRequired { .. }
                | ClientError::ServerBehind { .. }
                | ClientError::SchemaOutdated { .. },
            ) => self.lose_major(major).await,
            Err(ClientError::Refused {
                reason: FatalErrorReason::WriterUnknown | FatalErrorReason::WriterRetired,
            }) => {
                if let Some(writer) = writer {
                    self.drain.dead.insert(writer);
                }
                self.drain.arm(Duration::ZERO);
                Ok(())
            }
            Err(ClientError::Refused {
                reason: FatalErrorReason::SessionRevoked,
            }) => Ok(()),
            Err(ClientError::Refused {
                reason: FatalErrorReason::DeviceRevoked,
            }) => {
                self.exclude_device_writers()?;
                self.drain.arm(Duration::ZERO);
                Ok(())
            }
            Err(_) => {
                self.drain.back_off();
                Ok(())
            }
        }
    }

    /// Act on the old major's acknowledgement of the drain handshake.
    async fn drain_bound(
        &mut self,
        major: Major,
        writer: Option<WriterRef>,
        request: WriterRequest,
        ack: HandshakeOk,
    ) -> Result<(), ClientError> {
        match request {
            WriterRequest::Issue => {
                let Some(grant) = ack.writer else {
                    self.drop_drain_wire().await;
                    return Ok(());
                };
                let issued = WriterRef::Number(grant.number);
                if let Some(writer) = writer {
                    // This major's entries move to the issued number, and the
                    // rest of the tail goes to the live writer.
                    self.carry_matching(&[writer], &issued, |entry| entry.major == Some(major))?;
                    if self.writers.contains_key(&writer) {
                        self.carry_to_live(writer);
                    }
                    self.drain.dead.remove(&writer);
                }
                self.drain.writer = Some(issued);
                self.drain_reconcile(major, grant.frontier).await
            }
            WriterRequest::Number(_) => {
                self.drain.writer = writer;
                let frontier = ack.writer.map_or(0, |grant| grant.frontier);
                self.drain_reconcile(major, frontier).await
            }
            WriterRequest::Device => match writer {
                // Files alone, so nothing binds and the content layer asks for its tickets.
                None => self.after_drain_settle(major).await,
                Some(WriterRef::Device(key_id)) => self.drain_bind(key_id, &ack).await,
                Some(_) => {
                    self.drop_drain_wire().await;
                    Ok(())
                }
            },
        }
    }

    /// Sign the old major's challenge with the device's key and ask it to
    /// bind the device writer on the drain wire, bounded by the writer answer
    /// wait.
    #[cfg(feature = "device-identity")]
    async fn drain_bind(&mut self, key_id: [u8; 32], ack: &HandshakeOk) -> Result<(), ClientError> {
        use crate::away::Clock as _;
        let (Some(challenge), Some(keys)) = (ack.challenge, self.writer_keys.clone()) else {
            self.drop_drain_wire().await;
            return Ok(());
        };
        let opened = keys.open().await?;
        if *connetto_core::device_cert::key_id(&*opened.key).as_bytes() != key_id {
            // The device holds another key now, so the old one's entries move.
            self.drain.dead.insert(WriterRef::Device(key_id));
            self.drop_drain_wire().await;
            self.drain.arm(Duration::ZERO);
            return Ok(());
        }
        let signature = opened
            .key
            .sign(&connetto_core::messages::writer_bind_message(&challenge))
            .map_err(|err| {
                ClientError::DeviceChip(crate::device_key::ChipError::Failed(Box::new(err)))
            })?;
        let request_id = crate::writer_request_id();
        let Some(wire) = self.drain.wire.as_mut() else {
            return Ok(());
        };
        if let Err(err) = wire
            .send_control(ControlMessage::BindDevice(
                connetto_core::messages::BindDevice {
                    request_id: request_id.clone(),
                    key_id,
                    signature,
                },
            ))
            .await
        {
            tracing::warn!(error = %err, "the drain wire failed while binding the device");
            self.drop_drain_wire().await;
            return Ok(());
        }
        self.drain.bind = Some(DrainBind {
            request_id,
            key_id,
            deadline: crate::away::SystemClock.monotonic() + crate::WRITER_ANSWER_WAIT,
        });
        Ok(())
    }

    /// A build without a device identity never queues under a device writer.
    #[cfg(not(feature = "device-identity"))]
    async fn drain_bind(
        &mut self,
        _key_id: [u8; 32],
        _ack: &HandshakeOk,
    ) -> Result<(), ClientError> {
        self.drop_drain_wire().await;
        Ok(())
    }

    /// Drop the drain wire when its device bind overran the answer bound, so
    /// the next dial binds again.
    pub(crate) async fn check_drain_deadline(&mut self) {
        #[cfg(feature = "device-identity")]
        {
            use crate::away::Clock as _;
            if self
                .drain
                .bind
                .as_ref()
                .is_some_and(|bind| crate::away::SystemClock.monotonic() >= bind.deadline)
            {
                tracing::warn!(
                    "the drain's device bind overran its bound, dropping the drain wire"
                );
                self.drop_drain_wire().await;
            }
        }
    }

    /// Settle what the old major reports at or below `frontier` for the bound
    /// writer, then send the rest of the major's writes in sequence order.
    async fn drain_reconcile(&mut self, major: Major, frontier: u64) -> Result<(), ClientError> {
        let Some(writer) = self.drain.writer else {
            return self.after_drain_settle(major).await;
        };
        let settled: Vec<(u64, Option<Major>)> = self
            .writers
            .get(&writer)
            .map(|queue| {
                queue
                    .pending
                    .range(..=frontier)
                    .map(|(seq, entry)| (*seq, entry.major))
                    .collect()
            })
            .unwrap_or_default();
        for (seq, captured) in settled {
            self.settle_entry(writer, seq)?;
            if captured == Some(major) {
                self.notices.push_back(ClientEvent::Held(HeldWork::Applied {
                    major,
                    write: HeldWrite { writer, seq },
                }));
            }
        }
        if let Some(queue) = self.writers.get_mut(&writer) {
            let raised = frontier.saturating_add(1).max(queue.next_seq);
            if raised != queue.next_seq {
                queue.next_seq = raised;
                let (next_seq, head) = (queue.next_seq, queue.head);
                let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
                persist_writer_state(&mut self.db, &writer, next_seq, &head)?;
            }
        }
        self.send_held(major).await
    }

    /// Send the bound writer's writes of `major` the wire has not sent, in
    /// sequence order, stopping at the first entry another major captured or
    /// an earlier entry of another major holds back.
    async fn send_held(&mut self, major: Major) -> Result<(), ClientError> {
        let Some(writer) = self.drain.writer else {
            return self.after_drain_settle(major).await;
        };
        let limit = self.lowest_position_outside(Some(major));
        let sends: Vec<(u64, Vec<u8>, Option<Provenance>)> = self
            .writers
            .get(&writer)
            .map(|queue| {
                queue
                    .pending
                    .iter()
                    .take_while(|(_, entry)| {
                        entry.major == Some(major)
                            && limit.is_none_or(|position| entry.position < position)
                    })
                    .filter(|(seq, _)| !self.drain.in_flight.contains(seq))
                    .map(|(seq, entry)| (*seq, entry.changeset.clone(), entry.provenance))
                    .collect()
            })
            .unwrap_or_default();
        for (seq, changeset, provenance) in sends {
            let Some(wire) = self.drain.wire.as_mut() else {
                return Ok(());
            };
            if let Err(err) =
                crate::send_wire_changeset(wire, seq, &changeset, provenance.as_ref()).await
            {
                tracing::warn!(error = %err, "the drain wire failed while sending held writes");
                self.drop_drain_wire().await;
                return Ok(());
            }
            self.drain.in_flight.insert(seq);
        }
        self.after_drain_settle(major).await
    }

    /// Retire one entry of the drain's writer, settled one way or another.
    fn settle_entry(&mut self, writer: WriterRef, seq: u64) -> Result<(), ClientError> {
        let removed = self
            .writers
            .get_mut(&writer)
            .and_then(|queue| queue.pending.remove(&seq))
            .is_some();
        if removed {
            let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
            delete_pending(&mut self.db, &writer, seq)?;
        }
        self.drain.in_flight.remove(&seq);
        Ok(())
    }

    /// Decide what follows a settled write: the batch finishes once nothing
    /// of its major is left, files aside, and the wire moves to the next
    /// writer once nothing of the major is left on its own or can still go up.
    async fn after_drain_settle(&mut self, major: Major) -> Result<(), ClientError> {
        if !self.holds_major(major) {
            if (self.config.held_content.count)(&mut self.db, major)? > 0 {
                // The content layer's held files still ask for tickets on this wire.
                return Ok(());
            }
            return self.finish_batch().await;
        }
        let Some(writer) = self.drain.writer else {
            self.drop_drain_wire().await;
            return Ok(());
        };
        #[cfg(feature = "device-identity")]
        if self.drain.bind.is_some() {
            return Ok(());
        }
        let left_here = self.writers.get(&writer).is_some_and(|queue| {
            queue
                .pending
                .values()
                .any(|entry| entry.major == Some(major))
        });
        if !left_here {
            // Another writer holds the major's next write, so the next dial binds it.
            self.drop_drain_wire().await;
            self.drain.arm(Duration::ZERO);
        } else if self.drain.in_flight.is_empty() {
            // What is left waits behind another major's earlier write, so the
            // drain looks again after a backoff.
            self.drop_drain_wire().await;
        }
        Ok(())
    }

    /// Lose every write and file `major` captured, its server being gone or
    /// serving another schema: report them, retire each writer they were
    /// queued under, whose chain now has a gap, and carry its remaining tail
    /// to the live writer.
    async fn lose_major(&mut self, major: Major) -> Result<(), ClientError> {
        let lost: Vec<HeldWrite> = self
            .writers
            .iter()
            .flat_map(|(writer, queue)| {
                queue
                    .pending
                    .iter()
                    .filter(|(_, entry)| entry.major == Some(major))
                    .map(move |(seq, _)| HeldWrite {
                        writer: *writer,
                        seq: *seq,
                    })
            })
            .collect();
        let hit: BTreeSet<WriterRef> = lost.iter().map(|write| write.writer).collect();
        for write in &lost {
            self.settle_entry(write.writer, write.seq)?;
        }
        let files = {
            let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
            crate::majors::forget_batch(&mut self.db, major, self.config.held_content)?
        };
        let mut device_retired = false;
        for writer in hit {
            match writer {
                WriterRef::Device(_) if !device_retired => {
                    device_retired = true;
                    let event = self.retire_device()?;
                    self.notices.push_back(event);
                }
                WriterRef::Device(_) => {}
                number @ WriterRef::Number(_) if !is_real_writer(&number) => {
                    self.rechain_unissued()?;
                }
                number @ WriterRef::Number(_) => {
                    self.owe_retire(number).await?;
                    self.carry_to_live(number);
                    self.drain.dead.insert(number);
                }
            }
        }
        self.notices.push_back(ClientEvent::Held(HeldWork::Lost {
            major,
            writes: lost,
            files,
        }));
        self.drop_drain_wire().await;
        self.load_drain()?;
        self.release_held().await
    }

    /// Record that `writer` is owed a retirement and send it now when the
    /// connection's own wire is up.
    async fn owe_retire(&mut self, writer: WriterRef) -> Result<(), ClientError> {
        use crate::away::Clock as _;
        {
            let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
            persist_retire(&mut self.db, &writer)?;
        }
        if self.is_connected() {
            self.writer_tasks.push_back(crate::WriterTask {
                kind: crate::WriterTaskKind::Retire(writer),
                request_id: crate::writer_request_id(),
                deadline: crate::away::SystemClock.monotonic() + crate::WRITER_ANSWER_WAIT,
            });
            self.flush_writer_tasks().await?;
        }
        Ok(())
    }

    /// Re-chain the unissued queue from sequence one after entries left it.
    /// No server ever saw an unissued sequence, so renumbering it reuses
    /// nothing a frontier counted.
    fn rechain_unissued(&mut self) -> Result<(), ClientError> {
        let writer = unissued();
        let Some(queue) = self.writers.remove(&writer) else {
            return Ok(());
        };
        let mut rechained = WriterQueue::fresh();
        let mut placed: BTreeMap<u64, crate::PendingEntry> = BTreeMap::new();
        for (_, mut entry) in queue.pending {
            let seq = rechained.next_seq;
            entry.hash =
                connetto_core::chain::entry_hash(&rechained.head, seq, &self.chain_bytes(&entry)?);
            rechained.head = entry.hash;
            rechained.next_seq = seq + 1;
            placed.insert(seq, entry);
        }
        {
            let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
            self.db.transaction::<(), ClientError, _>(|db| {
                delete_writer_pending(db, &writer)?;
                for (seq, entry) in &placed {
                    let record: EntryRecord<'_> = entry.record();
                    persist_pending(db, &writer, *seq, &record)?;
                }
                persist_writer_state(db, &writer, rechained.next_seq, &rechained.head)
            })?;
        }
        rechained.pending = placed;
        self.writers.insert(writer, rechained);
        Ok(())
    }

    /// The batch is settled once no write and no held file of its major is
    /// left: forget it, close the drain wire, start the next batch, and let
    /// the connection's own wire send what waited behind it.
    async fn finish_batch(&mut self) -> Result<(), ClientError> {
        let Some(major) = self.draining_major() else {
            return Ok(());
        };
        if self.holds_major(major) || (self.config.held_content.count)(&mut self.db, major)? > 0 {
            return Ok(());
        }
        {
            let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
            crate::majors::forget_batch(&mut self.db, major, self.config.held_content)?;
        }
        self.drop_drain_wire().await;
        self.notices
            .push_back(ClientEvent::Held(HeldWork::Drained { major }));
        self.load_drain()?;
        self.release_held().await
    }

    /// Hand the connection's own wire what an older major's writes held
    /// back: a number tail now settled lets a waiting device bind go, and the
    /// queue replays.
    async fn release_held(&mut self) -> Result<(), ClientError> {
        if !self.is_connected() {
            return Ok(());
        }
        #[cfg(feature = "device-identity")]
        self.finish_number_tail().await?;
        self.replay_pending().await
    }

    /// The content layer settled a held file, uploaded or lost, so the batch
    /// may now be done.
    ///
    /// # Errors
    ///
    /// A failure to read or forget the held rows.
    pub async fn held_file_settled(&mut self) -> Result<(), ClientError> {
        self.finish_batch().await
    }

    /// Close and forget the drain wire, owing a redial when work remains.
    async fn drop_drain_wire(&mut self) {
        if let Some(mut wire) = self.drain.wire.take() {
            let _ = wire.close().await;
        }
        self.drain.unbind();
        if self.drain.batch.is_some() && self.drain.timer.is_none() {
            self.drain.back_off();
        }
    }

    /// Act on one frame from the drain wire.
    ///
    /// # Errors
    ///
    /// A failure to update the queued rows.
    pub(crate) async fn handle_drain_frame(
        &mut self,
        frame: Option<IncomingFrame>,
    ) -> Result<(), ClientError> {
        let Some(major) = self.draining_major() else {
            self.drop_drain_wire().await;
            return Ok(());
        };
        match frame {
            Some(IncomingFrame::Control(ControlMessage::MutationApplied(ack))) => {
                if let Some(write) = self.settle_held(ack.client_seq)? {
                    self.notices
                        .push_back(ClientEvent::Held(HeldWork::Applied { major, write }));
                }
            }
            Some(IncomingFrame::Control(ControlMessage::MutationReject(reject)))
                if reject.reason == MutationRejectReason::Indeterminate =>
            {
                // The old server could not settle it yet, so the wire is
                // dropped and the redial sends the writer's writes again.
                self.drop_drain_wire().await;
                return Ok(());
            }
            Some(IncomingFrame::Control(ControlMessage::MutationReject(reject))) => {
                if let Some(write) = self.settle_held(reject.client_seq)? {
                    self.notices
                        .push_back(ClientEvent::Held(HeldWork::Rejected {
                            major,
                            write,
                            reason: Some(reject.reason),
                        }));
                }
            }
            Some(IncomingFrame::Control(ControlMessage::MutationConflict(conflict))) => {
                if let Some(write) = self.settle_held(conflict.client_seq)? {
                    self.notices
                        .push_back(ClientEvent::Held(HeldWork::Rejected {
                            major,
                            write,
                            reason: None,
                        }));
                }
            }
            Some(IncomingFrame::Control(ControlMessage::WriterAnswer(answer))) => {
                return self.drain_writer_answer(major, answer).await;
            }
            Some(IncomingFrame::Control(ControlMessage::FatalError(fatal))) => {
                return self.drain_fatal(major, fatal.reason).await;
            }
            // The content layer's held-file tickets, answered on this wire.
            Some(IncomingFrame::Control(ControlMessage::ContentTicketGrant(grant))) => {
                self.notices.push_back(ClientEvent::ContentTicket {
                    request_id: grant.request_id,
                    url: grant.url,
                });
                return Ok(());
            }
            Some(IncomingFrame::Control(ControlMessage::NonFatalError(err))) => {
                self.notices.push_back(ClientEvent::NonFatal {
                    related_to: err.related_to,
                    detail: err.detail,
                });
                return Ok(());
            }
            Some(IncomingFrame::Control(ControlMessage::RateLimited(limited))) => {
                // A held write we sent on this wire and have not settled yet
                // could never come back on the main wire, so the wire is
                // dropped and the redial sends it again.
                if limited
                    .related_to
                    .as_deref()
                    .and_then(|related| related.parse::<u64>().ok())
                    .is_some_and(|seq| self.drain.in_flight.contains(&seq))
                {
                    self.drop_drain_wire().await;
                    return Ok(());
                }
                let event = self.rate_limited(limited);
                self.notices.push_back(event);
                return Ok(());
            }
            // Nothing else concerns a session with no subscription.
            Some(_) => return Ok(()),
            None => {
                self.drop_drain_wire().await;
                return Ok(());
            }
        }
        self.after_drain_settle(major).await
    }

    /// Settle one answered write of the drain's writer, returning it named
    /// for the report.
    fn settle_held(&mut self, seq: u64) -> Result<Option<HeldWrite>, ClientError> {
        let Some(writer) = self.drain.writer else {
            return Ok(None);
        };
        self.settle_entry(writer, seq)?;
        Ok(Some(HeldWrite { writer, seq }))
    }

    /// The old major's answer to the drain's device bind.
    async fn drain_writer_answer(
        &mut self,
        major: Major,
        answer: WriterAnswer,
    ) -> Result<(), ClientError> {
        #[cfg(feature = "device-identity")]
        {
            let Some(bind) = self
                .drain
                .bind
                .take_if(|bind| bind.request_id == answer.request_id)
            else {
                return Ok(());
            };
            let writer = WriterRef::Device(bind.key_id);
            if let WriterOutcome::Bound { frontier } = answer.outcome {
                self.drain.writer = Some(writer);
                return self.drain_reconcile(major, frontier).await;
            }
            // Retired, unknown or not enrolled there, so its entries move.
            self.drain.dead.insert(writer);
            self.drop_drain_wire().await;
            self.drain.arm(Duration::ZERO);
            Ok(())
        }
        #[cfg(not(feature = "device-identity"))]
        {
            let _ = (major, answer, WriterOutcome::Unknown);
            Ok(())
        }
    }

    /// A fatal frame on the drain wire.
    async fn drain_fatal(
        &mut self,
        major: Major,
        reason: FatalErrorReason,
    ) -> Result<(), ClientError> {
        match reason {
            FatalErrorReason::MajorMismatch { .. } => self.lose_major(major).await,
            FatalErrorReason::SessionRevoked => {
                self.drain.wire = None;
                self.drain.unbind();
                self.drain.timer = None;
                Ok(())
            }
            FatalErrorReason::DeviceRevoked => {
                self.exclude_device_writers()?;
                self.drop_drain_wire().await;
                self.drain.arm(Duration::ZERO);
                Ok(())
            }
            FatalErrorReason::WriterUnknown | FatalErrorReason::WriterRetired => {
                if let Some(writer) = self.drain.writer {
                    self.drain.dead.insert(writer);
                }
                self.drop_drain_wire().await;
                self.drain.arm(Duration::ZERO);
                Ok(())
            }
            _ => {
                self.drop_drain_wire().await;
                Ok(())
            }
        }
    }

    /// Ask the held major's server, over the drain wire, for a content ticket
    /// naming one held file (R31). The answer arrives as
    /// [`ClientEvent::ContentTicket`] carrying `request_id`, or as a refusal
    /// carrying it in `related_to`, exactly as
    /// [`request_content_ticket`](Self::request_content_ticket) is answered.
    ///
    /// # Errors
    ///
    /// [`ClientError::NotConnected`] when no drain wire is up, and
    /// [`ClientError::Transport`] when the request cannot be sent.
    pub async fn request_held_ticket(
        &mut self,
        request_id: String,
        file_id: [u8; 32],
        verb: ContentVerb,
    ) -> Result<(), ClientError> {
        let wire = self.drain.wire.as_mut().ok_or(ClientError::NotConnected)?;
        wire.send_control(ControlMessage::ContentTicketRequest(ContentTicketRequest {
            request_id,
            file_id,
            verb,
        }))
        .await
        .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// Whether the drain wire is up and its major's writes settled, so held
    /// files may ask for tickets on it.
    #[must_use]
    pub fn held_files_ready(&self) -> Option<Major> {
        let batch = self.drain.batch.as_ref()?;
        (self.drain.wire.is_some() && !self.holds_major(batch.major)).then_some(batch.major)
    }

    /// Whether the draining major still holds files, whatever the wire state
    /// (R31), so a content driver knows it must keep walking.
    ///
    /// # Errors
    ///
    /// A failure to read the held rows.
    pub fn held_files_pending(&mut self) -> Result<bool, ClientError> {
        let Some(major) = self.draining_major() else {
            return Ok(false);
        };
        Ok((self.config.held_content.count)(&mut self.db, major)? > 0)
    }

    /// The total held files across every held major (R31), the pending-work
    /// reading a teardown guard consults.
    ///
    /// # Errors
    ///
    /// A failure to read the held rows.
    pub fn held_files_total(&mut self) -> Result<u64, ClientError> {
        if !crate::majors::has_held(&mut self.db)? {
            return Ok(0);
        }
        let majors: Vec<i64> = held_batch::table
            .select(held_batch::major)
            .load(&mut self.db)?;
        let mut total = 0u64;
        for stored in majors {
            let major = u32::try_from(stored)
                .ok()
                .and_then(Major::new)
                .ok_or_else(|| {
                    ClientError::Session(format!("a held batch records major {stored}"))
                })?;
            total = total.saturating_add((self.config.held_content.count)(&mut self.db, major)?);
        }
        Ok(total)
    }

    /// The content layer gave up on one held file of `major` for good, a
    /// refused ticket or a refused upload, after deleting its held rows. The
    /// loss is reported and the batch may now be done.
    ///
    /// # Errors
    ///
    /// A failure to read or forget the held rows.
    pub async fn held_file_lost(&mut self, major: Major) -> Result<(), ClientError> {
        self.notices.push_back(ClientEvent::Held(HeldWork::Lost {
            major,
            writes: Vec::new(),
            files: 1,
        }));
        self.finish_batch().await
    }

    /// A drain wire receive failed, so the drain backs off and dials again.
    pub(crate) async fn drain_wire_failed(&mut self) {
        self.drop_drain_wire().await;
    }
}
