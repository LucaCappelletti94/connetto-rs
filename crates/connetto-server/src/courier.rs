//! The courier core's wire types (R75).
//!
//! A range of one author's writer entries arrives signed by the author's
//! device key and settles through the write path the direct upload takes, as
//! [`SettlePath::Courier`](crate::writer_schema::SettlePath::Courier),
//! under [`SessionManager::courier_deliver`](crate::session::SessionManager::courier_deliver).

use crate::writer_schema::SettledOutcome;

/// One entry of a courier range, the author's sequence number and its
/// changeset, the uncompressed patchset bytes the author queued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CourierEntry {
    /// The entry's sequence under the author's writer.
    pub seq: u64,
    /// The entry's changeset, uncompressed patchset bytes.
    pub changeset: Vec<u8>,
}

/// A refusal of a courier range, nothing settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CourierRefusal {
    /// The key is no live enrolment, or the range does not carry the author's
    /// signature over it.
    NotEnrolled,
    /// The author's writer is retired.
    WriterRetired,
    /// The entries do not continue the author's settled chain.
    SequenceGap {
        /// The sequence the range had to start at.
        expected: u64,
        /// The sequence the range actually starts at.
        got: u64,
    },
}

/// The result of a courier range.
#[derive(Debug, Clone)]
pub enum CourierDelivery {
    /// The range was refused before any entry settled.
    Refused(CourierRefusal),
    /// One outcome per entry processed, in order. The range stops at the
    /// first refusal, so a list shorter than the range's entry count stopped
    /// at its last element, a [`SettledOutcome::Rejected`]. A trailing
    /// [`connetto_core::messages::MutationRejectReason::Indeterminate`] settled nothing, so the range
    /// re-offers from that entry; a trailing
    /// [`connetto_core::messages::MutationRejectReason::Forked`] stands at the sequence under a
    /// different entry, so the rest of the range vouches a diverged chain;
    /// and every other refusal settled its entry, so the next offer starts
    /// after the list.
    Entries(Vec<SettledOutcome>),
}
