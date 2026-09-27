//! What a row snapshot saw, carried in the cursor its `SnapshotEnd` hands the client.
//!
//! A snapshot's cursor is a position read before its transaction, and a commit
//! flushed before that position can still be invisible to the snapshot, while
//! it waits for a synchronous standby. The fence names the snapshot's running
//! transactions, so such a commit is judged `Missed` and replayed instead of
//! lost behind the cursor.

use subql::{Checkpoint, OpaqueCheckpoint, PgCommitPosition, PgLsn, PgSnapshotFence, PgXid, Seen};

/// A position's length in `Checkpoint::to_opaque` form.
const POSITION_LEN: usize = 20;

/// A snapshot's cursor before the session stamps it: where the read sits, then its fence when the source read one.
#[must_use]
pub fn snapshot_cursor(read: PgCommitPosition, fence: Option<&ReadFence>) -> Vec<u8> {
    let mut bytes = read.to_opaque().0;
    if let Some(fence) = fence {
        fence.encode_into(&mut bytes);
    }
    bytes
}

/// Split a cursor [`snapshot_cursor`] wrote, `None` for any other bytes.
#[must_use]
pub fn split_snapshot_cursor(bytes: &[u8]) -> Option<(PgCommitPosition, Option<ReadFence>)> {
    let (position, fence) = bytes.split_at_checked(POSITION_LEN)?;
    let position = PgCommitPosition::from_opaque(&OpaqueCheckpoint(position.to_vec()))?;
    if fence.is_empty() {
        return Some((position, None));
    }
    Some((position, Some(ReadFence::decode(fence)?)))
}

/// The transactions a snapshot did not see: `running`, and every one from `from` on for the next 2^31 ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unseen {
    /// The transactions the snapshot lists as running.
    pub running: Vec<PgXid>,
    /// The snapshot's `xmax`, the first transaction it treats as not yet completed.
    pub from: PgXid,
}

impl Unseen {
    /// Whether `xid` is one of these, taking `from` onwards as the 2^31 ids after it in wrapping order.
    #[must_use]
    pub fn contains(&self, xid: PgXid) -> bool {
        self.running.contains(&xid) || xid.0.wrapping_sub(self.from.0) < 1 << 31
    }
}

/// An id printed in `pg_snapshot` text reduced to the 32 bits a change carries.
fn low_bits(xid: &str) -> Option<PgXid> {
    let xid = xid.parse::<u64>().ok()?;
    u32::try_from(xid & u64::from(u32::MAX)).ok().map(PgXid)
}

/// A read's snapshot, as Postgres printed it, with the WAL insert position read inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadFence {
    /// `pg_current_snapshot()::text`, `xmin:xmax:xip,…`, kept because subql's fence has no encoding of its own.
    snapshot: String,
    fence: PgSnapshotFence,
}

impl ReadFence {
    /// The fence of a snapshot printed as `snapshot`, with `insert_lsn` read inside it, `None` for text of another shape.
    #[must_use]
    pub fn parse(snapshot: &str, insert_lsn: PgLsn) -> Option<Self> {
        Some(Self {
            snapshot: snapshot.to_owned(),
            fence: PgSnapshotFence::parse(snapshot, insert_lsn)?,
        })
    }

    /// Whether the snapshot holds the change at `at`, missed it, or ends before it.
    #[must_use]
    pub fn seen(&self, at: PgCommitPosition) -> Seen {
        at.seen_by(&self.fence)
    }

    /// The transactions a change the snapshot missed can come from: the ones it lists as running, and every one from its `xmax` on, which Postgres leaves unlisted when it is newer than every completed one.
    ///
    /// Ids are reduced to the 32 bits a change carries, so an id of another epoch can match and is judged by [`seen`](Self::seen) afterwards.
    #[must_use]
    pub fn unseen(&self) -> Unseen {
        let mut fields = self.snapshot.split(':').skip(1);
        let from = fields.next().and_then(low_bits).unwrap_or(PgXid::INVALID);
        let running = fields
            .next()
            .into_iter()
            .flat_map(|list| list.split(','))
            .filter_map(low_bits)
            .collect();
        Unseen { running, from }
    }

    /// Append the encoded fence: the insert position, then the snapshot text.
    pub(crate) fn encode_into(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.fence.insert_lsn().0.to_be_bytes());
        bytes.extend_from_slice(self.snapshot.as_bytes());
    }

    /// Read a fence [`encode_into`](Self::encode_into) wrote, `None` for any other bytes.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let (insert_lsn, snapshot) = bytes.split_first_chunk::<8>()?;
        Self::parse(
            core::str::from_utf8(snapshot).ok()?,
            PgLsn(u64::from_be_bytes(*insert_lsn)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{ReadFence, snapshot_cursor, split_snapshot_cursor};
    use subql::{PgCommitPosition, PgLsn, PgXid, Seen};

    #[test]
    fn a_snapshot_cursor_splits_into_its_read_and_its_fence() {
        let read = PgCommitPosition::before_commit(PgLsn(0x1800));
        let fenced = snapshot_cursor(read, Some(&fence()));
        assert_eq!(split_snapshot_cursor(&fenced), Some((read, Some(fence()))));
        let plain = snapshot_cursor(read, None);
        assert_eq!(split_snapshot_cursor(&plain), Some((read, None)));
        assert_eq!(
            split_snapshot_cursor(&fenced[..fenced.len() - 1]),
            None,
            "a cut fence is no cursor"
        );
        assert_eq!(split_snapshot_cursor(&[]), None);
    }

    fn fence() -> ReadFence {
        ReadFence::parse("740:745:741,742", PgLsn(0x2000)).expect("parse")
    }

    #[test]
    fn a_fence_reads_back_what_it_wrote() {
        let mut bytes = Vec::new();
        fence().encode_into(&mut bytes);
        assert_eq!(ReadFence::decode(&bytes), Some(fence()));
    }

    #[test]
    fn bytes_that_name_no_snapshot_read_as_no_fence() {
        assert_eq!(ReadFence::decode(&[]), None);
        assert_eq!(ReadFence::decode(&0x2000_u64.to_be_bytes()), None);
        let mut bytes = 0x2000_u64.to_be_bytes().to_vec();
        bytes.extend_from_slice(b"745:740:");
        assert_eq!(ReadFence::decode(&bytes), None, "xmin past xmax");
    }

    #[test]
    fn the_unseen_transactions_are_the_listed_ones_and_every_one_from_xmax() {
        let unseen = fence().unseen();
        assert_eq!(unseen.running, vec![PgXid(741), PgXid(742)]);
        assert!(unseen.contains(PgXid(741)) && unseen.contains(PgXid(745)));
        assert!(unseen.contains(PgXid(745 + (1 << 30))));
        assert!(!unseen.contains(PgXid(740)) && !unseen.contains(PgXid(744)));
        let quiet = ReadFence::parse("740:740:", PgLsn(1)).expect("parse");
        assert!(
            quiet.unseen().contains(PgXid(740)),
            "a running transaction newer than every completed one is unlisted"
        );
        let wrapping = ReadFence::parse(&format!("{0}:{0}:", u64::from(u32::MAX) - 1), PgLsn(1))
            .expect("parse");
        assert!(
            wrapping.unseen().contains(PgXid(3)),
            "the range wraps past the 32-bit end"
        );
    }

    #[test]
    fn a_running_transaction_committing_before_the_insert_position_is_missed() {
        let at = |xid, lsn| PgCommitPosition::new(PgLsn(lsn), PgXid(xid), 1);
        assert_eq!(fence().seen(at(741, 0x1000)), Seen::Missed);
        assert_eq!(fence().seen(at(739, 0x1000)), Seen::Held);
        assert_eq!(fence().seen(at(741, 0x2000)), Seen::Beyond);
    }
}
