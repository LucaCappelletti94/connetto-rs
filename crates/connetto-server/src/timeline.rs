//! Which cluster and which timeline of the database a resume cursor belongs to (R73, R70).
//!
//! A promoted standby's history ends the old timeline where the standby stopped
//! receiving, so a cursor past that point names changes the database lost.
//! A dump restored into another cluster starts again at timeline 1 under another
//! system identifier, so a cursor naming the old identifier names changes it never had.

use pg_walstream::PgReplicationConnection;
use subql::{Checkpoint, OpaqueCheckpoint, PgCommitPosition, PgLsn};

/// The timeline of a database that was never promoted.
const FIRST_TIMELINE: u32 = 1;

/// A change's place in commit order, on the cluster and timeline it was issued from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    /// The system identifier of the cluster the position was issued on.
    pub system: u64,
    /// The timeline the position was issued on.
    pub timeline: u32,
    /// The commit the change belongs to and its ordinal in it, or a read's position.
    pub at: PgCommitPosition,
}

impl Position {
    /// A cursor's length on the wire.
    const ENCODED_LEN: usize = 28;

    /// The wire cursor, the cluster then the timeline then the position, so byte order stays issue order across a promotion.
    #[must_use]
    pub fn to_cursor_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::ENCODED_LEN);
        bytes.extend_from_slice(&self.system.to_be_bytes());
        bytes.extend_from_slice(&self.timeline.to_be_bytes());
        bytes.extend_from_slice(&self.at.to_opaque().0);
        bytes
    }

    /// Read a wire cursor, `None` for any other length, every earlier layout included.
    #[must_use]
    pub fn from_cursor_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; Self::ENCODED_LEN] = bytes.try_into().ok()?;
        let (system, rest) = bytes.split_at(8);
        let (timeline, at) = rest.split_at(4);
        Some(Self {
            system: u64::from_be_bytes(system.try_into().ok()?),
            timeline: u32::from_be_bytes(timeline.try_into().ok()?),
            at: PgCommitPosition::from_opaque(&OpaqueCheckpoint(at.to_vec()))?,
        })
    }
}

/// A failure while reading the database's timeline history.
#[derive(Debug, thiserror::Error)]
pub enum TimelineError {
    /// The replication connection could not be opened.
    #[error("opening a replication connection: {0}")]
    Connect(String),
    /// `IDENTIFY_SYSTEM` or `TIMELINE_HISTORY` failed.
    #[error("reading the timeline history: {0}")]
    Query(String),
    /// The server answered with something that is not a timeline history.
    #[error("malformed timeline history: {0}")]
    Malformed(String),
    /// The blocking read was cancelled or panicked.
    #[error("the timeline read did not finish: {0}")]
    Join(String),
}

/// The database's cluster, its current timeline, and where each timeline before it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineHistory {
    system: u64,
    current: u32,
    /// Each ancestor timeline and the last position it shares with the current one.
    ended: Vec<(u32, u64)>,
}

impl Default for TimelineHistory {
    fn default() -> Self {
        Self {
            system: 0,
            current: FIRST_TIMELINE,
            ended: Vec::new(),
        }
    }
}

impl TimelineHistory {
    /// A never promoted database of the cluster `system`.
    #[must_use]
    pub fn first(system: u64) -> Self {
        Self {
            system,
            ..Self::default()
        }
    }

    /// The system identifier of the database's cluster.
    #[must_use]
    pub const fn system(&self) -> u64 {
        self.system
    }

    /// The timeline the database writes on now.
    #[must_use]
    pub const fn current(&self) -> u32 {
        self.current
    }

    /// Parse the history file Postgres keeps for `current` on the cluster `system`.
    ///
    /// # Errors
    ///
    /// [`TimelineError::Malformed`] when a line names no timeline or no position.
    pub fn parse(system: u64, current: u32, content: &str) -> Result<Self, TimelineError> {
        let ended = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                let malformed = || TimelineError::Malformed(line.to_owned());
                let mut fields = line.split_whitespace();
                let timeline = fields
                    .next()
                    .and_then(|field| field.parse::<u32>().ok())
                    .ok_or_else(malformed)?;
                let end = fields.next().and_then(parse_lsn).ok_or_else(malformed)?;
                Ok((timeline, end))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            system,
            current,
            ended,
        })
    }

    /// Whether `position` is on this cluster, on the current timeline or on an ancestor at or before its end.
    #[must_use]
    pub fn contains(&self, position: Position) -> bool {
        position.system == self.system
            && (position.timeline == self.current
                || self.ended.iter().any(|&(timeline, end)| {
                    timeline == position.timeline && position.at.commit_lsn() <= PgLsn(end)
                }))
    }

    /// `at` as a cursor stamped with the cluster and the current timeline.
    #[must_use]
    pub fn stamp(&self, at: PgCommitPosition) -> Vec<u8> {
        Position {
            system: self.system,
            timeline: self.current,
            at,
        }
        .to_cursor_bytes()
    }
}

/// Read `X/Y`, the way Postgres prints a position.
fn parse_lsn(text: &str) -> Option<u64> {
    let (high, low) = text.split_once('/')?;
    let high = u32::from_str_radix(high, 16).ok()?;
    let low = u32::from_str_radix(low, 16).ok()?;
    Some(u64::from(high) << 32 | u64::from(low))
}

/// `database_url` as a conninfo that opens a logical replication connection.
fn replication_conninfo(database_url: &str) -> String {
    if database_url.starts_with("postgres://") || database_url.starts_with("postgresql://") {
        let separator = if database_url.contains('?') { '&' } else { '?' };
        format!("{database_url}{separator}replication=database")
    } else {
        format!("{database_url} replication=database")
    }
}

/// Read the timeline history over a replication connection, which needs only the `REPLICATION` attribute.
///
/// # Errors
///
/// [`TimelineError`] when the connection, either command, or the parse fails.
pub async fn read_history(database_url: &str) -> Result<TimelineHistory, TimelineError> {
    let conninfo = replication_conninfo(database_url);
    tokio::task::spawn_blocking(move || read_history_blocking(&conninfo))
        .await
        .map_err(|err| TimelineError::Join(err.to_string()))?
}

/// The read itself. The replication client's commands are synchronous.
fn read_history_blocking(conninfo: &str) -> Result<TimelineHistory, TimelineError> {
    let mut conn = PgReplicationConnection::connect(conninfo)
        .map_err(|err| TimelineError::Connect(err.to_string()))?;
    let identified = conn
        .identify_system()
        .map_err(|err| TimelineError::Query(err.to_string()))?;
    let named = |column: i32, what: &str| {
        identified
            .get_value(0, column)
            .ok_or_else(|| TimelineError::Malformed(format!("IDENTIFY_SYSTEM named no {what}")))
    };
    let reported = named(0, "system identifier")?;
    let Ok(system) = reported.parse::<u64>() else {
        return Err(TimelineError::Malformed(reported));
    };
    let reported = named(1, "timeline")?;
    let Ok(current) = reported.parse::<u32>() else {
        return Err(TimelineError::Malformed(reported));
    };
    if current == FIRST_TIMELINE {
        return Ok(TimelineHistory::first(system));
    }
    let history = conn
        .exec(&format!("TIMELINE_HISTORY {current}"))
        .map_err(|err| TimelineError::Query(err.to_string()))?;
    let content = history.get_bytes(0, 1).ok_or_else(|| {
        TimelineError::Malformed(format!("TIMELINE_HISTORY {current} returned no content"))
    })?;
    TimelineHistory::parse(system, current, &String::from_utf8_lossy(content))
}

#[cfg(test)]
mod tests {
    use super::{Position, TimelineHistory, replication_conninfo};
    use subql::{PgCommitPosition, PgLsn};

    /// The history Postgres 18.6 wrote for timeline 3 after two promotions,
    /// with the reason column it carries.
    const TWICE_PROMOTED: &str = "1\t0/3034A08\tno recovery target specified\n\n\
                                  2\t0/5000000\tno recovery target specified\n";

    /// The cluster every history here belongs to.
    const CLUSTER: u64 = 7_688_797_528_129_531_953;

    fn at(timeline: u32, lsn: u64) -> Position {
        Position {
            system: CLUSTER,
            timeline,
            at: PgCommitPosition::new(PgLsn(lsn), 1),
        }
    }

    #[test]
    fn an_ancestor_holds_positions_up_to_where_it_ended_and_no_further() {
        let history = TimelineHistory::parse(CLUSTER, 3, TWICE_PROMOTED).expect("parse");
        let first_end = 0x0303_4A08;
        assert!(history.contains(at(1, first_end)));
        assert!(!history.contains(at(1, first_end + 1)));
        assert!(history.contains(at(2, 0x0500_0000)));
        assert!(!history.contains(at(2, 0x0500_0001)));
        assert!(history.contains(at(3, u64::MAX)));
        assert!(
            !history.contains(at(4, 0)),
            "a timeline this history never had"
        );
    }

    #[test]
    fn a_never_promoted_database_holds_every_first_timeline_position_and_nothing_else() {
        let history = TimelineHistory::first(CLUSTER);
        assert!(history.contains(at(1, u64::MAX)));
        assert!(!history.contains(at(2, 1)));
    }

    #[test]
    fn a_position_from_another_cluster_is_outside_every_history() {
        let other = |timeline, lsn| Position {
            system: CLUSTER + 1,
            ..at(timeline, lsn)
        };
        assert!(!TimelineHistory::first(CLUSTER).contains(other(1, 0x10)));
        let history = TimelineHistory::parse(CLUSTER, 3, TWICE_PROMOTED).expect("parse");
        assert!(!history.contains(other(3, 0x10)));
        assert!(!history.contains(other(1, 0x10)));
    }

    #[test]
    fn a_line_without_a_position_is_refused() {
        assert!(TimelineHistory::parse(CLUSTER, 2, "1\tnot-a-position\treason").is_err());
        assert!(TimelineHistory::parse(CLUSTER, 2, "one\t0/1\treason").is_err());
    }

    #[test]
    fn a_stamped_cursor_reads_back_and_sorts_by_timeline_first() {
        let history = TimelineHistory::parse(CLUSTER, 2, "1\t0/10\treason").expect("parse");
        let stamped = history.stamp(PgCommitPosition::new(PgLsn(0x20), 1));
        assert_eq!(Position::from_cursor_bytes(&stamped), Some(at(2, 0x20)));
        assert!(at(1, u64::MAX).to_cursor_bytes() < at(2, 0).to_cursor_bytes());
    }

    /// Byte order is commit order, the ordinal breaking ties within one commit, which is what `advance_cursor` compares.
    #[test]
    fn cursor_bytes_sort_by_commit_then_ordinal() {
        let cursor = |lsn: u64, ordinal: u64| {
            TimelineHistory::first(CLUSTER).stamp(PgCommitPosition::new(PgLsn(lsn), ordinal))
        };
        assert!(cursor(0x100, 2) < cursor(0x101, 1));
        assert!(cursor(0x100, 1) < cursor(0x100, 2));
        assert!(cursor(0xFF, 256) < cursor(0x100, 0));
    }

    #[test]
    fn every_earlier_layout_reads_as_no_position() {
        assert_eq!(Position::from_cursor_bytes(&7_u64.to_be_bytes()), None);
        let timeline_only = [&2_u32.to_be_bytes()[..], &7_u64.to_be_bytes()].concat();
        assert_eq!(Position::from_cursor_bytes(&timeline_only), None);
        let single_lsn = [
            &CLUSTER.to_be_bytes()[..],
            &1_u32.to_be_bytes(),
            &7_u64.to_be_bytes(),
        ]
        .concat();
        assert_eq!(Position::from_cursor_bytes(&single_lsn), None);
        assert_eq!(Position::from_cursor_bytes(&[]), None);
    }

    #[test]
    fn both_conninfo_spellings_ask_for_a_replication_connection() {
        assert_eq!(
            replication_conninfo("postgres://u:p@h:5432/db"),
            "postgres://u:p@h:5432/db?replication=database"
        );
        assert_eq!(
            replication_conninfo("postgresql://h/db?sslmode=disable"),
            "postgresql://h/db?sslmode=disable&replication=database"
        );
        assert_eq!(
            replication_conninfo("host=h dbname=db"),
            "host=h dbname=db replication=database"
        );
    }
}
