//! The one queryable condition every platform reports for local work that
//! has not reached the server (R31 step 2).

use serde::{Deserialize, Serialize};

use crate::UnsyncedWrite;

/// Local work that would become unrecoverable if this device's data were
/// deleted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingWork {
    /// Writes captured locally that no server has confirmed durable yet, each
    /// named by its writer and sequence and the major it was captured under,
    /// an older major's writes included.
    pub unsynced: Vec<UnsyncedWrite>,
    /// Content files still waiting in the upload outbox.
    #[serde(default)]
    pub content_files: u64,
    /// Lost content files as hex identities, recorded until acknowledged and never pending.
    #[serde(default)]
    pub retired_files: Vec<String>,
    /// Files a rebuild held for an older major's drain (R31).
    #[serde(default)]
    pub held_files: u64,
}

impl PendingWork {
    /// Whether deleting local data would discard nothing, `retired_files` aside.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.unsynced.is_empty() && self.content_files == 0 && self.held_files == 0
    }

    /// The number of pending writes and content files, held files included.
    #[must_use]
    pub fn len(&self) -> u64 {
        u64::try_from(self.unsynced.len())
            .unwrap_or(u64::MAX)
            .saturating_add(self.content_files)
            .saturating_add(self.held_files)
    }
}

#[cfg(test)]
mod tests {
    use super::PendingWork;

    /// A loss alone is not pending, so the deletion guard may pass.
    #[test]
    fn retired_files_alone_are_not_pending() {
        let work = PendingWork {
            retired_files: vec!["a file".to_owned()],
            ..PendingWork::default()
        };
        assert!(work.is_empty());
    }

    /// A file held for an older major's drain is pending like any unsent file.
    #[test]
    fn held_files_keep_the_work_non_empty() {
        let files = PendingWork {
            held_files: 1,
            ..PendingWork::default()
        };
        assert!(!files.is_empty());
        assert_eq!(files.len(), 1);
    }
}
