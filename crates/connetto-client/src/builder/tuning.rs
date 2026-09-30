//! The tuning half of a client build.

use core::time::Duration;

use crate::{
    DEFAULT_GRACE, DEFAULT_RESIDUAL_THRESHOLD, DEFAULT_RESTED_STATISTICS_CAP, DEFAULT_TRIM_BUDGET,
    DEFAULT_TRIM_THRESHOLD, MAX_GRACE, ResidualPass,
};

/// The tuning levers a build carries, with their safe bounds applied at the
/// setter.
///
/// A value past a bound is clamped rather than refused, because the intent
/// (trim earlier, pass earlier, keep longer) survives the clamp while the
/// unsafe half of it does not.
#[derive(Clone, Copy, Debug)]
pub struct SyncTuning {
    trim_threshold: u8,
    trim_budget: u32,
    rested_statistics_cap: usize,
    residual_threshold: u64,
    residual_pass: ResidualPass,
    watch_grace: Duration,
}

impl Default for SyncTuning {
    fn default() -> Self {
        Self {
            trim_threshold: DEFAULT_TRIM_THRESHOLD,
            trim_budget: DEFAULT_TRIM_BUDGET,
            rested_statistics_cap: DEFAULT_RESTED_STATISTICS_CAP,
            residual_threshold: DEFAULT_RESIDUAL_THRESHOLD,
            residual_pass: ResidualPass::default(),
            watch_grace: DEFAULT_GRACE,
        }
    }
}

impl SyncTuning {
    /// The freelist percentage that arms the trimming pass. Clamped to `100`,
    /// because a threshold above it would arm the pass on an empty freelist.
    #[must_use]
    pub fn with_trim_threshold(mut self, threshold: u8) -> Self {
        self.trim_threshold = threshold.min(100);
        self
    }

    /// The pages one `incremental_vacuum` step reclaims.
    #[must_use]
    pub fn with_trim_budget(mut self, pages: u32) -> Self {
        self.trim_budget = pages;
        self
    }

    /// The cap on distinct rested statistics the aggregate table keeps.
    #[must_use]
    pub fn with_rested_statistics_cap(mut self, cap: usize) -> Self {
        self.rested_statistics_cap = cap;
        self
    }

    /// The applied rows that arm the residual pass. Clamped to at least `1`,
    /// because a threshold of zero would arm it on every apply.
    #[must_use]
    pub fn with_residual_threshold(mut self, rows: u64) -> Self {
        self.residual_threshold = rows.max(1);
        self
    }

    /// Who runs the residual pass at the crossing.
    #[must_use]
    pub fn with_residual_pass(mut self, pass: ResidualPass) -> Self {
        self.residual_pass = pass;
        self
    }

    /// The default grace a live query outlives its last handle for. Clamped
    /// to [`MAX_GRACE`], because past the ceiling a grace is a pin by
    /// definition and a pin is said with [`ConnettoClient::pin`](crate::live::ConnettoClient::pin).
    #[must_use]
    pub fn with_watch_grace(mut self, grace: Duration) -> Self {
        self.watch_grace = grace.min(MAX_GRACE);
        self
    }

    /// The trimming threshold.
    #[must_use]
    pub const fn trim_threshold(&self) -> u8 {
        self.trim_threshold
    }

    /// The trimming budget.
    #[must_use]
    pub const fn trim_budget(&self) -> u32 {
        self.trim_budget
    }

    /// The rested statistics cap.
    #[must_use]
    pub const fn rested_statistics_cap(&self) -> usize {
        self.rested_statistics_cap
    }

    /// The residual threshold.
    #[must_use]
    pub const fn residual_threshold(&self) -> u64 {
        self.residual_threshold
    }

    /// The residual pass.
    #[must_use]
    pub const fn residual_pass(&self) -> ResidualPass {
        self.residual_pass
    }

    /// The default watch grace.
    #[must_use]
    pub const fn watch_grace(&self) -> Duration {
        self.watch_grace
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_threshold_clamps_to_100_and_keeps_in_range() {
        assert_eq!(
            SyncTuning::default()
                .with_trim_threshold(255)
                .trim_threshold(),
            100
        );
        assert_eq!(
            SyncTuning::default()
                .with_trim_threshold(50)
                .trim_threshold(),
            50
        );
    }

    #[test]
    fn residual_threshold_never_falls_below_one() {
        assert_eq!(
            SyncTuning::default()
                .with_residual_threshold(0)
                .residual_threshold(),
            1
        );
        assert_eq!(
            SyncTuning::default()
                .with_residual_threshold(500)
                .residual_threshold(),
            500
        );
    }

    #[test]
    fn watch_grace_clamps_to_the_pin_ceiling() {
        assert_eq!(
            SyncTuning::default()
                .with_watch_grace(MAX_GRACE + Duration::from_secs(1))
                .watch_grace(),
            MAX_GRACE
        );
        assert_eq!(
            SyncTuning::default()
                .with_watch_grace(Duration::from_secs(1))
                .watch_grace(),
            Duration::from_secs(1)
        );
    }
}
