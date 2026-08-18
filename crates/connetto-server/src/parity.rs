//! Both executors on one question, so a divergence is caught rather than
//! delivered.
//!
//! The design rests on one claim: a single policy source compiles to two
//! executors that must not disagree. Postgres row-level security answers the
//! snapshot, the model answers the change path, and a divergence reaches a
//! client as a row that is there and then is not, with nothing in a log to say
//! why. Nothing else in this tree can notice that, because the two are only
//! ever asked separately.
//!
//! A disagreement increments [`VISIBILITY_DISAGREEMENTS`] and writes a warning
//! naming the row and both answers. **Every Docker-backed suite asserts that
//! counter is zero**, so a real divergence fails a build rather than sitting in
//! a log nobody reads, and a false one cannot stall delivery for anybody.
//!
//! # It compares the row as it is now, and only that
//!
//! Row-level security reads the live table, so it can only answer about a row as
//! it is now. For a deletion the row is gone and it answers no for everyone, and
//! about the previous version of an update it cannot answer at all.
//!
//! Since R6 the change path asks about both versions, and it asks them through
//! `subql::visibility::transition::transitions`, which builds the two row views
//! itself. A policy wrapper therefore cannot tell which version a question is
//! about: [`RowView`] carries a table and a cell reader and nothing that names
//! the image. **So the comparison sits where the versions are still told apart**,
//! at the two delivery sites, and is asked only about the current row. What was
//! shipped is recoverable there without asking twice, because a watcher is told
//! to deliver exactly when the shipped policy allowed the current row.
//!
//! Before R6 this was a [`VisibilityPolicy`] wrapper comparing every `may_see`.
//! That was right while only one version was ever asked about and would report a
//! difference on every previous-version question now.
//!
//! # What it does not compare
//!
//! Writes. Since R50 `RlsAuth::may_write` answers the two verbs that carry an
//! existing row and passes the insert and resulting-row halves through, whose
//! gate is the database write that follows them. So a comparison would disagree
//! on that pass-through pair by construction, and the counter would stop meaning
//! anything. The two answered verbs reach it from the minting path alone, which
//! this wrapper does not sit on.
//!
//! Deletions, and truncates. Neither has a current row, so there is nothing
//! row-level security can be asked, and the site skips the comparison rather
//! than counting an answer nobody gave.

use std::fmt::Display;
use std::pin::Pin;
use std::sync::Arc;

use connetto_core::auth::Principal;
use subql::backend::Postgres;
use subql::visibility::{RowView, Verdict, VisibilityPolicy};

use crate::auth::RlsAuth;
use crate::capability::CapabilityKey;
use crate::counters::{VISIBILITY_DISAGREEMENTS, add};

/// A second executor asked about the row as it is now, alongside the one that
/// delivers.
///
/// Type-erased on purpose. The session manager is generic over the deployment's
/// identity type while row-level security answers only for the reference one,
/// and the row arrives as whichever view the change path built. Erasure costs
/// one boxed future per compared event, paid only by a run that asked for the
/// comparison.
pub trait SecondOpinion<Id, Key>: Send + Sync {
    /// Compare this executor's answer about `row` against `shipped`, counting
    /// and naming every watcher the two answered differently about.
    ///
    /// Reaching no answer is not a disagreement and is not counted: it says
    /// nothing about the shipped answer, and counting it would make a Postgres
    /// blip read as a policy divergence.
    fn compare<'a>(
        &'a self,
        row: &'a (dyn RowView<Backend = Postgres> + Sync),
        watchers: &'a [Arc<Principal<Id, Key>>],
        shipped: &'a [Verdict],
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

impl<Key: CapabilityKey> SecondOpinion<String, Key> for RlsAuth<Key> {
    fn compare<'a>(
        &'a self,
        row: &'a (dyn RowView<Backend = Postgres> + Sync),
        watchers: &'a [Arc<Principal<String, Key>>],
        shipped: &'a [Verdict],
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let mut second = Vec::new();
            Verdict::reset(&mut second, watchers.len());
            if let Err(err) = self.may_see(row, watchers, &mut second).await {
                tracing::debug!(
                    error = %err,
                    "the second opinion could not answer, so nothing was compared"
                );
                return;
            }
            report(row.table_id(), watchers, shipped, &second);
        })
    }
}

/// Count and name every watcher the two answered differently about.
///
/// Named rather than counted alone: a count says the design's central claim
/// broke and a name says where, and whoever reads the warning has to be able to
/// reach the row.
fn report<Id: Display, Key>(
    table: subql::TableId,
    watchers: &[Arc<Principal<Id, Key>>],
    shipped: &[Verdict],
    second: &[Verdict],
) {
    for ((watcher, ours), theirs) in watchers.iter().zip(shipped).zip(second) {
        if ours == theirs {
            continue;
        }
        add(&VISIBILITY_DISAGREEMENTS, 1);
        tracing::warn!(
            table = table,
            caller = watcher.identity().map_or("<none>".to_owned(), |id| id.user_id.to_string()),
            shipped = ?ours,
            row_level_security = ?theirs,
            "the two executors disagreed about one row, which is the divergence \
             one policy source compiled to both exists to prevent"
        );
    }
}
