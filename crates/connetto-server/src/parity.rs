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
//! [`ParityAuth`] asks both and delivers on the shipped one. A disagreement
//! increments [`VISIBILITY_DISAGREEMENTS`] and writes a warning naming the row
//! and both answers. **Every Docker-backed suite asserts that counter is
//! zero**, so a real divergence fails a build rather than sitting in a log
//! nobody reads, and a false one cannot stall delivery for anybody.
//!
//! # What it compares, and why that is every call today
//!
//! Row-level security reads the live table, so it can only answer about a row
//! as it is now. That would make it useless for a deletion, where the row is
//! gone and it answers no for everyone, and for the previous version of an
//! update, which it cannot see at all.
//!
//! Neither is asked today. `SessionManager::dispatch_event` asks `may_see` only
//! when `EventRow::current` yields a view, which a deletion never does, and
//! nothing anywhere asks about a previous version because the two-check form is
//! R6 and is unbuilt. So comparing every `may_see` is exactly right now and
//! stops being right the day R6 lands, which is why this says so here rather
//! than leaving it to be discovered.
//!
//! # What it does not compare
//!
//! Writes. `RlsAuth::may_write` allows unconditionally by design, so comparing
//! it would report a disagreement on every genuine refusal and the counter
//! would stop meaning anything.

use std::fmt::Display;
use std::sync::Arc;

use connetto_core::auth::Principal;
use openfga_client::tonic::body::Body;
use openfga_client::tonic::client::GrpcService;
use openfga_client::tonic::codegen::{Body as ResponseBody, Bytes, StdError};
use subql::backend::Postgres;
use subql::visibility::openfga::OpenFgaError;
use subql::visibility::{RowView, RowWrite, Verdict, VisibilityPolicy};

use crate::auth::RlsAuth;
use crate::counters::{VISIBILITY_DISAGREEMENTS, add};
use crate::openfga::FgaAuth;

/// The shipped executor, with row-level security asked alongside it as a second
/// opinion.
///
/// Not what a deployment serves through by default. It costs one Postgres round
/// trip per watcher per changed row, which is the whole cost R5b removed, so it
/// is for a run that wants the two compared rather than for one that wants to
/// be fast.
pub struct ParityAuth<T> {
    shipped: FgaAuth<String, String, T>,
    second_opinion: RlsAuth,
}

impl<T> ParityAuth<T> {
    /// Deliver on `shipped`, and check `second_opinion` against it.
    ///
    /// The order is the guarantee: the shipped answer is the one written into
    /// the caller's buffer, and nothing row-level security does can change it,
    /// including failing.
    #[must_use]
    pub const fn new(shipped: FgaAuth<String, String, T>, second_opinion: RlsAuth) -> Self {
        Self {
            shipped,
            second_opinion,
        }
    }

    /// The shipped executor, for a caller that needs it directly, such as one
    /// building the store upkeep from the same index.
    #[must_use]
    pub const fn shipped(&self) -> &FgaAuth<String, String, T> {
        &self.shipped
    }
}

impl<T> core::fmt::Debug for ParityAuth<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ParityAuth").finish_non_exhaustive()
    }
}

impl<T> VisibilityPolicy for ParityAuth<T>
where
    T: GrpcService<Body> + Clone + Send + Sync + 'static,
    T::Error: Into<StdError>,
    T::ResponseBody: ResponseBody<Data = Bytes> + Send + 'static,
    <T::ResponseBody as ResponseBody>::Error: Into<StdError> + Send,
    T::Future: Send,
{
    type Watcher = Arc<Principal>;
    type Error = OpenFgaError;
    type Backend = Postgres;

    async fn may_see<R>(
        &self,
        row: &R,
        watchers: &[Self::Watcher],
        verdicts: &mut [Verdict],
    ) -> Result<(), OpenFgaError>
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        // The shipped answer first and into the caller's own buffer, so what is
        // delivered does not depend on anything below.
        self.shipped.may_see(row, watchers, verdicts).await?;

        let mut second = Vec::new();
        Verdict::reset(&mut second, watchers.len());
        if let Err(err) = self
            .second_opinion
            .may_see(row, watchers, &mut second)
            .await
        {
            // Row-level security failing to answer is not a disagreement. It
            // says nothing about the shipped answer, and counting it would make
            // a Postgres blip read as a policy divergence.
            tracing::debug!(
                error = %err,
                "the second opinion could not answer, so nothing was compared"
            );
            return Ok(());
        }
        report(row.table_id(), watchers, verdicts, &second);
        Ok(())
    }

    /// Answered by the shipped executor alone.
    ///
    /// Row-level security allows every write unconditionally, so a comparison
    /// here would report a disagreement whenever the shipped policy correctly
    /// refuses one.
    fn may_write<R>(
        &self,
        write: RowWrite<'_, R>,
        watcher: &Self::Watcher,
    ) -> impl Future<Output = Result<Verdict, OpenFgaError>> + Send
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        self.shipped.may_write(write, watcher)
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
