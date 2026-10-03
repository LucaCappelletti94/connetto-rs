//! The assembly path for a [`SessionManager`]. The required collaborators go
//! on `new`, the seams tests replace go on setters, and `build` returns the
//! manager.
//!
//! This module stays out of the public surface without the `test-seams`
//! feature. A production build has no public way to reach the builder, and
//! the crate-internal callers reach it through the lib's re-export.

use std::sync::Arc;

use connetto_core::auth::Principal;
use connetto_core::traits::{ContentTicketSigner, HandshakeAuthority};
use subql::ParserDB;
use subql::backend::Postgres;
use subql::visibility::VisibilityPolicy;

use crate::guard::RequestGuard;
use crate::materializer::{Materializer, ReadConnector, RuntimeWritableCatalog};
use crate::openfga::StoreUpkeep;
use crate::oplog::{InMemoryOplog, Oplog};
use crate::parity::SecondOpinion;
use crate::reexec::FailedRead;
use crate::session::{NoSigner, SessionConfig, SnapshotSource};
use crate::watermark_schema::ConnettoWatermarkSchema;
use crate::write_target::PgWriteTarget;

/// Assembles one [`SessionManager`](crate::session::SessionManager).
///
/// `new` takes the six collaborators a manager cannot run without, the
/// materializer, the snapshot source, the visibility policy, the handshake
/// authority, the manager's own re-execution connector, and the write
/// target. Everything a deployment tunes goes on a setter, and `build`
/// hands the value to the one internal assembly every construction shares.
///
/// The connector the manager reads re-executions through is its own value of
/// the materializer's connector type. The engine keeps the copy its read
/// mode took at materializer construction, so the two sides are the
/// deployment's to wire, a shared handle or two reads of one pool.
pub struct ManagerBuilder<Snap, Auth, W, C, O, S>
where
    Snap: SnapshotSource,
    Auth: VisibilityPolicy<Watcher = Arc<Principal>, Backend = Postgres>,
    W: ConnettoWatermarkSchema<Id = String>,
    C: ReadConnector,
    C::Error: FailedRead,
    O: Oplog,
    S: ContentTicketSigner,
{
    materializer: Materializer<ParserDB, RuntimeWritableCatalog, C>,
    snapshot_source: Snap,
    auth: Auth,
    authority: Arc<dyn HandshakeAuthority>,
    connector: C,
    target: PgWriteTarget<W>,
    guard: Option<Arc<RequestGuard<String>>>,
    session: Option<SessionConfig>,
    oplog: O,
    upkeep: Option<Arc<dyn StoreUpkeep>>,
    signer: S,
    withdrawal_source: Option<Snap>,
    second_opinion: Option<Arc<dyn SecondOpinion<String, String>>>,
}

impl<Snap, Auth, W, C> ManagerBuilder<Snap, Auth, W, C, InMemoryOplog, NoSigner>
where
    Snap: SnapshotSource,
    Auth: VisibilityPolicy<Watcher = Arc<Principal>, Backend = Postgres>,
    W: ConnettoWatermarkSchema<Id = String>,
    C: ReadConnector,
    C::Error: FailedRead,
{
    /// Assemble over the required collaborators, with a default in-memory
    /// oplog, the default counters, and the default per-session settings.
    #[must_use]
    pub fn new(
        materializer: Materializer<ParserDB, RuntimeWritableCatalog, C>,
        snapshot_source: Snap,
        auth: Auth,
        authority: Arc<dyn HandshakeAuthority>,
        connector: C,
        target: PgWriteTarget<W>,
    ) -> Self {
        Self {
            materializer,
            snapshot_source,
            auth,
            authority,
            connector,
            target,
            guard: None,
            session: None,
            oplog: InMemoryOplog::default(),
            upkeep: None,
            signer: NoSigner,
            withdrawal_source: None,
            second_opinion: None,
        }
    }
}

impl<Snap, Auth, W, C, O, S> ManagerBuilder<Snap, Auth, W, C, O, S>
where
    Snap: SnapshotSource,
    Auth: VisibilityPolicy<Watcher = Arc<Principal>, Backend = Postgres>,
    W: ConnettoWatermarkSchema<Id = String>,
    C: ReadConnector,
    C::Error: FailedRead,
    O: Oplog,
    S: ContentTicketSigner,
{
    /// The counters the server meters and tallies against.
    #[must_use]
    pub fn with_guard(mut self, guard: Arc<RequestGuard<String>>) -> Self {
        self.guard = Some(guard);
        self
    }

    /// The per-session server configuration.
    #[must_use]
    pub fn with_session(mut self, session: SessionConfig) -> Self {
        self.session = Some(session);
        self
    }

    /// The oplog the reconnect catchup reads from.
    #[must_use]
    pub fn with_oplog<NewO: Oplog>(self, oplog: NewO) -> ManagerBuilder<Snap, Auth, W, C, NewO, S> {
        let Self {
            materializer,
            snapshot_source,
            auth,
            authority,
            connector,
            target,
            guard,
            session,
            upkeep,
            signer,
            withdrawal_source,
            second_opinion,
            ..
        } = self;
        ManagerBuilder {
            materializer,
            snapshot_source,
            auth,
            authority,
            connector,
            target,
            guard,
            session,
            oplog,
            upkeep,
            signer,
            withdrawal_source,
            second_opinion,
        }
    }

    /// Brings the authorization store level with each changed row before that
    /// row reaches anybody.
    #[must_use]
    pub fn with_upkeep(mut self, upkeep: Arc<dyn StoreUpkeep>) -> Self {
        self.upkeep = Some(upkeep);
        self
    }

    /// The deployment's content ticket signer, called after a successful
    /// visibility check to mint a signed URL the caller may use at the file
    /// server.
    #[must_use]
    pub fn with_signer<NewS: ContentTicketSigner>(
        self,
        signer: NewS,
    ) -> ManagerBuilder<Snap, Auth, W, C, O, NewS> {
        let Self {
            materializer,
            snapshot_source,
            auth,
            authority,
            connector,
            target,
            guard,
            session,
            oplog,
            upkeep,
            withdrawal_source,
            second_opinion,
            ..
        } = self;
        ManagerBuilder {
            materializer,
            snapshot_source,
            auth,
            authority,
            connector,
            target,
            guard,
            session,
            oplog,
            upkeep,
            signer,
            withdrawal_source,
            second_opinion,
        }
    }

    /// Reads move-out withdrawals on the privileged pool, as the source the
    /// deployment reads them through.
    #[must_use]
    pub fn with_withdrawal_source(mut self, source: Snap) -> Self {
        self.withdrawal_source = Some(source);
        self
    }

    /// Asks a second executor about every current row alongside the one that
    /// delivers, so a divergence between them is counted and named.
    #[must_use]
    pub fn with_second_opinion(mut self, second: Arc<dyn SecondOpinion<String, String>>) -> Self {
        self.second_opinion = Some(second);
        self
    }

    /// Build the manager.
    #[must_use]
    pub fn build(self) -> Arc<crate::session::ConnettoManager<Snap, Auth, W, C, O, S>> {
        let guard = self
            .guard
            .unwrap_or_else(|| Arc::new(RequestGuard::default()));
        let session = self.session.unwrap_or_default();
        crate::session::assemble_manager(
            self.materializer,
            self.snapshot_source,
            self.auth,
            self.authority,
            self.connector,
            self.oplog,
            self.target,
            guard,
            session,
            self.upkeep,
            self.signer,
            self.withdrawal_source,
            self.second_opinion,
        )
    }
}
