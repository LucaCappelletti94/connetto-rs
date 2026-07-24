//! Multi-page leader election for the dedicated DB worker.
//!
//! Every page of one app instance calls [`join`] with the same leader lock
//! name. Web Locks serializes those requests across all same-origin contexts
//! (windows, tabs, workers alike), so exactly one page holds the lock at a
//! time: the leader. The leader spawns and owns the dedicated DB worker, the
//! only context kind with OPFS sync access handles. Every other page keeps
//! its request queued and does nothing but wait.
//!
//! Handover is the browser's own liveness, not a heartbeat: when the leader's
//! context dies the browser releases the lock and terminates its child
//! worker, the next queued request is granted, and that new leader spawns a
//! replacement worker. Tabs converge on it through the reconnect machinery,
//! which is the failover path proven in `tests/failover.rs`. `tests/election.rs`
//! proves the election leg: two candidates race, one leads, and dropping the
//! leader promotes the survivor, which serves the tab a row written while no
//! worker existed.
//!
//! Being a leader is orthogonal to being a tab client: a page connects a tab
//! over its own wire channel to whatever worker currently exists (see
//! [`tab_wire_factory`](crate::workers::tab_wire_factory)) whether it leads or
//! follows.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen_futures::spawn_local;
use web_sys::{ErrorEvent, Event, Worker};

use crate::locks::{HeldLock, hold_lock};
use crate::workers::spawn_db_worker;

/// What the winning page holds: the leader lock and the DB worker it spawned.
/// Kept alive by the owning [`Membership`] for the leader's whole tenure.
struct Leadership {
    held: HeldLock,
    worker: Worker,
}

/// A page's standing in the topology. While it lives, the page is a
/// leadership candidate.
///
/// Dropping it resigns. A leader terminates its worker and releases the lock,
/// which promotes a surviving candidate. A follower still queued stops
/// competing, but the browser only cancels a not-yet-granted lock request on
/// context death, so a dropped follower may briefly win and release again
/// before the next candidate takes over. Real pages resign by dying, where
/// the browser does all of this natively.
pub struct Membership {
    resigned: Rc<Cell<bool>>,
    leadership: Rc<RefCell<Option<Leadership>>>,
}

impl Membership {
    /// Whether this page currently holds leadership, so it owns the DB worker.
    /// Follows the election asynchronously: false until a freshly joined page
    /// wins, false again once it resigns.
    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.leadership.borrow().is_some()
    }
}

impl Drop for Membership {
    fn drop(&mut self) {
        self.resigned.set(true);
        // try_borrow_mut keeps the drop infallible. No borrow is ever held
        // across an await, so this only fails if a drop races itself, which
        // it cannot on the single-threaded wasm executor.
        if let Ok(mut slot) = self.leadership.try_borrow_mut()
            && let Some(leadership) = slot.take()
        {
            leadership.worker.terminate();
            leadership.held.release();
        }
    }
}

/// Join the topology as a leadership candidate. Returns at once, the election
/// runs in the background.
///
/// `leader_lock` MUST be identical across every page of one app instance, and
/// `glue_url` names the wasm-bindgen glue module `db-worker.js` imports (see
/// [`spawn_db_worker`]).
#[must_use]
pub fn join(leader_lock: &str, glue_url: &str) -> Membership {
    let resigned = Rc::new(Cell::new(false));
    let leadership = Rc::new(RefCell::new(None));
    spawn_local(run_election(
        leader_lock.to_owned(),
        glue_url.to_owned(),
        Rc::clone(&resigned),
        Rc::clone(&leadership),
    ));
    Membership {
        resigned,
        leadership,
    }
}

/// Park until this page wins the leader lock, then spawn the DB worker and
/// hand leadership to the [`Membership`].
async fn run_election(
    leader_lock: String,
    glue_url: String,
    resigned: Rc<Cell<bool>>,
    leadership: Rc<RefCell<Option<Leadership>>>,
) {
    // Resolves immediately if the lock is free, otherwise when the current
    // leader's context dies and this request is next in the queue.
    let held = hold_lock(&leader_lock).await;
    if resigned.get() {
        // Resigned while queued: release at once so the next candidate wins.
        held.release();
        return;
    }
    match spawn_db_worker(&glue_url) {
        Ok(worker) => {
            log_worker_errors(&worker);
            leadership.borrow_mut().replace(Leadership { held, worker });
        }
        Err(err) => {
            web_sys::console::error_1(
                &format!("leader election: spawning the db worker failed: {err:?}").into(),
            );
            // Releasing leadership lets another candidate try.
            held.release();
        }
    }
}

/// Surface a DB worker's load or runtime errors to the console: a worker's
/// own console is not always visible to the page that spawned it.
fn log_worker_errors(worker: &Worker) {
    let on_error = Closure::<dyn FnMut(Event)>::new(|event: Event| {
        let detail = event
            .dyn_ref::<ErrorEvent>()
            .map_or_else(|| "no error detail".to_owned(), ErrorEvent::message);
        web_sys::console::error_1(&format!("db worker error: {detail}").into());
    });
    worker.set_onerror(Some(on_error.as_ref().unchecked_ref()));
    // The handler lives for the worker's whole life.
    on_error.forget();
}
