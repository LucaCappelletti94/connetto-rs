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
use wasm_bindgen::JsValue;
use wasm_bindgen::closure::Closure;
use wasm_bindgen_futures::spawn_local;
use web_sys::{BroadcastChannel, ErrorEvent, Event, MessageEvent, Worker};

use crate::locks::{HeldLock, hold_lock};
use crate::unlock::AccountChoice;
use crate::workers::{WorkerBootstrap, spawn_db_worker};

/// What the winning page holds: the leader lock and the DB worker it spawned.
/// Kept alive by the owning [`Membership`] for the leader's whole tenure.
struct Leadership {
    held: HeldLock,
    worker: Worker,
}

/// How to launch a replacement worker, retained because a switch replaces the
/// one this page spawned.
struct Launch {
    glue_url: String,
    bootstrap: WorkerBootstrap,
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
    launch: Rc<Launch>,
    /// The switch-request listener, alive for as long as this page competes.
    _switches: BroadcastChannel,
}

impl Membership {
    /// Whether this page currently holds leadership, so it owns the DB worker.
    /// Follows the election asynchronously: false until a freshly joined page
    /// wins, false again once it resigns.
    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.leadership.borrow().is_some()
    }

    /// Sign in as `account`, which must be one the worker offered.
    ///
    /// The switch replaces the DB worker: the replacement boots against the named
    /// account exactly as a cold start does, and every tab converges on it through
    /// the same ready handshake that leader failover uses. That is why it needs no
    /// interactive login, since the account's credential is already stored, and
    /// why it costs one gate ceremony, since the gate is one prompt per worker
    /// boot.
    ///
    /// # Errors
    ///
    /// [`JsValue`] if a replacement worker cannot be spawned, or if the request
    /// cannot be broadcast to the leader.
    pub fn switch_account(&self, account: &str) -> Result<(), JsValue> {
        self.reboot_as(AccountChoice::Named(account.to_owned()))
    }

    /// Sign in as somebody new, keeping every account already signed in.
    ///
    /// This is what puts a second account on the device, and it is the only path
    /// that does: a switch names a credential that is already stored, and signing
    /// the current account out to make room would delete the very credential that
    /// would have made it the second account. The replacement worker addresses no
    /// stored credential, so it runs an interactive login and the new one lands
    /// beside the others.
    ///
    /// # Errors
    ///
    /// [`JsValue`] if a replacement worker cannot be spawned, or if the request
    /// cannot be broadcast to the leader.
    pub fn add_account(&self) -> Result<(), JsValue> {
        self.reboot_as(AccountChoice::New)
    }

    /// Offer the gate to a profile that has not adopted it, from the page that
    /// owns the worker.
    ///
    /// The ceremony runs here and only the derived key crosses to the worker,
    /// which adopts it as a late enrolment and re-wraps what it already holds. Use
    /// it when custody reads
    /// [`NoGate::Offerable`](connetto_core::custody::NoGate::Offerable), which is a
    /// profile that could be gated and is not.
    ///
    /// Reachable here rather than through [`crate::unlock::enrol`] directly because
    /// a page never sees the `Worker`: it reaches the topology through [`join`]
    /// alone, so without this an application could read that the gate is on offer
    /// and have no way to accept.
    ///
    /// Answers `false` on a page that owns no worker. Only the leader holds the
    /// private port the derived key travels on, so a follower cannot run this and
    /// must ask the user to act in the window that leads.
    ///
    /// # Errors
    ///
    /// [`JsValue`] if the ceremony fails or the key cannot be posted.
    pub async fn enrol_gate(&self) -> Result<bool, JsValue> {
        // Cloned out of the slot so the borrow is released before the ceremony is
        // awaited: it runs for as long as the user takes to present a finger, and
        // holding a borrow across that would poison every other use of the slot.
        let Some(worker) = self
            .leadership
            .borrow()
            .as_ref()
            .map(|leadership| leadership.worker.clone())
        else {
            return Ok(false);
        };
        crate::unlock::enrol(&worker).await?;
        Ok(true)
    }

    /// Replace the worker so it boots as `choice`.
    ///
    /// Callable from any page. A follower cannot replace a worker it does not own,
    /// so it asks the leader to, which is why this does not report whether the
    /// replacement has happened yet. Wait for it the way a first boot does, with
    /// [`await_db_worker_ready`](crate::workers::await_db_worker_ready).
    fn reboot_as(&self, choice: AccountChoice) -> Result<(), JsValue> {
        if self.is_leader() {
            // The worker asks the page that spawned it, so the choice belongs on
            // this page only when this page is the one that will spawn it.
            crate::unlock::set_pending_switch(choice);
            return self.restart_worker();
        }
        // A `BroadcastChannel` never delivers to its own sender, so this reaches
        // every other page and no leader can miss it by having sent it.
        BroadcastChannel::new(SWITCH_CHANNEL)
            .map_err(|err| JsValue::from_str(&format!("switch channel: {err:?}")))?
            .post_message(&JsValue::from_str(&encode_choice(&choice)))
    }

    /// Replace the worker this page owns, keeping the lock so no other page can
    /// take leadership in between.
    fn restart_worker(&self) -> Result<(), JsValue> {
        let mut slot = self.leadership.borrow_mut();
        let Some(leadership) = slot.as_mut() else {
            return Ok(());
        };
        leadership.worker.terminate();
        let worker = spawn_worker(&self.launch)?;
        leadership.worker = worker;
        Ok(())
    }
}

/// The channel a page with no worker uses to ask the leader to reboot.
const SWITCH_CHANNEL: &str = "connetto-switch";

/// Encode a choice for [`SWITCH_CHANNEL`], which carries strings.
///
/// Prefixed rather than bare, because an account key is caller data and a bare
/// sentinel could collide with one.
fn encode_choice(choice: &AccountChoice) -> String {
    match choice {
        AccountChoice::Named(account) => format!("named:{account}"),
        AccountChoice::LastUsed => "last-used".to_owned(),
        AccountChoice::New => "new".to_owned(),
    }
}

/// Decode what [`encode_choice`] wrote, or `None` when it is not one of ours.
fn decode_choice(message: &str) -> Option<AccountChoice> {
    match message {
        "last-used" => Some(AccountChoice::LastUsed),
        "new" => Some(AccountChoice::New),
        other => other
            .strip_prefix("named:")
            .map(|account| AccountChoice::Named(account.to_owned())),
    }
}

/// Spawn a DB worker and wire the page side of everything it may ask for.
///
/// The tab-side unlock handler is installed here rather than left to the
/// application, because the application never sees this `Worker`: a page reaches
/// the topology through [`join`] alone. Without it a gated profile could not be
/// unlocked under the leader topology at all. The handler is inert unless the
/// worker asks something, so a consumer with no gate pays nothing for it.
fn spawn_worker(launch: &Launch) -> Result<Worker, JsValue> {
    let worker = spawn_db_worker(&launch.glue_url, &launch.bootstrap)?;
    log_worker_errors(&worker);
    crate::unlock::serve_unlock(&worker)?;
    Ok(worker)
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
/// `leader_lock` MUST be identical across every page of one app instance,
/// `glue_url` names the wasm-bindgen glue module, and `bootstrap` selects how
/// the worker is launched from it (see [`spawn_db_worker`]).
#[must_use]
pub fn join(leader_lock: &str, glue_url: &str, bootstrap: WorkerBootstrap) -> Membership {
    let resigned = Rc::new(Cell::new(false));
    let leadership = Rc::new(RefCell::new(None));
    let launch = Rc::new(Launch {
        glue_url: glue_url.to_owned(),
        bootstrap,
    });
    spawn_local(run_election(
        leader_lock.to_owned(),
        Rc::clone(&launch),
        Rc::clone(&resigned),
        Rc::clone(&leadership),
    ));
    let switches = serve_switch_requests(Rc::clone(&launch), Rc::clone(&leadership));
    Membership {
        resigned,
        leadership,
        launch,
        _switches: switches,
    }
}

/// Listen for a switch asked for by a page that owns no worker, and carry it out
/// when this page is the one that does.
///
/// A page that is not the leader ignores it rather than recording the target: the
/// worker asks the page that spawned it, so a target held anywhere else would
/// either go unused or be answered later by a page that has since been promoted,
/// long after the switch it belonged to.
fn serve_switch_requests(
    launch: Rc<Launch>,
    leadership: Rc<RefCell<Option<Leadership>>>,
) -> BroadcastChannel {
    let channel = BroadcastChannel::new(SWITCH_CHANNEL)
        .unwrap_or_else(|err| panic!("switch channel: {err:?}"));
    let listener = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
        let Some(choice) = event.data().as_string().as_deref().and_then(decode_choice) else {
            return;
        };
        let mut slot = leadership.borrow_mut();
        let Some(current) = slot.as_mut() else {
            return;
        };
        crate::unlock::set_pending_switch(choice);
        current.worker.terminate();
        match spawn_worker(&launch) {
            Ok(worker) => current.worker = worker,
            Err(err) => {
                tracing::error!(error = ?err, "leader election: replacing the db worker failed");
            }
        }
    });
    channel.set_onmessage(Some(listener.as_ref().unchecked_ref()));
    // The listener lives as long as the channel this page holds.
    listener.forget();
    channel
}

/// Park until this page wins the leader lock, then spawn the DB worker and
/// hand leadership to the [`Membership`].
async fn run_election(
    leader_lock: String,
    launch: Rc<Launch>,
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
    match spawn_worker(&launch) {
        Ok(worker) => {
            leadership.borrow_mut().replace(Leadership { held, worker });
        }
        Err(err) => {
            tracing::error!(error = ?err, "leader election: spawning the db worker failed");
            // Releasing leadership lets another candidate try.
            held.release();
        }
    }
}

/// Surface a DB worker's load or runtime errors: a worker's own console is not
/// always visible to the page that spawned it.
fn log_worker_errors(worker: &Worker) {
    let on_error = Closure::<dyn FnMut(Event)>::new(|event: Event| {
        let detail = event
            .dyn_ref::<ErrorEvent>()
            .map_or_else(|| "no error detail".to_owned(), ErrorEvent::message);
        tracing::error!(detail = %detail, "db worker error");
    });
    worker.set_onerror(Some(on_error.as_ref().unchecked_ref()));
    // The handler lives for the worker's whole life.
    on_error.forget();
}
