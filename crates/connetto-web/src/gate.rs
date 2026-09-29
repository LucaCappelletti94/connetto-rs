//! The browser's away-and-return gate, the mechanism over the worker's
//! unlock ceremony, and the call that installs it on the worker's relay hub.
//!
//! The worker's relay hub holds the re-check in a gate controller, and this
//! module supplies the browser's [`GateMechanism`]. `lock` drops the derived
//! key-encryption key from the worker's key store, so no new key read works
//! until the next approval. `ask` posts the unlock request to the spawning
//! tab over the worker's private port, the only channel a non-extractable key
//! may cross, and resolves `Approved` when the key arrives, re-adopting it,
//! and `Dismissed` on a decline, a failure, or the ceremony's bound.
//!
//! The hub drives the prompt in its own loop, feeds the away input from the
//! tabs' visibility, and states each lock to every tab. A tab's client, which
//! has no mechanism of its own, applies each stated lock as it arrives, so the
//! tabs refuse and hold exactly as a gated client would.

use std::rc::Rc;
use std::sync::Arc;

use connetto_client::Gate;
use connetto_client::away::{GateAskFuture, GateAskOutcome, GateMechanism};

use crate::auth::IdbKeyStore;
use crate::relay::RelayHub;
use crate::unlock::{CEREMONY_TIMEOUT_MS, TabAnswer, ask_unlock, clear_pending_answer};
use crate::visibility;

/// The browser's gate mechanism over the worker's unlock ceremony.
pub struct BrowserGateMechanism {
    key_store: Rc<IdbKeyStore>,
}

impl BrowserGateMechanism {
    /// A mechanism over the worker's key store.
    #[must_use]
    pub fn new(key_store: Rc<IdbKeyStore>) -> Self {
        Self { key_store }
    }
}

impl GateMechanism for BrowserGateMechanism {
    fn lock(&self) {
        self.key_store.drop_derived();
    }

    fn ask(&self) -> GateAskFuture {
        let key_store = Rc::clone(&self.key_store);
        Box::pin(async move {
            let credentials = match key_store.enrolled().await {
                Ok(credentials) => credentials,
                Err(err) => {
                    tracing::error!(%err, "gate: reading the enrolled credentials failed");
                    return GateAskOutcome::Dismissed;
                }
            };
            if credentials.is_empty() {
                tracing::error!("gate: no enrolled credential to ask with");
                return GateAskOutcome::Dismissed;
            }
            // The bound is a fixed millisecond literal, and 60_000 fits an
            // i32, so the cast cannot truncate.
            debug_assert!(
                i32::try_from(CEREMONY_TIMEOUT_MS).is_ok(),
                "the ceremony bound exceeds i32"
            );
            let answer = tokio::select! {
                biased;
                answer = ask_unlock(credentials) => answer,
                () = crate::workers::helpers::sleep_ms(CEREMONY_TIMEOUT_MS.cast_signed()) => {
                    clear_pending_answer();
                    tracing::warn!("gate: the spawning tab never answered the unlock");
                    return GateAskOutcome::Dismissed;
                }
            };
            match answer {
                // The key arrived over the private port, so re-adopt it for
                // the next read.
                Ok(TabAnswer::Key { credential_id, key }) => {
                    match key_store.use_derived(key, &credential_id).await {
                        Ok(()) => GateAskOutcome::Approved,
                        Err(err) => {
                            tracing::error!(%err, "gate: re-adopting the derived key failed");
                            GateAskOutcome::Dismissed
                        }
                    }
                }
                // A decline, a failure, a platform without the ceremony, or
                // an answer to another question all mean the key did not
                // arrive.
                Ok(_) => GateAskOutcome::Dismissed,
                Err(err) => {
                    tracing::error!(%err, "gate: the unlock request could not be posted");
                    GateAskOutcome::Dismissed
                }
            }
        })
    }
}

/// Install the away-and-return gate on the worker's relay hub, worker side.
///
/// Takes the build's [`Gate`], whether this boot unlocked through the gate,
/// and the worker's [`RelayHub`]. When the gate is on and the boot is gated,
/// the re-check is armed on the hub's gate controller with the browser's
/// mechanism, the controller's away input is fed by the tabs' visibility,
/// and its lock states are delivered straight to the hub, which states them
/// to every tab. A gated boot starts locked and asks the one launch prompt,
/// which is what the spawning tab answers. A return past the grace asks
/// again, and the tabs learn each state from the hub.
///
/// A boot that is not gated, or a gate the application turned off, arms
/// nothing, so the away input is ignored and the tabs stay open.
pub fn install_worker_gate(
    hub: &RelayHub,
    key_store: Rc<IdbKeyStore>,
    gate: Gate,
    boot_gated: bool,
) {
    if !(gate.on() && boot_gated) {
        return;
    }
    let mechanism = BrowserGateMechanism::new(key_store);
    #[expect(
        clippy::arc_with_non_send_sync,
        reason = "wasm is single-threaded, so the controller's Arc shares the non-Send mechanism only within this thread"
    )]
    hub.gate().enable(gate.recheck(), Arc::new(mechanism));
    visibility::track_visibility(Rc::clone(hub.gate()));
    // A gated boot starts locked, and the one launch prompt is what the
    // spawning tab answers.
    hub.gate().unlock();
}
