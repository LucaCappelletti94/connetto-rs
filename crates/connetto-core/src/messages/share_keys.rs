//! Share keys changed on a running session (R95).

use serde::{Deserialize, Serialize};

use super::handshake::Grant;

/// Client replaces every share key its session holds with `keys`.
///
/// The identity resolved at the handshake stays, so a grant here naming a
/// person is dropped like a grant that fails to check. Nothing on the wire
/// says which keys resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaceShareKeys {
    /// Client-chosen correlation token, echoed by the answer.
    pub request_id: String,
    /// The whole set the session holds from now on, empty to hold none.
    pub keys: Vec<Grant>,
}

/// Server has swapped the session's share keys and queued the resend of
/// every subscription the change reaches, so every frame after this one is
/// filtered by the new set.
///
/// A request over the swap limit is answered with
/// [`RateLimited`](super::RateLimited) carrying its `request_id` instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareKeysReplaced {
    /// Correlation token from the request this answers.
    pub request_id: String,
}

/// One change a relay tab asks its worker to make to the share keys the
/// worker holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShareKeyChange {
    /// Hold `grant` beside the subject it renders as.
    Add {
        /// The signed share key.
        grant: Grant,
        /// The subject the key renders as in the subjects function.
        subject: String,
    },
    /// Drop every grant held for this rendered subject.
    Remove {
        /// The rendered subject whose grants go.
        subject: String,
    },
}

/// A tab asks its relay's worker to change the worker's share keys.
///
/// Relay only, like [`TabIdentity`](super::TabIdentity). A real server
/// neither sends nor answers it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TabShareKeyChange {
    /// Tab-chosen correlation token, echoed by the answer.
    pub request_id: String,
    /// What to change.
    pub change: ShareKeyChange,
}

/// How a worker settled a tab's share-key change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TabShareKeyOutcome {
    /// The worker holds the changed set, or already held it.
    Changed,
    /// The worker's gate is locked, so nothing changed.
    Locked,
    /// The secret store refused the save, so nothing changed.
    StoreRefused(String),
    /// The worker's replica refused the change, so nothing changed.
    ReplicaRefused(String),
}

/// A worker answers a [`TabShareKeyChange`] after stating the resulting
/// [`TabIdentity`](super::TabIdentity) to every tab.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TabShareKeyAnswer {
    /// Correlation token from the request this answers.
    pub request_id: String,
    /// How the change was settled.
    pub outcome: TabShareKeyOutcome,
}
