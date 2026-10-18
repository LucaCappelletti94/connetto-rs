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
