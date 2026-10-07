//! What the node tells the device about its links.

use connetto_core::device_cert::DeviceIdentity;

use crate::CloseReason;

/// A change to the node's links, or a list one of them delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEvent {
    /// A peer key is now linked.
    Linked {
        /// The peer the link reached.
        peer: DeviceIdentity,
    },
    /// A peer key lost its last link.
    Unlinked {
        /// The peer the link fell from.
        peer: DeviceIdentity,
        /// Why the link closed.
        reason: CloseReason,
    },
    /// A link delivered a revocation list the node lacked.
    ListReceived {
        /// The list, DER.
        list: Vec<u8>,
        /// The signer's certificate, DER.
        signer: Vec<u8>,
    },
}
