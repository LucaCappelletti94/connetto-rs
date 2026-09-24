//! The content protocol that rides a tab transport's internal lane.
//!
//! Staging and resolution questions travel between a tab and the worker hub
//! as JSON frames, never as codec frames, so the sync protocol between worker
//! and server is untouched. Bytes move beside the JSON rather than inside it:
//! a `Stage` and a local `ResolveReply` attach a `Blob` to the message, which
//! structured clone hands over without a copy through Rust.

use connetto_file_core::MimeClass;
use serde::{Deserialize, Serialize};

/// One content-protocol message between a tab and the worker hub.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentFrame {
    /// The tab announces content it is about to name, declaring the identity
    /// it computed, with the blob attached to the same message.
    Stage {
        /// The identity the tab's bytes hash to.
        file_id: [u8; 32],
        /// The MIME class the tab chose, as [`mime_code`].
        mime: u8,
    },
    /// The tab asks where this file's bytes are to be had.
    Resolve {
        /// Identifies the reply, unique per tab transport.
        request_id: u64,
        /// The file being asked about.
        file_id: [u8; 32],
    },
    /// The hub's answer to a [`ContentFrame::Resolve`]. A `Local` answer
    /// carries its bytes as the blob attached to the reply message.
    ResolveReply {
        /// The `request_id` being answered.
        request_id: u64,
        /// The answer.
        answer: WireResolve,
    },
    /// The tab keeps the files `query` names in `file_id_column` on this device under `name`.
    Pin {
        /// Identifies the reply, unique per tab transport.
        request_id: u64,
        /// The pin's name, its identity for replace and end.
        name: String,
        /// The SQLite query naming the pinned files.
        query: String,
        /// The result column carrying the file identity.
        file_id_column: String,
    },
    /// The tab ends the pin under `name`.
    Unpin {
        /// Identifies the reply, unique per tab transport.
        request_id: u64,
        /// The pin to end.
        name: String,
    },
    /// The tab asks for every pin.
    ListPins {
        /// Identifies the reply, unique per tab transport.
        request_id: u64,
    },
    /// The hub's answer to a pin frame.
    PinReply {
        /// The `request_id` being answered.
        request_id: u64,
        /// The answer.
        answer: WirePins,
    },
}

/// A pin answer in its wire shape.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WirePins {
    /// The pin or unpin was recorded.
    Done,
    /// Every pin, as name, query and file-id column, in name order.
    Pins(Vec<(String, String, String)>),
    /// The hub refused, with the reason.
    Refused(String),
}

/// A resolution answer in its wire shape.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireResolve {
    /// The server granted a read for these bytes.
    Remote {
        /// The granted URL.
        url: String,
    },
    /// The worker holds the bytes, attached to this message.
    Local,
    /// Neither the worker nor the server can produce the bytes right now.
    Unavailable,
}

impl ContentFrame {
    /// Encode for the internal lane.
    pub fn to_json(&self) -> Vec<u8> {
        // Encoding our own value of a Serialize type cannot fail.
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Decode from the internal lane, rejecting anything that is not one of
    /// these frames.
    pub fn from_json(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// The wire code for a MIME class.
#[must_use]
pub const fn mime_code(mime: MimeClass) -> u8 {
    match mime {
        MimeClass::Fasta => 0,
        MimeClass::Mgf => 1,
        MimeClass::Csv => 2,
        MimeClass::Json => 3,
        MimeClass::Jpeg => 4,
        MimeClass::Png => 5,
        MimeClass::Video => 6,
        MimeClass::Gzip => 7,
        MimeClass::Zip => 8,
        MimeClass::Generic => 9,
    }
}

/// The class behind a wire code. An unknown code classes as `Generic`, the
/// same answer an unrecognised MIME string gets everywhere else.
#[must_use]
pub const fn mime_from_code(code: u8) -> MimeClass {
    match code {
        0 => MimeClass::Fasta,
        1 => MimeClass::Mgf,
        2 => MimeClass::Csv,
        3 => MimeClass::Json,
        4 => MimeClass::Jpeg,
        5 => MimeClass::Png,
        6 => MimeClass::Video,
        7 => MimeClass::Gzip,
        8 => MimeClass::Zip,
        _ => MimeClass::Generic,
    }
}
