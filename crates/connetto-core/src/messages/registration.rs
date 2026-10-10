//! The bot registration frames (R91).
//!
//! The server opens every connection with a [`Challenge`]. A bot answers one
//! with a [`RegisterBot`], the server settles it with a [`BotRegistered`], or
//! refuses it with the one undisclosing `ControlMessage::RegistrationRefused`,
//! and either way a fresh challenge follows. A person's client reads the
//! leading challenge and ignores it.

use serde::{Deserialize, Serialize};

/// The domain separator of the message a bot signs to register (R91).
///
/// The bytes precede the connection's nonce in the signed message. R99's
/// login signs the same nonce under its own separator, so a registration
/// signature cannot be replayed as a login and a login signature cannot be
/// replayed as a registration.
pub const BOT_REGISTRATION_DOMAIN: &[u8] = b"connetto bot registration v1\0";

/// The message a bot signs to register, the separator followed by the
/// connection's nonce.
#[must_use]
pub fn bot_registration_message(nonce: &[u8; 32]) -> Vec<u8> {
    let mut message = BOT_REGISTRATION_DOMAIN.to_vec();
    message.extend_from_slice(nonce);
    message
}

/// One entry of a bot's list, the wire shape a registration carries.
///
/// The verb travels as a bare word rather than a closed enum, so a spelling
/// outside the four decodes and is refused like every other bad registration,
/// instead of failing the frame's decode and dropping the connection without
/// a word. The spellings the server admits are `read`, `insert`, `update` and
/// `delete`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BotListEntry {
    /// The table the entry names.
    pub table: String,
    /// The verb the entry declares on it.
    pub verb: String,
    /// Whether an installation takes the table at all, so its entries join
    /// the effective list only when the installation accepts the table.
    pub optional: bool,
}

/// The server's opening frame of every connection (R91).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    /// The random bytes the first frame of the connection signs, kept for
    /// this connection only and spent by the frame that signs it.
    pub nonce: [u8; 32],
}

/// The bot's answer to a challenge with a registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterBot {
    /// The registration code the person's app showed once.
    pub code: String,
    /// The name the bot goes by.
    pub name: String,
    /// The Ed25519 public key the bot registers and later signs with.
    pub public_key: [u8; 32],
    /// The tables and verbs the bot asks for.
    pub list: Vec<BotListEntry>,
    /// The signature over the connection's nonce with the presented key. An
    /// Ed25519 signature is 64 bytes, and any other length is refused like every
    /// other bad registration rather than failing the frame's decode.
    pub signature: Vec<u8>,
}

/// The settled registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BotRegistered {
    /// The bot id, minted at the first registration and kept by later ones,
    /// in the dashed form the database shows it.
    pub bot_id: String,
}
