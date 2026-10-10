//! Registering a bot over a live connection (R91).
//!
//! A bot opens a connection to the server, waits for the challenge the server
//! opens every connection with, signs the connection's nonce under the
//! registration's domain separator, and sends the registration. The answer is
//! the bot id, or the one undisclosing refusal, after which the connection
//! carries on with a fresh challenge.

use ring::signature::{Ed25519KeyPair, KeyPair};

use connetto_core::messages::{
    BotListEntry, ControlMessage, RegisterBot, bot_registration_message,
};
use connetto_core::traits::{IncomingFrame, Transport};

use crate::ClientError;
use uuid::Uuid;
/// What a bot presents to register.
#[derive(Debug)]
pub struct Registration {
    /// The registration code the person's app showed once.
    pub code: String,
    /// The name the bot goes by.
    pub name: String,
    /// The bot's Ed25519 key.
    pub key_pair: Ed25519KeyPair,
    /// The tables and verbs the bot asks for.
    pub list: Vec<BotListEntry>,
}

/// Register over a live connection.
///
/// Waits for the challenge the server opens the connection with, signs the
/// connection's nonce with the bot's key, sends the registration, and ends
/// with the bot id or the refusal. A refused registration spends the nonce,
/// so the challenge that follows belongs to the next frame of this
/// connection.
///
/// # Errors
///
/// [`ClientError`] when the transport fails, the server breaks the exchange's
/// shape, or the server refuses the registration or ends the connection.
pub async fn register<T: Transport>(
    transport: &mut T,
    registration: &Registration,
) -> Result<Uuid, ClientError>
where
    T::Error: core::fmt::Display,
{
    let nonce = match transport
        .recv()
        .await
        .map_err(|e| ClientError::Transport(e.to_string()))?
    {
        Some(IncomingFrame::Control(ControlMessage::Challenge(challenge))) => challenge.nonce,
        Some(IncomingFrame::Control(other)) => {
            return Err(ClientError::Protocol(format!(
                "expected the connection's challenge, got {other:?}"
            )));
        }
        Some(IncomingFrame::Bulk(_)) => {
            return Err(ClientError::Protocol(
                "expected the connection's challenge, got a bulk frame".into(),
            ));
        }
        None => {
            return Err(ClientError::Protocol(
                "the connection closed before its challenge".into(),
            ));
        }
    };
    let signature = registration
        .key_pair
        .sign(&bot_registration_message(&nonce));
    let mut public_key = [0_u8; 32];
    public_key.copy_from_slice(registration.key_pair.public_key().as_ref());
    transport
        .send_control(ControlMessage::RegisterBot(RegisterBot {
            code: registration.code.clone(),
            name: registration.name.clone(),
            public_key,
            list: registration.list.clone(),
            signature: signature.as_ref().to_vec(),
        }))
        .await
        .map_err(|e| ClientError::Transport(e.to_string()))?;
    match transport
        .recv()
        .await
        .map_err(|e| ClientError::Transport(e.to_string()))?
    {
        Some(IncomingFrame::Control(ControlMessage::BotRegistered(answer))) => {
            Uuid::parse_str(&answer.bot_id).map_err(|e| {
                ClientError::Protocol(format!("the registered bot id is not a uuid: {e}"))
            })
        }
        Some(IncomingFrame::Control(ControlMessage::RegistrationRefused)) => {
            Err(ClientError::RegistrationRefused)
        }
        Some(IncomingFrame::Control(ControlMessage::FatalError(fatal))) => {
            Err(ClientError::Refused {
                reason: fatal.reason,
            })
        }
        Some(_) => Err(ClientError::Protocol(
            "expected the registration's answer".into(),
        )),
        None => Err(ClientError::Protocol(
            "the connection closed before the registration's answer".into(),
        )),
    }
}
