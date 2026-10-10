//! The bot registry (R91): the one-time codes that register a bot, the bots
//! themselves, their list versions and the installations that serve owners.
//!
//! The deployment declares the tables and names them through the
//! [`ConnettoBotSchema`] member of its
//! [`ConnettoSchema`](crate::schema::ConnettoSchema), by hand or through
//! [`connetto_schema!`](crate::connetto_schema). [`pg_bot_registry`]
//! runs the registration decisions over them on the owner pool.

pub mod schema;

pub use schema::{__public_key, __verb};
pub use schema::{
    BotFacts, CodeFacts, ConnettoBotSchema, Installation, ListEntry, ListRow, NewBot,
    PgBotRegistry, Registered, RegistryError, Statement, Verb, pg_bot_registry,
};
#[doc(hidden)]
pub use schema::{BotRegistryIdSql, Uuid};
