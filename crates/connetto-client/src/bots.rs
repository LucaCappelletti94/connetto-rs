//! The person's app side of the bot registry (R91).
//!
//! [`install`] writes connetto's rows for an add beside the app's own
//! membership row in the app's local transaction, so the one uploaded change
//! lands whole or is refused whole by the deployment's rule.
//! [`create_registration_code`] mints a one-time code, stores only its
//! SHA-256, and returns the code to show once.
//!
//! The registry `table!` definitions and the typed writes live in
//! [`connetto_bot_tables!`](crate::connetto_bot_tables), which the app invokes
//! once with the deployment's `Id` type; both functions are generic over the
//! [`ClientBotTables`] impl it emits, so they hold the table-agnostic logic
//! (minting, hashing, the code's display form, the expiry) beside it.

use std::collections::BTreeSet;
#[cfg(any(feature = "native-transport", feature = "native-auth"))]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use diesel::{Connection, sqlite::Sqlite};
#[cfg(any(feature = "native-transport", feature = "native-auth"))]
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ClientError;

/// The client's bot registry tables, implemented by
/// [`connetto_bot_tables!`](crate::connetto_bot_tables) with the deployment's
/// `Id` and the replica's typed writes. The replica is always the client's
/// local SQLite, so the writes are bound to the SQLite backend rather than
/// left to the caller.
pub trait ClientBotTables {
    /// The deployment's principal id.
    type Id: Clone;
    /// Write the installations row and its optional-table children. The caller
    /// owns the surrounding transaction, so a refused change rolls the app's
    /// membership row and these rows back together.
    ///
    /// # Errors
    ///
    /// Fails if the installations row or an optional-table child cannot be
    /// written, or if the installation is already present.
    fn write_installation<C: Connection<Backend = Sqlite>>(
        conn: &mut C,
        installation: Self::Id,
        bot: Vec<u8>,
        owner: Self::Id,
        accepted_version: i32,
        optional_tables: &[String],
    ) -> diesel::QueryResult<()>;
    /// Write a registration code row, storing only the SHA-256 of the code's
    /// canonical form.
    ///
    /// # Errors
    ///
    /// Fails if the code row cannot be written or the code is already present.
    fn write_code<C: Connection<Backend = Sqlite>>(
        conn: &mut C,
        code_hash: Vec<u8>,
        creator: Self::Id,
        bot: Option<Vec<u8>>,
        expires_at: String,
    ) -> diesel::QueryResult<()>;
}

/// The client's bot registry tables, the [`connetto_core::connetto_registry_tables!`]
/// replica preset plus a [`ClientBotTables`] impl with the typed writes. Invoke
/// once with the deployment's `Id` Rust type and its SQL type; the app names
/// the same tables connetto's writes use, so the add and the app's membership
/// row upload as one change.
#[macro_export]
macro_rules! connetto_bot_tables {
    ($id:ty, $id_sql:ty) => {
        connetto_core::connetto_registry_tables!(replica, $id_sql);
        /// The default client bot registry tables over the deployment's `Id`.
        #[derive(Debug, Clone, Copy, Default)]
        pub struct ConnettoBots;
        impl $crate::bots::ClientBotTables for ConnettoBots {
            type Id = $id;
            fn write_installation<C: diesel::Connection<Backend = diesel::sqlite::Sqlite>>(
                conn: &mut C,
                installation: Self::Id,
                bot: Vec<u8>,
                owner: Self::Id,
                accepted_version: i32,
                optional_tables: &[String],
            ) -> diesel::QueryResult<()> {
                let row = diesel::insert_into(connetto_installations::table).values((
                    connetto_installations::id.eq(&installation),
                    connetto_installations::bot.eq(bot),
                    connetto_installations::owner.eq(owner),
                    connetto_installations::accepted_version.eq(accepted_version),
                ));
                diesel::query_dsl::methods::ExecuteDsl::<C>::execute(row, conn)?;
                for table_name in optional_tables {
                    let row = diesel::insert_into(connetto_installation_optional_tables::table)
                        .values((
                            connetto_installation_optional_tables::installation.eq(&installation),
                            connetto_installation_optional_tables::table_name.eq(table_name),
                        ));
                    diesel::query_dsl::methods::ExecuteDsl::<C>::execute(row, conn)?;
                }
                Ok(())
            }
            fn write_code<C: diesel::Connection<Backend = diesel::sqlite::Sqlite>>(
                conn: &mut C,
                code_hash: Vec<u8>,
                creator: Self::Id,
                bot: Option<Vec<u8>>,
                expires_at: String,
            ) -> diesel::QueryResult<()> {
                let row = diesel::insert_into(connetto_registration_codes::table).values((
                    connetto_registration_codes::code_hash.eq(code_hash),
                    connetto_registration_codes::creator.eq(creator),
                    connetto_registration_codes::bot.eq(bot),
                    connetto_registration_codes::expires_at.eq(expires_at),
                    connetto_registration_codes::used_at.eq(None::<String>),
                ));
                diesel::query_dsl::methods::ExecuteDsl::<C>::execute(row, conn)?;
                Ok(())
            }
        }
    };
}

/// The connetto side of an add: the installations row and its optional tables.
///
/// The app writes its membership row beside these in the same local
/// transaction and uploads the one change, which lands whole or is refused
/// whole. connetto never learns the deployment's membership table.
pub struct Install<T: ClientBotTables> {
    /// The deployment's id of the installation, minted by the admin's app.
    pub installation: T::Id,
    /// The bot it runs.
    pub bot: Uuid,
    /// The owner it serves.
    pub owner: T::Id,
    /// The list version the admin accepted.
    pub accepted_version: i32,
    /// The optional tables the installation accepted. [`install`] refuses an
    /// entry that is empty or named twice.
    pub optional_tables: Vec<String>,
}

/// Write connetto's rows for an add. The app writes its membership row beside
/// this in the same local transaction and uploads the one change.
///
/// The optional tables are validated before a row is written, so an install
/// that names an empty table or the same table twice is refused with nothing
/// written, and the app's transaction rolls back whole.
///
/// # Errors
///
/// [`ClientError::InstallRefused`] when an optional table is empty or named
/// twice, and [`ClientError::Db`] when a write fails.
pub fn install<T: ClientBotTables, C: Connection<Backend = Sqlite>>(
    conn: &mut C,
    install: Install<T>,
) -> Result<(), ClientError> {
    for (index, table) in install.optional_tables.iter().enumerate() {
        if table.is_empty() {
            return Err(ClientError::InstallRefused(format!(
                "the optional table at position {index} names no table"
            )));
        }
    }
    let mut named = BTreeSet::new();
    for table in &install.optional_tables {
        if !named.insert(table.as_str()) {
            return Err(ClientError::InstallRefused(format!(
                "the optional table '{table}' is named twice"
            )));
        }
    }
    T::write_installation(
        conn,
        install.installation,
        install.bot.as_bytes().to_vec(),
        install.owner,
        install.accepted_version,
        &install.optional_tables,
    )?;
    Ok(())
}

/// Mint a registration code, store the SHA-256 of the code's canonical form,
/// and return the code to show once. The registration carries the code on the
/// wire, and the registry looks it up by the hash of its canonical form, so a
/// code the operator types in lowercase or without its dashes settles.
/// `creator` is the signed-in person; `for_bot` names the bot the code admits
/// a list or key for, absent for a first registration; `valid_for` bounds how
/// long it stays usable.
///
/// # Errors
///
/// [`ClientError::Session`] when the platform RNG or the clock fails, and
/// [`ClientError::Db`] when the write fails.
#[cfg(any(feature = "native-transport", feature = "native-auth"))]
pub fn create_registration_code<T: ClientBotTables, C: Connection<Backend = Sqlite>>(
    conn: &mut C,
    creator: T::Id,
    for_bot: Option<Uuid>,
    valid_for: Duration,
) -> Result<String, ClientError> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|err| ClientError::Session(err.to_string()))?;
    let code = base32_groups(&raw);
    let canonical = connetto_core::bots::canonical_code(&code);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let code_hash = hasher.finalize().to_vec();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| ClientError::Session(err.to_string()))?;
    let expires_at = rfc3339(now.as_secs() + valid_for.as_secs());
    T::write_code(
        conn,
        code_hash,
        creator,
        for_bot.map(|bot| bot.as_bytes().to_vec()),
        expires_at,
    )?;
    Ok(code)
}

#[cfg(any(feature = "native-transport", feature = "native-auth"))]
/// The RFC 4648 base32 alphabet.
const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[cfg(any(feature = "native-transport", feature = "native-auth"))]
/// Encode bytes as RFC 4648 base32 (no padding), in 4-character groups joined
/// by `-`, the registration code's display form.
fn base32_groups(input: &[u8]) -> String {
    let mut out = String::new();
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for &byte in input {
        buf = (buf << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            // The mask keeps the index at 0..=31, lossless into usize.
            let idx = ((buf >> bits) & 31) as usize;
            out.push(char::from(B32_ALPHABET[idx]));
        }
        // Keep only the pending bits so the buffer never outgrows 12 bits.
        buf &= (1 << bits) - 1;
    }
    if bits > 0 {
        // The mask keeps the index at 0..=31, lossless into usize.
        let idx = ((buf << (5 - bits)) & 31) as usize;
        out.push(char::from(B32_ALPHABET[idx]));
    }
    out.as_bytes()
        .chunks(4)
        .map(|chunk| core::str::from_utf8(chunk).expect("ascii base32"))
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(any(feature = "native-transport", feature = "native-auth"))]
/// Format a unix timestamp as RFC 3339, the replica's `timestamptz` form.
fn rfc3339(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3_600;
    let min = (rem % 3_600) / 60;
    let s = rem % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{s:02}Z")
}

#[cfg(any(feature = "native-transport", feature = "native-auth"))]
/// Howard Hinnant's days-since-1970 to a civil date, unsigned since a replica
/// timestamp is never before the epoch.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

#[cfg(test)]
#[cfg(any(feature = "native-transport", feature = "native-auth"))]
mod tests {
    use super::*;

    /// The display form round-trips: 16 bytes are 128 bits, 26 base32
    /// characters, in 4-character groups.
    #[test]
    fn the_code_display_form_groups_base32() {
        let raw = [7u8; 16];
        let code = base32_groups(&raw);
        let groups: Vec<&str> = code.split('-').collect();
        assert_eq!(groups.len(), 7, "26 characters form six fours and a two");
        for (i, group) in groups.iter().enumerate() {
            assert!(
                group.len() == 4 || (i == groups.len() - 1 && group.len() == 2),
                "group {i} is {group:?}"
            );
        }
        // Every character is from the alphabet.
        for c in code.chars().filter(|c| *c != '-') {
            assert!(B32_ALPHABET.contains(&(c as u8)));
        }
    }

    /// The timestamp formatter matches known RFC 3339 values.
    #[test]
    fn the_timestamp_formatter_matches_rfc3339() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(86_400), "1970-01-02T00:00:00Z");
        // The day after a leap day, so a dropped 29th would surface.
        assert_eq!(rfc3339(1_709_251_200), "2024-03-01T00:00:00Z");
        assert_eq!(rfc3339(1_791_590_400), "2026-10-10T00:00:00Z");
    }

    /// A whole second of expiry lands in the format, not clipped.
    #[test]
    fn the_timestamp_formatter_keeps_the_time_of_day() {
        assert_eq!(rfc3339(86_399), "1970-01-01T23:59:59Z");
        assert_eq!(rfc3339(86_400), "1970-01-02T00:00:00Z");
    }
}
