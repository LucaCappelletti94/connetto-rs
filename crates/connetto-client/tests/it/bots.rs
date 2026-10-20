//! R91: the person's app side of the bot registry, against the in-process
//! client and its local replica.
//!
//! `install` writes connetto's rows beside the app's membership row in the
//! app's local transaction, so the one uploaded change carries both.
//! `create_registration_code` mints a code, stores only its SHA-256, and
//! returns the base32 display form.

use std::time::Duration;

use super::support::captured_tables;
use connetto_client::bots::{Install, create_registration_code, install};
use connetto_client::{ClientBuilder, ClientError, ConnettoConnection};
use connetto_server::LoopbackTransport;
use diesel::prelude::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const DDL: &str = "\
CREATE TABLE membership (installation TEXT PRIMARY KEY, member TEXT NOT NULL); \
CREATE TABLE connetto_bots (id BLOB PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL, public_key BLOB NOT NULL, list_version INTEGER NOT NULL, wake_url TEXT); \
CREATE TABLE connetto_registration_codes (code_hash BLOB PRIMARY KEY, creator TEXT NOT NULL, bot BLOB, expires_at TEXT NOT NULL, used_at TEXT); \
CREATE TABLE connetto_bot_lists (bot BLOB NOT NULL, version INTEGER NOT NULL, table_name TEXT NOT NULL, verb TEXT NOT NULL, optional INTEGER NOT NULL, PRIMARY KEY (bot, version, table_name, verb)); \
CREATE TABLE connetto_installations (id TEXT PRIMARY KEY, bot BLOB NOT NULL, owner TEXT NOT NULL, accepted_version INTEGER NOT NULL); \
CREATE TABLE connetto_installation_optional_tables (installation TEXT NOT NULL, table_name TEXT NOT NULL, PRIMARY KEY (installation, table_name));";

diesel::table! {
    /// The app's membership row, written beside connetto's in the add.
    membership (installation) {
        /// The installation the membership belongs to.
        installation -> Text,
        /// The member the installation serves.
        member -> Text,
    }
}

connetto_client::connetto_bot_tables!(String, diesel::sql_types::Text);

/// The in-process client, offline, so a written change stays local.
fn client() -> ConnettoConnection<LoopbackTransport> {
    ClientBuilder::<LoopbackTransport>::new(
        super::support::bundle(DDL),
        super::support::NeverDial::<LoopbackTransport>::default(),
    )
    .open_driven()
    .expect("the builder opens offline")
}

/// `install` writes connetto's rows beside the app's membership row in the
/// app's local transaction, so the one uploaded change carries both.
#[tokio::test]
async fn install_lands_connettos_rows_and_the_membership_row_as_one_change() {
    let mut client = client();
    let bot = Uuid::new_v4();
    {
        let replica = client.conn();
        replica
            .transaction::<(), ClientError, _>(|tx| {
                install::<ConnettoBots, _>(
                    tx,
                    Install {
                        installation: "inst-1".to_owned(),
                        bot,
                        owner: "owner-1".to_owned(),
                        accepted_version: 1,
                        optional_tables: vec!["orders".to_owned()],
                    },
                )?;
                diesel::insert_into(membership::table)
                    .values((
                        membership::installation.eq("inst-1"),
                        membership::member.eq("owner-1"),
                    ))
                    .execute(tx)?;
                Ok(())
            })
            .expect("the add transaction commits");
    }
    let seq = client
        .push()
        .await
        .expect("the push records the change")
        .expect("a non-empty changeset records");
    let replica = client.conn();
    let tables = captured_tables(replica, seq);
    assert!(
        tables.contains(&"connetto_installations".to_owned()),
        "the change names connetto's installations row: {tables:?}"
    );
    assert!(
        tables.contains(&"connetto_installation_optional_tables".to_owned()),
        "the change names the accepted optional table: {tables:?}"
    );
    assert!(
        tables.contains(&"membership".to_owned()),
        "the change names the app's membership row: {tables:?}"
    );
    // The rows are durable in the replica.
    let installations: Vec<(String, Vec<u8>, String, i32)> = connetto_installations::table
        .load(replica)
        .expect("the installation loads");
    assert_eq!(installations.len(), 1, "one installation row");
    let (id, stored_bot, owner, version) = &installations[0];
    assert_eq!(id, "inst-1");
    assert_eq!(stored_bot, &bot.as_bytes().to_vec());
    assert_eq!(owner, "owner-1");
    assert_eq!(*version, 1);
    let optional: Vec<(String, String)> = connetto_installation_optional_tables::table
        .load(replica)
        .expect("the optional tables load");
    assert_eq!(
        optional,
        vec![("inst-1".to_owned(), "orders".to_owned())],
        "the accepted optional table is recorded"
    );
}

/// The code row the replica keeps: every column, so a drift between the
/// writes and the columns the test reads shows up here.
#[derive(Queryable, Selectable, Debug)]
#[diesel(table_name = connetto_registration_codes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct CodeRow {
    code_hash: Vec<u8>,
    creator: String,
    bot: Option<Vec<u8>>,
    expires_at: String,
    used_at: Option<String>,
}

/// A minted code stores only the SHA-256 of its canonical form, names the
/// creator and the bot it admits, leaves itself unspent, and returns the
/// display form whose canonical form hashes to the stored row.
#[tokio::test]
async fn a_minted_code_stores_only_its_hash_and_returns_its_display_form() {
    let mut client = client();
    let bot = Uuid::new_v4();
    let code = create_registration_code::<ConnettoBots, _>(
        client.conn(),
        "owner-1".to_owned(),
        Some(bot),
        Duration::from_secs(3600),
    )
    .expect("the code mints");
    // The stored hash is the SHA-256 of the code's canonical form, the form a
    // registration typed in lowercase or without dashes reads as.
    let canonical = connetto_core::bots::canonical_code(&code);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let expected_hash = hasher.finalize().to_vec();
    let row: CodeRow = connetto_registration_codes::table
        .select(CodeRow::as_select())
        .first(client.conn())
        .expect("the code row loads");
    assert_eq!(
        row.code_hash, expected_hash,
        "the stored hash is the code's SHA-256"
    );
    assert_eq!(
        row.creator, "owner-1",
        "the creator is the signed-in person"
    );
    assert_eq!(
        row.bot,
        Some(bot.as_bytes().to_vec()),
        "the code admits the named bot"
    );
    assert!(row.used_at.is_none(), "a fresh code is unspent");
    assert!(!row.expires_at.is_empty(), "the expiry is written");
}

/// An install that names an empty optional table or the same table twice is
/// refused before a row is written, so the local transaction rolls the app's
/// membership row back with connetto's and the push records nothing.
#[tokio::test]
async fn an_install_naming_an_empty_or_duplicate_optional_table_is_refused() {
    for optional_tables in [
        vec![String::new()],
        vec!["orders".to_owned(), "orders".to_owned()],
    ] {
        let mut client = client();
        let bot = Uuid::new_v4();
        let refused = {
            let replica = client.conn();
            replica
                .transaction::<(), ClientError, _>(|tx| {
                    install::<ConnettoBots, _>(
                        tx,
                        Install {
                            installation: "inst-1".to_owned(),
                            bot,
                            owner: "owner-1".to_owned(),
                            accepted_version: 1,
                            optional_tables,
                        },
                    )?;
                    diesel::insert_into(membership::table)
                        .values((
                            membership::installation.eq("inst-1"),
                            membership::member.eq("owner-1"),
                        ))
                        .execute(tx)?;
                    Ok(())
                })
                .expect_err("the add is refused locally")
        };
        assert!(
            matches!(refused, ClientError::InstallRefused(_)),
            "the refusal is the install's own validation: {refused:?}"
        );
        let replica = client.conn();
        let installations: Vec<String> = connetto_installations::table
            .select(connetto_installations::id)
            .load(replica)
            .expect("the installations table loads");
        assert!(
            installations.is_empty(),
            "the refused add wrote no installation row: {installations:?}"
        );
        let members: Vec<String> = membership::table
            .select(membership::installation)
            .load(replica)
            .expect("the membership table loads");
        assert!(
            members.is_empty(),
            "the refused add wrote no membership row"
        );
        assert!(
            client.push().await.expect("the push runs").is_none(),
            "the refused add recorded no change"
        );
    }
}
