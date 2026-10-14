//! The bot registry tables' DDL, the one source the translation step appends
//! to a deployment's schema document (R91).
//!
//! connetto adds the five registry tables (`connetto_bots`,
//! `connetto_registration_codes`, `connetto_bot_lists`,
//! `connetto_installations`, `connetto_installation_optional_tables`) to the
//! schema document the build translates, so a deployment's Postgres migration
//! and every replica carry them as synced tables and the cap rules cover them
//! like any other synced table. A deployment that omits them still gets them.
//! The tables' id columns use the deployment's own `Id` SQL type, so the DDL
//! has one variant per id type [`BotRegistryIdSql`] names.

/// The registry tables' DDL over the deployment's `Id` SQL type.
///
/// The one source of the five registry tables' `CREATE TABLE` statements,
/// which the translation step appends to a deployment's schema document. A
/// type names one variant of the DDL by the SQL type its id columns carry.
pub trait BotRegistryIdSql {
    /// The registry tables' DDL over this `Id` SQL type, the five `CREATE
    /// TABLE` statements joined by `;`.
    const DDL: &'static str;
}

/// The registry DDL over `TEXT` ids.
pub const REGISTRY_DDL_TEXT: &str = "CREATE TABLE connetto_bots (id UUID PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL, public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32), list_version INT NOT NULL, wake_url TEXT); CREATE TABLE connetto_registration_codes (code_hash BYTEA PRIMARY KEY, creator TEXT NOT NULL, bot UUID REFERENCES connetto_bots (id), expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ); CREATE TABLE connetto_bot_lists (bot UUID NOT NULL REFERENCES connetto_bots (id), version INT NOT NULL, table_name TEXT NOT NULL, verb TEXT NOT NULL CHECK (verb IN ('read', 'insert', 'update', 'delete')), optional BOOLEAN NOT NULL, PRIMARY KEY (bot, version, table_name, verb)); CREATE TABLE connetto_installations (id TEXT PRIMARY KEY, bot UUID NOT NULL REFERENCES connetto_bots (id), owner TEXT NOT NULL, accepted_version INT NOT NULL); CREATE TABLE connetto_installation_optional_tables (installation TEXT NOT NULL REFERENCES connetto_installations (id), table_name TEXT NOT NULL, PRIMARY KEY (installation, table_name));";

/// The registry DDL over `UUID` ids.
pub const REGISTRY_DDL_UUID: &str = "CREATE TABLE connetto_bots (id UUID PRIMARY KEY, owner UUID NOT NULL, name TEXT NOT NULL, public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32), list_version INT NOT NULL, wake_url TEXT); CREATE TABLE connetto_registration_codes (code_hash BYTEA PRIMARY KEY, creator UUID NOT NULL, bot UUID REFERENCES connetto_bots (id), expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ); CREATE TABLE connetto_bot_lists (bot UUID NOT NULL REFERENCES connetto_bots (id), version INT NOT NULL, table_name TEXT NOT NULL, verb TEXT NOT NULL CHECK (verb IN ('read', 'insert', 'update', 'delete')), optional BOOLEAN NOT NULL, PRIMARY KEY (bot, version, table_name, verb)); CREATE TABLE connetto_installations (id UUID PRIMARY KEY, bot UUID NOT NULL REFERENCES connetto_bots (id), owner UUID NOT NULL, accepted_version INT NOT NULL); CREATE TABLE connetto_installation_optional_tables (installation UUID NOT NULL REFERENCES connetto_installations (id), table_name TEXT NOT NULL, PRIMARY KEY (installation, table_name));";

/// A marker naming the registry DDL over `TEXT` ids, for callers that do not
/// carry the diesel `Text` SQL type, such as a build script.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct TextIds;

/// A marker naming the registry DDL over `UUID` ids, for callers that do not
/// carry the diesel `Uuid` SQL type, such as a build script.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct UuidIds;

impl BotRegistryIdSql for TextIds {
    const DDL: &'static str = REGISTRY_DDL_TEXT;
}

impl BotRegistryIdSql for UuidIds {
    const DDL: &'static str = REGISTRY_DDL_UUID;
}

/// The registry tables' DDL over `Id`'s id columns, the one source the
/// translation step appends to a deployment's schema document.
#[must_use]
pub fn registry_ddl<Id: BotRegistryIdSql>() -> &'static str {
    Id::DDL
}

/// The five bot registry tables' names (R91), which connetto appends to every
/// deployment's schema.
pub const REGISTRY_TABLES: &[&str] = &[
    "connetto_bots",
    "connetto_registration_codes",
    "connetto_bot_lists",
    "connetto_installations",
    "connetto_installation_optional_tables",
];

/// The registry tables a client writes through the ordinary sync path, the
/// creator's registration codes and the admin's installations. The write path
/// admits them whatever the deployment's write policy names, because the
/// deployment's catalog never lists connetto's own tables, and their rows are
/// gated by the deployment's rules and the cap. `connetto_bots` and
/// `connetto_bot_lists` are absent on purpose, since only the server writes
/// them, at registration.
pub const CLIENT_WRITTEN_REGISTRY_TABLES: &[&str] = &[
    "connetto_registration_codes",
    "connetto_installations",
    "connetto_installation_optional_tables",
];

/// The code's canonical form: uppercase, group separators and whitespace
/// removed. The client and the server both hash this one form, so a code
/// typed in lowercase or without dashes settles, and a character outside the
/// base32 alphabet changes the form and is refused like a wrong code.
#[must_use]
pub fn canonical_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// One of the four verbs a bot list entry declares.
///
/// Named once here rather than per side, so the entries a session carries
/// and the rows the registry stores name the same verb, and a spelling
/// outside the four the registry's `CHECK` allows parses to `None` on both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verb {
    /// The `read` verb, `FOR SELECT`.
    Read,
    /// The `insert` verb, `FOR INSERT`.
    Insert,
    /// The `update` verb, `FOR UPDATE`.
    Update,
    /// The `delete` verb, `FOR DELETE`.
    Delete,
}

impl Verb {
    /// The column's spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Verb::Read => "read",
            Verb::Insert => "insert",
            Verb::Update => "update",
            Verb::Delete => "delete",
        }
    }

    /// The verb a wire or column spelling names, or `None` for a spelling
    /// outside the four the registry's `CHECK` allows.
    #[must_use]
    pub fn parse(spelled: &str) -> Option<Self> {
        match spelled {
            "read" => Some(Self::Read),
            "insert" => Some(Self::Insert),
            "update" => Some(Self::Update),
            "delete" => Some(Self::Delete),
            _ => None,
        }
    }
}

/// The effective list a bot session carries, the entries its connection
/// binds into [`crate::schema::BOT_LIST_SETTING`] and its replica's
/// [`crate::schema::BOT_LIST_FUNCTION`] answers.
///
/// Held as entries rather than as the joined text, so a list a login
/// resolved travels typed and is rendered only where a setting binds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotList {
    entries: Vec<(String, Verb)>,
}

impl BotList {
    /// A list from its entries, each a table and the verb it declares.
    #[must_use]
    pub fn new(entries: impl IntoIterator<Item = (String, Verb)>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
        }
    }

    /// The entries, in the list's order.
    #[must_use]
    pub fn entries(&self) -> &[(String, Verb)] {
        &self.entries
    }

    /// Whether the list declares nothing, which sees and writes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The text form the session setting carries, the entries' `table:verb`
    /// spellings joined by [`crate::schema::BOT_LIST_SEPARATOR`], the one
    /// renderer of it.
    #[must_use]
    pub fn text(&self) -> String {
        let mut text = String::new();
        for (table, verb) in &self.entries {
            if !text.is_empty() {
                text.push(crate::schema::BOT_LIST_SEPARATOR);
            }
            text.push_str(table);
            text.push(':');
            text.push_str(verb.as_str());
        }
        text
    }
}

#[cfg(feature = "diesel-pg")]
impl BotRegistryIdSql for diesel::sql_types::Text {
    const DDL: &'static str = REGISTRY_DDL_TEXT;
}

#[cfg(feature = "diesel-pg")]
impl BotRegistryIdSql for diesel::sql_types::Uuid {
    const DDL: &'static str = REGISTRY_DDL_UUID;
}

/// The five bot registry tables' diesel `table!` definitions, one column list
/// parameterized by the backend's SQL types.
///
/// The `pg` preset is the Postgres backend's types; the `replica` preset is
/// the SQLite replica's, matching what the translated replica DDL stores
/// (uuid as a 16-byte `BLOB`, `timestamptz` as `TEXT`, `bytea` as `BLOB`).
/// The deployment's `Id` SQL type is the one its id columns carry.
#[macro_export]
macro_rules! connetto_registry_tables {
    (pg, $id_sql:ty) => {
        $crate::__connetto_registry_tables_inner!(
            diesel::sql_types::Uuid,
            diesel::sql_types::Timestamptz,
            diesel::sql_types::Bytea,
            $id_sql
        );
    };
    (replica, $id_sql:ty) => {
        $crate::__connetto_registry_tables_inner!(
            diesel::sql_types::Binary,
            diesel::sql_types::Timestamp,
            diesel::sql_types::Binary,
            $id_sql
        );
    };
}

/// The one column list the [`connetto_registry_tables!`] presets share, taken
/// as the four parameterized SQL types and the deployment's `Id` type.
#[doc(hidden)]
#[macro_export]
macro_rules! __connetto_registry_tables_inner {
    ($uuid_sql:ty, $timestamptz_sql:ty, $bytea_sql:ty, $id_sql:ty) => {
        diesel::table! {
            /// One row per registered bot.
            connetto_bots (id) {
                /// The id connetto minted at the first registration.
                id -> $uuid_sql,
                /// The registration code's creator, the bot's owner.
                owner -> $id_sql,
                /// The name the registration gave it.
                name -> diesel::sql_types::Text,
                /// Its Ed25519 public key, 32 bytes.
                public_key -> $bytea_sql,
                /// The current list version.
                list_version -> diesel::sql_types::Integer,
                /// The wake URL R103 registers for it, absent until then.
                wake_url -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
            }
        }

        diesel::table! {
            /// One row per one-time registration code, its SHA-256 as the key.
            connetto_registration_codes (code_hash) {
                /// The SHA-256 of the code, which the code itself never is.
                code_hash -> $bytea_sql,
                /// The signed-in person who created it.
                creator -> $id_sql,
                /// The bot it names, absent for a first registration.
                bot -> diesel::sql_types::Nullable<$uuid_sql>,
                /// When it stops being usable.
                expires_at -> $timestamptz_sql,
                /// When a registration spent it.
                used_at -> diesel::sql_types::Nullable<$timestamptz_sql>,
            }
        }

        diesel::table! {
            /// One row per table and verb of one bot's list version.
            connetto_bot_lists (bot, version, table_name, verb) {
                /// The bot the version belongs to.
                bot -> $uuid_sql,
                /// The version the row belongs to.
                version -> diesel::sql_types::Integer,
                /// The table the entry names.
                table_name -> diesel::sql_types::Text,
                /// The verb, one of `read`, `insert`, `update` and `delete`.
                verb -> diesel::sql_types::Text,
                /// Whether the entry's table is optional for an installation.
                optional -> diesel::sql_types::Bool,
            }
        }

        diesel::table! {
            /// One row per bot installed for an owner.
            connetto_installations (id) {
                /// The deployment's id of the installation, minted by the
                /// admin's app.
                id -> $id_sql,
                /// The bot it runs.
                bot -> $uuid_sql,
                /// The owner it serves.
                owner -> $id_sql,
                /// The list version the admin accepted.
                accepted_version -> diesel::sql_types::Integer,
            }
        }

        diesel::table! {
            /// One row per optional table an installation accepted.
            connetto_installation_optional_tables (installation, table_name) {
                /// The installation the acceptance belongs to.
                installation -> $id_sql,
                /// The optional table it accepted.
                table_name -> diesel::sql_types::Text,
            }
        }

        diesel::allow_tables_to_appear_in_same_query!(
            connetto_installations,
            connetto_installation_optional_tables,
        );
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two DDL variants differ only in the five id columns' type, and each
    /// names all five registry tables.
    #[test]
    fn the_ddl_variants_cover_the_five_tables_and_differ_only_in_the_id_type() {
        for ddl in [REGISTRY_DDL_TEXT, REGISTRY_DDL_UUID] {
            for table in [
                "connetto_bots",
                "connetto_registration_codes",
                "connetto_bot_lists",
                "connetto_installations",
                "connetto_installation_optional_tables",
            ] {
                assert!(
                    ddl.contains(&format!("CREATE TABLE {table} ")),
                    "{ddl} names {table}"
                );
            }
        }
        // The TEXT variant types the id columns TEXT, the UUID variant UUID.
        assert!(REGISTRY_DDL_TEXT.contains("owner TEXT NOT NULL"));
        assert!(REGISTRY_DDL_TEXT.contains("creator TEXT NOT NULL"));
        assert!(REGISTRY_DDL_TEXT.contains("installation TEXT NOT NULL"));
        assert!(REGISTRY_DDL_UUID.contains("owner UUID NOT NULL"));
        assert!(REGISTRY_DDL_UUID.contains("creator UUID NOT NULL"));
        assert!(REGISTRY_DDL_UUID.contains("installation UUID NOT NULL"));
        // The bot's own id is always the UUID connetto mints, in both variants.
        assert!(REGISTRY_DDL_TEXT.contains("connetto_bots (id UUID PRIMARY KEY"));
        assert!(REGISTRY_DDL_UUID.contains("connetto_bots (id UUID PRIMARY KEY"));
    }

    /// The markers and the diesel id types name the same DDL, so a build
    /// script and a server over the same deployment agree on the variant.
    #[test]
    fn the_markers_and_the_diesel_id_types_name_the_same_ddl() {
        assert_eq!(registry_ddl::<TextIds>(), REGISTRY_DDL_TEXT);
        assert_eq!(registry_ddl::<UuidIds>(), REGISTRY_DDL_UUID);
        #[cfg(feature = "diesel-pg")]
        {
            assert_eq!(registry_ddl::<diesel::sql_types::Text>(), REGISTRY_DDL_TEXT);
            assert_eq!(registry_ddl::<diesel::sql_types::Uuid>(), REGISTRY_DDL_UUID);
        }
    }

    /// The canonical form is case-insensitive to the operator and to the
    /// group separators and whitespace, and a character outside the base32
    /// alphabet survives the form rather than being dropped, so it changes
    /// the hash and reads as a wrong code.
    #[test]
    fn the_canonical_form_folds_case_separators_and_keeps_foreign_characters() {
        for typed in [
            "K7Q2-9XAB-CDEF",
            "k7q2-9xab-cdef",
            "K7Q29XABCDEF",
            "k7q2 9xab cdef",
        ] {
            assert_eq!(
                canonical_code(typed),
                "K7Q29XABCDEF",
                "{typed} reads as the one canonical form"
            );
        }
        // A digit outside the base32 alphabet is kept, so the form differs
        // from the code it was typed from and the lookup misses.
        assert_eq!(canonical_code("k7q2-9xa0b"), "K7Q29XA0B");
    }

    /// The four spellings parse, and a spelling outside the four does not.
    #[test]
    fn the_four_verbs_parse_and_a_foreign_spelling_does_not() {
        assert_eq!(Verb::parse("read"), Some(Verb::Read));
        assert_eq!(Verb::parse("insert"), Some(Verb::Insert));
        assert_eq!(Verb::parse("update"), Some(Verb::Update));
        assert_eq!(Verb::parse("delete"), Some(Verb::Delete));
        assert_eq!(Verb::parse("drop"), None);
        assert_eq!(Verb::parse("*"), None);
        assert_eq!(
            [Verb::Read, Verb::Insert, Verb::Update, Verb::Delete,]
                .iter()
                .map(|verb| verb.as_str())
                .collect::<Vec<_>>(),
            ["read", "insert", "update", "delete"]
        );
    }

    /// The list's text is its entries' `table:verb` spellings joined by the
    /// separator, in the list's order, and an empty list renders to nothing.
    #[test]
    fn the_list_renders_its_entries_in_order() {
        let list = BotList::new([
            ("orders".to_owned(), Verb::Read),
            ("orders".to_owned(), Verb::Insert),
            ("invoices".to_owned(), Verb::Read),
        ]);
        assert_eq!(list.text(), "orders:read,orders:insert,invoices:read");
        assert_eq!(
            list.entries(),
            &[
                ("orders".to_owned(), Verb::Read),
                ("orders".to_owned(), Verb::Insert),
                ("invoices".to_owned(), Verb::Read),
            ]
        );
        assert!(!list.is_empty());
        let empty = BotList::new([]);
        assert!(empty.is_empty());
        assert_eq!(empty.text(), "");
    }
}
