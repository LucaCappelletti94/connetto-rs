//! The schema half of a client build.

use std::collections::HashSet;
use std::sync::Arc;

use connetto_core::schema::SchemaBundle;
use connetto_core::schema::UUID_FUNCTION;

use crate::PolicyTables;
use crate::SqlFunctions;

/// A translated schema and the client-side registrations its DDL reaches, as
/// one value.
///
/// Every build registers `uuidv4()`, because a synced column `DEFAULT` may
/// call it and a device without a server still has to mint the id. The
/// application adds its own functions with
/// [`with_sql_functions`](Self::with_sql_functions).
#[derive(Clone)]
pub struct SyncSchema {
    bundle: SchemaBundle,
    policy_tables: PolicyTables,
    sql_functions: SqlFunctions,
    unrecorded: HashSet<String>,
    /// Both tiers as one main-schema DDL, for a relay tab's mirror.
    mirror_ddl: Option<String>,
}

impl SyncSchema {
    /// Wrap a translated schema and register `uuidv4()`.
    #[must_use]
    pub fn new(bundle: SchemaBundle) -> Self {
        let policy_tables = PolicyTables::from_translation(
            bundle
                .policy_tables()
                .iter()
                .map(|(logical, physical)| (logical.as_str(), physical.as_str())),
            bundle.policy_views().iter().cloned(),
        );
        Self {
            bundle,
            policy_tables,
            sql_functions: uuidv4_installer(),
            unrecorded: HashSet::new(),
            mirror_ddl: None,
        }
    }

    /// Add the application's own function installers alongside `uuidv4()`.
    #[must_use]
    pub fn with_sql_functions(mut self, functions: SqlFunctions) -> Self {
        self.sql_functions = self.sql_functions.merged(functions);
        self
    }

    /// Name the tables whose missing key is intentional, so connetto records
    /// nothing for them and the schema's unkeyed tables are not refused.
    #[must_use]
    pub fn with_unrecorded_tables(
        mut self,
        tables: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.unrecorded = tables.into_iter().map(Into::into).collect();
        self
    }

    /// The same schema as a relay tab's mirror runs it, both tiers in the
    /// main schema.
    ///
    /// A relay applies every patch it serves a tab, synced and device-private
    /// alike, to the tab's main schema, and the relay itself keeps the tiers
    /// apart. The version stays the bundle's, which is what the worker the
    /// relay speaks for presents.
    #[must_use]
    pub fn relay_mirror(mut self) -> Self {
        if let Some(tier) = self.bundle.local_tier_ddl() {
            self.mirror_ddl = Some(format!("{}\n{tier}", self.bundle.replica_ddl()));
        }
        self
    }

    /// The translated replica DDL a first boot applies.
    #[must_use]
    pub fn replica_ddl(&self) -> &str {
        self.mirror_ddl
            .as_deref()
            .unwrap_or_else(|| self.bundle.replica_ddl())
    }

    /// The translated device-private tier DDL, absent when the build has none
    /// or when the schema is a relay mirror, whose tier lives in main.
    #[must_use]
    pub fn local_tier_ddl(&self) -> Option<&str> {
        match self.mirror_ddl {
            Some(_) => None,
            None => self.bundle.local_tier_ddl(),
        }
    }

    /// The schema version the handshake reports.
    #[must_use]
    pub fn version(&self) -> connetto_core::schema::SchemaVersion {
        self.bundle.version()
    }

    /// The RLS split the sync boundaries rename through.
    #[must_use]
    pub fn policy_tables(&self) -> &PolicyTables {
        &self.policy_tables
    }

    /// The function installers, `uuidv4()` first and the application's after.
    #[must_use]
    pub fn sql_functions(&self) -> &SqlFunctions {
        &self.sql_functions
    }

    /// The device-only tables, lowercased.
    #[must_use]
    pub fn unrecorded_tables(&self) -> &HashSet<String> {
        &self.unrecorded
    }
}

/// The installer that registers `uuidv4()`.
fn uuidv4_installer() -> SqlFunctions {
    SqlFunctions::new().with(Arc::new(|conn| {
        // diesel's own registrar seam, hidden API by design, since the function
        // is client-side only and must exist before any DDL runs.
        conn.register_noarg_sql_function::<diesel::sql_types::Binary, _, _>(
            UUID_FUNCTION,
            diesel::sqlite::SqliteFunctionBehavior::INNOCUOUS,
            || uuid::Uuid::new_v4().into_bytes(),
        )
    }))
}
