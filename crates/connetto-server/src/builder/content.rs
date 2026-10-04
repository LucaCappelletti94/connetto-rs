//! The file-serving half of the assembled server: its settings, its chunk
//! store, and the build that mounts its routes beside the login endpoints.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use axum::Router;
use thiserror::Error;

use crate::builder::PoolError;
#[cfg(feature = "content")]
use crate::builder::build_pool;
#[cfg(feature = "content")]
use connetto_file_server::{
    self as files, AnyStore, DbPool, FsStore, PreflightError, TicketSigner, TicketVerifier,
};

/// The chunk store the file half serves.
#[derive(Clone, Debug)]
pub enum StoreSpec {
    /// A directory chunk store.
    Fs(PathBuf),
    /// An `object_store` URL backend.
    Object(url::Url),
}

impl StoreSpec {
    /// Parse a store spec, `fs:<dir>` for the directory store and anything
    /// else an `object_store` URL.
    ///
    /// # Errors
    ///
    /// [`ContentBuildError::StoreSpec`] when the spec is neither `fs:` nor a URL.
    pub fn parse(spec: &str) -> Result<Self, ContentBuildError> {
        if let Some(dir) = spec.strip_prefix("fs:") {
            if dir.trim().is_empty() {
                return Err(ContentBuildError::StoreSpec {
                    spec: spec.to_owned(),
                    reason: "fs: needs a directory".to_owned(),
                });
            }
            return Ok(Self::Fs(PathBuf::from(dir)));
        }
        url::Url::parse(spec)
            .map(Self::Object)
            .map_err(|err| ContentBuildError::StoreSpec {
                spec: spec.to_owned(),
                reason: err.to_string(),
            })
    }
}

/// Why the file half refused to build.
#[derive(Debug, Error)]
pub enum ContentBuildError {
    /// The chunk store spec did not name a store.
    #[error("the chunk store spec {spec:?} names no store: {reason}")]
    StoreSpec {
        /// The spec as handed over.
        spec: String,
        /// Why it names no store.
        reason: String,
    },
    /// The chunk store would not open.
    #[error("opening the chunk store: {0}")]
    OpenStore(String),
    /// The ticket key would not load.
    #[cfg(feature = "content")]
    #[error("loading the content ticket key: {0}")]
    TicketKey(#[from] files::ticket::TicketError),
    /// A Postgres pool for the file routes would not build.
    #[error(transparent)]
    Pool(#[from] PoolError),
    /// The file server's preflight failed.
    #[cfg(feature = "content")]
    #[error("content preflight: {0}")]
    Preflight(#[from] PreflightError),
    /// The chunk store and the database would not reconcile.
    #[cfg(feature = "content")]
    #[error("reconciling the chunk store with the database: {0}")]
    Reconcile(#[from] files::ReconcileError),
    /// The bandwidth window names no UTC day row.
    #[error("the bandwidth window must name at least one UTC day row")]
    BandwidthWindow,
}

/// The resolved file settings, read once before building the file half.
#[derive(Clone)]
pub struct ContentSettings {
    /// The address the file routes answer on, with no trailing slash, query
    /// or fragment.
    pub base_url: String,
    /// Ticket lifetime, which is a ticket's revocation lag.
    pub ttl: Duration,
    /// The bytes one response may serve under a read ticket.
    pub read_ceiling: u64,
    /// How long a recent manifest is spared by the sweep.
    pub grace: Duration,
    /// How often the sweep runs, zero turning it off.
    pub cadence: Duration,
    /// The bytes one uploader may hold across committed manifests, zero
    /// unlimited.
    pub quota_identity: u64,
    /// The deployment-wide stored bytes over distinct committed chunks, zero
    /// unlimited.
    pub storage_ceiling: u64,
    /// The deployment-wide bytes served plus accepted inside the window, zero
    /// unlimited.
    pub bandwidth_ceiling: u64,
    /// The trailing window length in UTC day rows.
    pub bandwidth_window_days: i32,
    /// The fraction of each ceiling where one warning fires per crossing.
    pub warn_fraction: f64,
    /// How often a replica re-reads the cached deployment totals.
    pub ceiling_refresh: Duration,
    /// The size of the owner pool the file routes build for themselves.
    pub owner_pool_size: u32,
    /// The chunk store.
    pub store: StoreSpec,
    /// The ticket keypair, PKCS8 DER Ed25519.
    pub key: Vec<u8>,
}

impl fmt::Debug for ContentSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentSettings")
            .field("base_url", &self.base_url)
            .field("ttl", &self.ttl)
            .field("read_ceiling", &self.read_ceiling)
            .field("grace", &self.grace)
            .field("cadence", &self.cadence)
            .field("quota_identity", &self.quota_identity)
            .field("storage_ceiling", &self.storage_ceiling)
            .field("bandwidth_ceiling", &self.bandwidth_ceiling)
            .field("bandwidth_window_days", &self.bandwidth_window_days)
            .field("warn_fraction", &self.warn_fraction)
            .field("ceiling_refresh", &self.ceiling_refresh)
            .field("owner_pool_size", &self.owner_pool_size)
            .field("store", &self.store)
            .field("key", &"present")
            .finish()
    }
}

impl ContentSettings {
    /// Refuse the settings that would serve a meter that never trips.
    ///
    /// # Errors
    ///
    /// [`ContentBuildError::BandwidthWindow`] when the window is under one day.
    pub fn validate(&self) -> Result<(), ContentBuildError> {
        if self.bandwidth_window_days < 1 {
            return Err(ContentBuildError::BandwidthWindow);
        }
        Ok(())
    }
}

/// Open the store one spec names.
#[cfg(feature = "content")]
fn open_store(spec: &StoreSpec) -> Result<AnyStore, ContentBuildError> {
    match spec {
        StoreSpec::Fs(dir) => Ok(AnyStore::Fs(FsStore::new(dir).map_err(|err| {
            ContentBuildError::OpenStore(format!("{}: {err}", dir.display()))
        })?)),
        StoreSpec::Object(url) => AnyStore::from_url(url)
            .map_err(|err| ContentBuildError::OpenStore(format!("{url}: {err}"))),
    }
}

/// The file server's own signer over the one keypair the deployment keeps,
/// with the public half the mounted routes verify with.
#[cfg(feature = "content")]
fn ticket_keypair(
    settings: &ContentSettings,
) -> Result<(TicketSigner, Vec<u8>), ContentBuildError> {
    let signer = TicketSigner::from_pkcs8_der(
        &settings.key,
        &settings.base_url,
        settings.ttl,
        settings.read_ceiling,
    )?;
    let public = signer.public_key_bytes().to_vec();
    Ok((signer, public))
}

/// Reclaim unreferenced chunks on a cadence, the way the slot watch runs,
/// handing back the loop's stop handle so a refusal after it started cannot
/// leave it running. A failed pass is logged, not fatal, the next pass
/// retries what it lost.
#[cfg(feature = "content")]
fn spawn_sweep<D: crate::schema::ConnettoSchema>(
    admin: DbPool,
    spec: StoreSpec,
    grace: Duration,
    cadence: Duration,
) -> Option<super::BackgroundTask> {
    if cadence.is_zero() {
        return None;
    }
    Some(super::BackgroundTask::new(tokio::spawn(async move {
        let store = match open_store(&spec) {
            Ok(store) => store,
            Err(err) => {
                tracing::error!(error = %err, "the content sweep has no store");
                return;
            }
        };
        let mut ticker = tokio::time::interval(cadence);
        // The first tick completes at once, before the deployment can have
        // orphaned anything, so spend it here.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match files::sweep::<D::Files>(&admin, &store, grace).await {
                Ok(0) => {}
                Ok(removed) => {
                    tracing::info!(removed, "content sweep reclaimed unreferenced chunks");
                }
                Err(err) => tracing::warn!(error = %err, "content sweep failed"),
            }
        }
    })))
}

/// The file-serving half of the deployment.
///
/// `settings` absent answers no signer and no router, which is the
/// no-files deployment. Present, the store opens, the keypair loads, and
/// the file server's preflight runs before serving proceeds, so a
/// deployment missing its `_cfs_` tables or its two contract functions
/// refuses to start naming what is absent.
///
/// The pools are the file router's own two, built from the same conninfos,
/// so an upload never queues behind the change stream for the owner pool
/// and a bulk read never spends the change path's reader share (R81's
/// finding).
#[cfg(feature = "content")]
pub(crate) async fn build<D: crate::schema::ConnettoSchema>(
    settings: Option<ContentSettings>,
    owner_url: &str,
    reader_url: &str,
    reader_pool_size: u32,
) -> Result<
    (
        super::ContentSigner,
        Option<Router>,
        Option<super::BackgroundTask>,
    ),
    ContentBuildError,
> {
    let Some(settings) = settings else {
        return Ok((super::ContentSigner::None, None, None));
    };
    settings.validate()?;
    let (signer, public) = ticket_keypair(&settings)?;
    let admin = build_pool(owner_url, settings.owner_pool_size).await?;
    let reader = build_pool(reader_url, reader_pool_size).await?;
    let router = files::serve(files::Config::<D::Files> {
        pools: files::AppPools {
            admin: admin.clone(),
            reader,
        },
        store: open_store(&settings.store)?,
        verifier: TicketVerifier::new(public),
        grace: settings.grace,
        // The server binds the caller under connetto's default names, which
        // is what its session manager is left configured with.
        caller_settings: files::CallerSettings::default(),
        quotas: files::QuotaSettings {
            identity_quota: settings.quota_identity,
            storage_ceiling: settings.storage_ceiling,
            bandwidth_ceiling: settings.bandwidth_ceiling,
            window_days: settings.bandwidth_window_days,
            warn_fraction: settings.warn_fraction,
            refresh: settings.ceiling_refresh,
        },
        ceilings: files::CeilingCache::default(),
        _schema: std::marker::PhantomData,
    })
    .await?;
    let reconciled = files::reconcile_store::<D::Files>(
        &admin,
        &open_store(&settings.store)?,
        &files::CallerSettings::default(),
        settings.grace,
    )
    .await?;
    if reconciled.orphans_removed > 0 || !reconciled.lost.is_empty() {
        tracing::warn!(
            orphans_removed = reconciled.orphans_removed,
            lost = reconciled.lost.len(),
            "the chunk store and the database disagreed, reconciled before serving",
        );
    }
    let sweep = spawn_sweep::<D>(
        admin,
        settings.store.clone(),
        settings.grace,
        settings.cadence,
    );
    tracing::info!(
        base = %settings.base_url,
        store = ?settings.store,
        ticket_ttl_secs = settings.ttl.as_secs(),
        sweep_secs = settings.cadence.as_secs(),
        quota_bytes = settings.quota_identity,
        storage_ceiling = settings.storage_ceiling,
        bandwidth_ceiling = settings.bandwidth_ceiling,
        bandwidth_window_days = settings.bandwidth_window_days,
        "file routes mounted beside the login endpoints",
    );
    Ok((
        super::ContentSigner::Files(Box::new(signer)),
        Some(router),
        sweep,
    ))
}

/// The no-op shape of [`build`] for a server built without the `content`
/// feature. A configured deployment still hears about it.
#[cfg(not(feature = "content"))]
#[expect(
    clippy::extra_unused_type_parameters,
    reason = "one call site serves both builds, and the content build reads the schema's file member"
)]
pub(crate) async fn build<D: crate::schema::ConnettoSchema>(
    settings: Option<ContentSettings>,
    _owner_url: &str,
    _reader_url: &str,
    _reader_pool_size: u32,
) -> Result<
    (
        super::ContentSigner,
        Option<Router>,
        Option<super::BackgroundTask>,
    ),
    ContentBuildError,
> {
    if settings.is_some() {
        tracing::warn!(
            "file settings were handed over but this server was built without \
             the content feature, so no file routes are mounted"
        );
    }
    Ok((super::ContentSigner::None, None, None))
}

#[cfg(all(test, feature = "content"))]
mod tests {
    use super::*;
    use connetto_core::messages::ContentVerb;
    use connetto_core::traits::ContentTicketSigner;

    /// A caller carrying only an identity, which is what these mints exercise.
    fn identified(user_id: &str) -> connetto_core::auth::ContentCaller {
        connetto_core::auth::ContentCaller::new(Some(user_id.to_owned()), None)
    }

    #[test]
    fn fs_prefix_names_a_directory() {
        match StoreSpec::parse("fs:/var/lib/connetto/content").expect("a directory store") {
            StoreSpec::Fs(dir) => assert_eq!(dir.as_os_str(), "/var/lib/connetto/content"),
            StoreSpec::Object(_) => panic!("fs: names the directory store"),
        }
    }

    #[test]
    fn an_object_url_names_an_object_store() {
        match StoreSpec::parse("s3://bucket/prefix").expect("an object store") {
            StoreSpec::Object(url) => assert_eq!(url.scheme(), "s3"),
            StoreSpec::Fs(_) => panic!("a url names an object store"),
        }
    }

    #[test]
    fn fs_without_a_directory_and_an_unparsable_url_are_refused() {
        assert!(StoreSpec::parse("fs:").is_err());
        assert!(StoreSpec::parse("not a url").is_err());
    }

    #[tokio::test]
    async fn a_keypair_loaded_from_der_mints_what_its_public_half_verifies() {
        let rng = ring::rand::SystemRandom::new();
        let doc = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("a fresh key");
        let signer = connetto_file_server::TicketSigner::from_pkcs8_der(
            doc.as_ref(),
            "http://127.0.0.1:8081",
            Duration::from_secs(60),
            1 << 20,
        )
        .expect("a keypair from its DER");
        let url = ContentTicketSigner::mint(
            &signer,
            &identified("caller-1"),
            [7u8; 32],
            ContentVerb::Read,
        )
        .await
        .expect("a minted read url");
        let token = url.split_once("?t=").expect("the token rides the url").1;
        let payload = connetto_file_server::TicketVerifier::new(signer.public_key_bytes().to_vec())
            .verify(token)
            .expect("the minted token verifies");
        assert_eq!(payload.file_id, [7u8; 32]);
        assert_eq!(payload.caller.identity(), Some("caller-1"));
    }

    #[tokio::test]
    async fn an_ephemeral_keypair_mints_what_its_public_half_verifies() {
        let (signer, public) = connetto_file_server::TicketSigner::generate(
            "http://127.0.0.1:8081",
            Duration::from_secs(60),
            1 << 20,
        )
        .expect("an ephemeral keypair");
        let url = ContentTicketSigner::mint(
            &signer,
            &identified("caller-2"),
            [9u8; 32],
            ContentVerb::Write { declared_len: 128 },
        )
        .await
        .expect("a minted write url");
        assert!(url.starts_with("http://127.0.0.1:8081/files/"));
        assert!(url.contains("/intent?t="));
        let token = url.split_once("?t=").expect("the token rides the url").1;
        let payload = connetto_file_server::TicketVerifier::new(public)
            .verify(token)
            .expect("the minted token verifies");
        assert_eq!(payload.file_id, [9u8; 32]);
    }

    /// The photo table and the two contract functions a configured deployment applies.
    const DEPLOYMENT_SQL: &[&str] = &[
        "CREATE TABLE photos (content_id BYTEA PRIMARY KEY, content_state TEXT NOT NULL \
             DEFAULT 'staged')",
        "CREATE OR REPLACE FUNCTION connetto_visible_files(p_file_ids BYTEA[]) \
             RETURNS BYTEA[] LANGUAGE sql SECURITY INVOKER SET search_path TO '' AS $$ \
             SELECT ARRAY(SELECT f FROM UNNEST(p_file_ids) AS f \
             WHERE EXISTS (SELECT 1 FROM public.photos p WHERE p.content_id = f)) $$",
        "CREATE OR REPLACE FUNCTION connetto_set_content_state(p_file_id BYTEA, \
             p_new_state TEXT, p_caller TEXT) RETURNS BYTEA \
             LANGUAGE plpgsql SECURITY DEFINER SET search_path TO '' \
             AS $$ BEGIN UPDATE public.photos SET content_state = p_new_state \
             WHERE content_id = p_file_id; RETURN p_file_id; END; $$",
    ];

    /// The no-files deployment is the common one: no settings, no signer, no
    /// router.
    #[tokio::test]
    async fn a_deployment_without_settings_mounts_nothing() {
        use crate::builder::ContentSigner;
        let (signer, router, _) = build::<crate::defaults::ConnettoDefaults>(
            None,
            "postgres://unused",
            "postgres://unused",
            1,
        )
        .await
        .expect("no settings is a valid deployment");
        assert!(matches!(signer, ContentSigner::None));
        assert!(router.is_none());
    }

    /// A configured deployment builds the whole file half in process:
    /// the deployment DDL, the router's preflight, a signer whose mints
    /// the mounted routes would verify, and one sweep tick reclaimed on
    /// the cadence.
    #[tokio::test]
    async fn a_configured_deployment_mounts_routes_and_sweeps() {
        use diesel_async::RunQueryDsl as _;
        let fixture = connetto_test_harness::Fixture::acquire().await;
        let admin_url = fixture.admin_url().to_owned();
        let pool = build_pool(&admin_url, 2)
            .await
            .expect("a pool on the fixture");
        let mut conn = pool.get().await.expect("a connection");
        for stmt in [
            "DROP TABLE IF EXISTS photos CASCADE",
            "DROP TABLE IF EXISTS _cfs_manifest_chunks CASCADE",
            "DROP TABLE IF EXISTS _cfs_manifests CASCADE",
            "DROP TABLE IF EXISTS _cfs_chunk_registry CASCADE",
            "DROP TABLE IF EXISTS _cfs_traffic CASCADE",
            "DROP FUNCTION IF EXISTS connetto_visible_files(BYTEA[])",
            "DROP FUNCTION IF EXISTS connetto_set_content_state(BYTEA, TEXT, TEXT)",
        ] {
            diesel::sql_query(stmt)
                .execute(&mut *conn)
                .await
                .expect("a clean slate");
        }
        for stmt in connetto_file_server::DEPLOYMENT_DDL.split(';') {
            let meaningful = stmt
                .lines()
                .any(|line| !line.trim().is_empty() && !line.trim_start().starts_with("--"));
            if meaningful {
                diesel::sql_query(stmt.trim())
                    .execute(&mut *conn)
                    .await
                    .expect("the deployment applies");
            }
        }
        for stmt in DEPLOYMENT_SQL {
            diesel::sql_query(*stmt)
                .execute(&mut *conn)
                .await
                .expect("the contract applies");
        }
        for stmt in [
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_reader') \
             THEN CREATE ROLE app_reader LOGIN PASSWORD 'app_reader'; END IF; END $$",
            "GRANT USAGE ON SCHEMA public TO app_reader",
            "GRANT SELECT ON photos TO app_reader",
            "GRANT SELECT ON _cfs_chunk_registry, _cfs_manifests, _cfs_manifest_chunks \
             TO app_reader",
        ] {
            diesel::sql_query(stmt)
                .execute(&mut *conn)
                .await
                .expect("the reader role can read the deployment");
        }
        let reader_url = connetto_test_harness::with_user(&admin_url, "app_reader", "app_reader");
        drop(conn);
        let dir = tempfile::tempdir().expect("a chunk directory");
        let doc = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .expect("a ticket key");
        let settings = ContentSettings {
            base_url: "http://127.0.0.1:8099".to_owned(),
            ttl: Duration::from_secs(60),
            read_ceiling: 1 << 20,
            grace: Duration::ZERO,
            cadence: Duration::from_secs(1),
            quota_identity: 0,
            storage_ceiling: 0,
            bandwidth_ceiling: 0,
            bandwidth_window_days: 30,
            warn_fraction: 0.8,
            ceiling_refresh: Duration::from_secs(10),
            owner_pool_size: 2,
            store: StoreSpec::Fs(dir.path().to_path_buf()),
            key: doc.as_ref().to_vec(),
        };
        // The sweep's guard stays alive until the tick below, then stops it.
        let (signer, router, _sweep) =
            build::<crate::defaults::ConnettoDefaults>(Some(settings), &admin_url, &reader_url, 2)
                .await
                .expect("a configured deployment builds");
        let url = ContentTicketSigner::mint(
            &signer,
            &identified("caller-9"),
            [3u8; 32],
            ContentVerb::Read,
        )
        .await
        .expect("the deployment signer mints");
        assert!(url.starts_with("http://127.0.0.1:8099/files/"));
        assert!(router.is_some(), "the file router rides the listener");
        // One sweep tick at the cadence, so the reclaim arm runs.
        tokio::time::sleep(Duration::from_millis(1_300)).await;
    }
}
