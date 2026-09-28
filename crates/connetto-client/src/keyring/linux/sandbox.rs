//! libsecret's sandbox keyring, a file opened with the Secret portal's
//! per-application secret (R71 decision 14).

use std::ffi::OsString;
use std::io::Read as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use oo7::ashpd::desktop::secret::{RetrieveOptions, Secret};
use oo7::file::{Item, UnlockedKeyring};
use zeroize::Zeroizing;

use super::{attributes, backend_error, decode, encode};
use crate::ClientError;
use crate::keyring::SecretStoreError;

pub(super) struct Sandbox {
    keyring: UnlockedKeyring,
}

impl Sandbox {
    pub(super) async fn open() -> Result<Self, ClientError> {
        let bus = zbus::Connection::session()
            .await
            .map_err(|err| backend_error("the session bus", err))?;
        Self::open_with(&bus, super::secret_service::PROMPT_BOUND, keyring_path()).await
    }

    /// The keyring at `path`, opened with the secret the portal on `bus` hands
    /// over within `bound`.
    pub(super) async fn open_with(
        bus: &zbus::Connection,
        bound: Duration,
        path: Option<PathBuf>,
    ) -> Result<Self, ClientError> {
        let path = path.ok_or_else(|| {
            SecretStoreError::Backend(
                "the sandbox has no data directory for its keyring".to_owned(),
            )
        })?;
        let secret = tokio::time::timeout(bound, portal_secret(bus))
            .await
            .map_err(|_| SecretStoreError::TimedOut(bound))??;
        Self::load(&path, oo7::Secret::from(secret)).await
    }

    pub(super) async fn load(path: &Path, secret: oo7::Secret) -> Result<Self, ClientError> {
        Ok(Self {
            keyring: UnlockedKeyring::load(path, secret)
                .await
                .map_err(|err| backend_error("the sandbox keyring", err))?,
        })
    }

    pub(super) async fn read(
        &self,
        service: &str,
        name: &str,
    ) -> Result<Option<String>, ClientError> {
        let item = self
            .keyring
            .lookup_item(&attributes(service, name))
            .await
            .map_err(|err| backend_error("the sandbox keyring", err))?;
        match item {
            Some(Item::Unlocked(item)) => decode(&item.secret()).map(Some),
            Some(Item::Locked(_)) => Err(SecretStoreError::Backend(
                "a sandbox keyring item does not open under the portal's secret".to_owned(),
            )
            .into()),
            None => Ok(None),
        }
    }

    pub(super) async fn write(
        &self,
        service: &str,
        name: &str,
        secret: &str,
    ) -> Result<(), ClientError> {
        self.keyring
            .create_item(
                service,
                &attributes(service, name),
                oo7::Secret::text(encode(secret).as_str()),
                true,
            )
            .await
            .map(drop)
            .map_err(|err| backend_error("the sandbox keyring", err))
    }

    pub(super) async fn clear(&self, service: &str, name: &str) -> Result<(), ClientError> {
        self.keyring
            .delete(&attributes(service, name))
            .await
            .map_err(|err| backend_error("the sandbox keyring", err))
    }
}

/// The application's own secret, which the portal writes into a socket it is handed.
async fn portal_secret(bus: &zbus::Connection) -> Result<Zeroizing<Vec<u8>>, ClientError> {
    let portal = Secret::with_connection(bus.clone())
        .await
        .map_err(|err| backend_error("the Secret portal", err))?;
    let (mut reader, writer) =
        UnixStream::pair().map_err(|err| backend_error("the Secret portal socket", err))?;
    portal
        .retrieve(&writer, RetrieveOptions::default())
        .await
        .map_err(|err| backend_error("the Secret portal", err))?;
    // The portal holds its own copy, so the read below ends once the portal closes it.
    drop(writer);
    tokio::task::spawn_blocking(move || {
        let mut secret = Zeroizing::new(Vec::with_capacity(64));
        reader.read_to_end(&mut secret).map(|_| secret)
    })
    .await
    .map_err(|err| backend_error("the Secret portal socket", err))?
    .map_err(|err| backend_error("the Secret portal socket", err))
}

/// libsecret's own path for the sandbox keyring, which `oo7` keeps crate-private.
fn keyring_path() -> Option<PathBuf> {
    keyring_path_from(std::env::var_os("XDG_DATA_HOME"), std::env::var_os("HOME"))
}

/// The keyring path under `XDG_DATA_HOME` when it is absolute, else under `HOME`.
pub(super) fn keyring_path_from(
    xdg_data_home: Option<OsString>,
    home: Option<OsString>,
) -> Option<PathBuf> {
    let data = xdg_data_home
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
        .or_else(|| {
            home.filter(|home| !home.is_empty())
                .map(|home| PathBuf::from(home).join(".local/share"))
        })?;
    Some(data.join("keyrings").join("default.keyring"))
}
