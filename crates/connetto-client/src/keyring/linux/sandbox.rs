//! libsecret's sandbox keyring, a file opened with the Secret portal's
//! per-application secret (R71 decision 14).

use std::path::{Path, PathBuf};

use oo7::file::{Item, UnlockedKeyring};

use super::{attributes, backend_error, decode, encode};
use crate::ClientError;
use crate::keyring::SecretStoreError;

pub(super) struct Sandbox {
    keyring: UnlockedKeyring,
}

impl Sandbox {
    pub(super) async fn open() -> Result<Self, ClientError> {
        let bound = super::secret_service::PROMPT_BOUND;
        let secret = tokio::time::timeout(bound, oo7::ashpd::desktop::secret::retrieve())
            .await
            .map_err(|_| SecretStoreError::TimedOut(bound))?
            .map_err(|err| backend_error("the Secret portal", err))?;
        let path = keyring_path().ok_or_else(|| {
            SecretStoreError::Backend(
                "the sandbox has no data directory for its keyring".to_owned(),
            )
        })?;
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

/// libsecret's own path for the sandbox keyring, which `oo7` keeps crate-private.
fn keyring_path() -> Option<PathBuf> {
    let data = std::env::var_os("XDG_DATA_HOME")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|home| !home.is_empty())
                .map(|home| PathBuf::from(home).join(".local/share"))
        })?;
    Some(data.join("keyrings").join("default.keyring"))
}
