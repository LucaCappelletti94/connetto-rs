//! The Secret Service's default collection through `oo7`, unlocked or created
//! first through a prompt connetto bounds (R71 decisions 2, 6, 10 and 12).

use std::collections::HashMap;
use std::time::Duration;

use futures_util::StreamExt as _;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

use super::{attributes, backend_error, decode, encode};
use crate::ClientError;
use crate::keyring::SecretStoreError;

/// How long a desktop dialog may stay unanswered before it is dismissed.
pub(super) const PROMPT_BOUND: Duration = Duration::from_secs(120);
const BUS_NAME: &str = "org.freedesktop.secrets";
const DEFAULT_ALIAS: &str = "default";
/// libsecret's label for the collection it creates under the default alias.
const DEFAULT_LABEL: &str = "Default keyring";
const LABEL_PROPERTY: &str = "org.freedesktop.Secret.Collection.Label";
/// The Secret Service's "no object" path.
const NONE: &str = "/";

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Service",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets",
    gen_blocking = false
)]
trait Secrets {
    fn read_alias(&self, name: &str) -> zbus::Result<OwnedObjectPath>;

    fn create_collection(
        &self,
        properties: HashMap<&str, Value<'_>>,
        alias: &str,
    ) -> zbus::Result<(OwnedObjectPath, OwnedObjectPath)>;

    fn unlock(
        &self,
        objects: &[ObjectPath<'_>],
    ) -> zbus::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)>;
}

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Collection",
    default_service = "org.freedesktop.secrets",
    gen_blocking = false
)]
trait SecretCollection {
    #[zbus(property(emits_changed_signal = "false"))]
    fn locked(&self) -> zbus::Result<bool>;
}

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Prompt",
    default_service = "org.freedesktop.secrets",
    gen_blocking = false
)]
trait SecretPrompt {
    fn prompt(&self, window_id: &str) -> zbus::Result<()>;

    fn dismiss(&self) -> zbus::Result<()>;

    #[zbus(signal)]
    fn completed(&self, dismissed: bool, result: OwnedValue) -> zbus::Result<()>;
}

/// The session bus, when it carries a Secret Service or can start one.
pub(super) async fn session_bus() -> Option<zbus::Connection> {
    let bus = zbus::Connection::session().await.ok()?;
    let dbus = zbus::fdo::DBusProxy::new(&bus).await.ok()?;
    let name = zbus::names::BusName::try_from(BUS_NAME).ok()?;
    if dbus.name_has_owner(name).await.unwrap_or(false) {
        return Some(bus);
    }
    let activatable = dbus.list_activatable_names().await.ok()?;
    activatable
        .iter()
        .any(|name| name.as_str() == BUS_NAME)
        .then_some(bus)
}

/// Makes the default collection exist and unlocked, through prompts that are
/// dismissed once `bound` passes.
pub(super) async fn ensure_default(
    bus: &zbus::Connection,
    bound: Duration,
) -> Result<(), ClientError> {
    let secrets = SecretsProxy::new(bus).await.map_err(dbus_error)?;
    let mut collection = secrets
        .read_alias(DEFAULT_ALIAS)
        .await
        .map_err(dbus_error)?;
    if collection.as_str() == NONE {
        let properties = HashMap::from([(LABEL_PROPERTY, Value::from(DEFAULT_LABEL))]);
        let (created, prompt) = secrets
            .create_collection(properties, DEFAULT_ALIAS)
            .await
            .map_err(dbus_error)?;
        collection = if created.as_str() == NONE {
            OwnedObjectPath::try_from(run_prompt(bus, prompt, bound).await?)
                .map_err(|err| backend_error("the created collection", err))?
        } else {
            created
        };
    }
    let locked = SecretCollectionProxy::builder(bus)
        .path(collection.as_ref())
        .map_err(dbus_error)?
        .build()
        .await
        .map_err(dbus_error)?
        .locked()
        .await
        .map_err(dbus_error)?;
    if locked {
        let (_, prompt) = secrets
            .unlock(&[collection.as_ref()])
            .await
            .map_err(dbus_error)?;
        if prompt.as_str() != NONE {
            run_prompt(bus, prompt, bound).await?;
        }
    }
    Ok(())
}

/// Shows the prompt at `path` and waits for its answer up to `bound`,
/// dismissing it once the bound passes.
async fn run_prompt(
    bus: &zbus::Connection,
    path: OwnedObjectPath,
    bound: Duration,
) -> Result<OwnedValue, ClientError> {
    let prompt = SecretPromptProxy::builder(bus)
        .path(path)
        .map_err(dbus_error)?
        .build()
        .await
        .map_err(dbus_error)?;
    // Subscribed before the prompt shows, so a fast answer is not missed.
    let mut completed = prompt.receive_completed().await.map_err(dbus_error)?;
    prompt
        .prompt("")
        .await
        .map_err(|_| SecretStoreError::Dismissed)?;
    match tokio::time::timeout(bound, completed.next()).await {
        Ok(Some(signal)) => {
            let args = signal.args().map_err(dbus_error)?;
            if *args.dismissed() {
                Err(SecretStoreError::Dismissed.into())
            } else {
                Ok(args.result)
            }
        }
        Ok(None) => Err(SecretStoreError::Dismissed.into()),
        Err(_) => {
            // The dialog is already failing the caller, so a failed dismissal changes nothing.
            let _ = prompt.dismiss().await;
            Err(SecretStoreError::TimedOut(bound).into())
        }
    }
}

pub(super) struct SecretService {
    bus: zbus::Connection,
    service: oo7::dbus::Service,
    bound: Duration,
}

impl SecretService {
    pub(super) async fn open(bus: zbus::Connection, bound: Duration) -> Result<Self, ClientError> {
        ensure_default(&bus, bound).await?;
        let service = oo7::dbus::Service::new()
            .await
            .map_err(|err| backend_error("the Secret Service", err))?;
        Ok(Self {
            bus,
            service,
            bound,
        })
    }

    async fn collection(&self) -> Result<oo7::dbus::Collection, ClientError> {
        ensure_default(&self.bus, self.bound).await?;
        self.service
            .default_collection()
            .await
            .map_err(|err| backend_error("the Secret Service", err))
    }

    async fn items(&self, service: &str, name: &str) -> Result<Vec<oo7::dbus::Item>, ClientError> {
        self.collection()
            .await?
            .search_items(&attributes(service, name))
            .await
            .map_err(|err| backend_error("the Secret Service", err))
    }

    pub(super) async fn read(
        &self,
        service: &str,
        name: &str,
    ) -> Result<Option<String>, ClientError> {
        let Some(item) = self.items(service, name).await?.into_iter().next() else {
            return Ok(None);
        };
        let secret = item
            .secret()
            .await
            .map_err(|err| backend_error("the Secret Service", err))?;
        decode(&secret).map(Some)
    }

    pub(super) async fn write(
        &self,
        service: &str,
        name: &str,
        secret: &str,
    ) -> Result<(), ClientError> {
        self.collection()
            .await?
            .create_item(
                service,
                &attributes(service, name),
                oo7::Secret::text(encode(secret).as_str()),
                true,
                None,
            )
            .await
            .map(drop)
            .map_err(|err| backend_error("the Secret Service", err))
    }

    pub(super) async fn clear(&self, service: &str, name: &str) -> Result<(), ClientError> {
        for item in self.items(service, name).await? {
            item.delete(None)
                .await
                .map_err(|err| backend_error("the Secret Service", err))?;
        }
        Ok(())
    }
}

fn dbus_error(err: zbus::Error) -> ClientError {
    backend_error("the Secret Service", err)
}
