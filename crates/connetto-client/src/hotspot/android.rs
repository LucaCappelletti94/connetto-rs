//! The Android hotspot backend, over the application's JNI access (R76).
//!
//! The backend drives the bundled `HotspotPlugin` through the device's
//! `WifiManager` and `ConnectivityManager`, and the joined network's subnet
//! reaches the dials' sockets through the plugin's `bindSocket`.

use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;

use jni::JNIEnv;
use jni::objects::{JClass, JString, JValue};
use socket2::SockRef;

use super::{
    HostStatus, HotspotBackend, HotspotError, HotspotOffer, HotspotSecurity, JoinError, JoinStatus,
};
use crate::device_key::JavaAccess;

/// The plugin the backend drives, bundled by the app's `dx` build.
const PLUGIN_CLASS: &str = "dev.connetto.peer.HotspotPlugin";

/// The plugin's security codes, `WifiNetworkSpecifier`'s choice.
const SECURITY_WPA2: i32 = 0;
const SECURITY_WPA3: i32 = 1;

/// The plugin's host outcome codes.
const HOST_STARTED: i32 = 2;
const HOST_FAILED: i32 = 3;
const HOST_STOPPED: i32 = 4;

/// The plugin's join outcome codes.
const JOIN_AVAILABLE: i32 = 2;
const JOIN_UNAVAILABLE: i32 = 3;
const JOIN_LOST: i32 = 4;

/// The permissions whose names a failure's text names, the backstop to the
/// missing-permission pre-check.
const KNOWN_PERMISSIONS: [&str; 2] = ["NEARBY_WIFI_DEVICES", "CHANGE_WIFI_MULTICAST_STATE"];

/// The join's timeout in milliseconds, the join bound handed to the device.
const JOIN_TIMEOUT_MS: i64 = 60_000;

/// The device's SDK level, from the build's properties.
fn sdk() -> u32 {
    android_system_properties::AndroidSystemProperties::new()
        .get("ro.build.version.sdk")
        .and_then(|sdk| sdk.parse().ok())
        .unwrap_or(0)
}

/// A failure reaching the plugin through the Java VM.
#[derive(Debug, thiserror::Error)]
enum PluginFailure {
    /// A refusal from the Java side, kept as the exception's text, else the JNI error's.
    #[error("the hotspot plugin refused: {0}")]
    Java(String),
    /// The process has no reachable Java VM.
    #[error("the hotspot plugin will not run: {0}")]
    NoVm(String),
    /// The application's JNI access returned without running the body.
    #[error("the hotspot plugin will not run: the JNI access ran nothing")]
    RanNothing,
}

/// The permission a failure's text names, else nothing.
fn permission_in(text: &str) -> Option<String> {
    KNOWN_PERMISSIONS
        .into_iter()
        .find(|name| text.contains(name))
        .map(ToOwned::to_owned)
}

/// Map a plugin failure to the host side's error.
fn host_failure(failure: PluginFailure) -> HotspotError {
    match failure {
        PluginFailure::Java(text) => {
            permission_in(&text).map_or(HotspotError::Failed, HotspotError::MissingPermission)
        }
        PluginFailure::NoVm(_) | PluginFailure::RanNothing => HotspotError::Failed,
    }
}

/// Map a plugin failure to the join side's error.
fn join_failure(failure: PluginFailure) -> JoinError {
    match failure {
        PluginFailure::Java(text) => {
            permission_in(&text).map_or(JoinError::Failed, JoinError::MissingPermission)
        }
        PluginFailure::NoVm(_) | PluginFailure::RanNothing => JoinError::Failed,
    }
}

/// The pending Java exception's text, cleared, else the JNI error's.
fn exception_text(env: &mut JNIEnv<'_>, err: &jni::errors::Error) -> PluginFailure {
    let pending = env.exception_occurred().ok().filter(|ex| !ex.is_null());
    let _ = env.exception_clear();
    let text = pending
        .and_then(|ex| {
            env.call_method(&ex, "toString", "()Ljava/lang/String;", &[])
                .ok()
        })
        .and_then(|value| value.l().ok())
        .and_then(|text| env.get_string(&text.into()).ok().map(String::from));
    PluginFailure::Java(text.unwrap_or_else(|| err.to_string()))
}

/// Run `body` on the device's Java VM, a pending exception becoming its text.
fn call<T>(
    java: &dyn JavaAccess,
    body: impl FnOnce(&mut JNIEnv<'_>) -> jni::errors::Result<T>,
) -> Result<T, PluginFailure> {
    let mut body = Some(body);
    let mut outcome: Option<Result<T, PluginFailure>> = None;
    java.with_env(&mut |env| {
        let Some(body) = body.take() else { return };
        outcome = Some(body(env).map_err(|err| exception_text(env, &err)));
    })
    .map_err(|err| PluginFailure::NoVm(err.to_string()))?;
    match outcome {
        Some(outcome) => outcome,
        None => Err(PluginFailure::RanNothing),
    }
}

/// The plugin's class, on the application's class loader.
fn plugin<'local>(env: &mut JNIEnv<'local>) -> jni::errors::Result<JClass<'local>> {
    let application = env
        .call_static_method(
            "android/app/ActivityThread",
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        )?
        .l()?;
    let class_loader = env
        .call_method(
            &application,
            "getClassLoader",
            "()Ljava/lang/ClassLoader;",
            &[],
        )?
        .l()?;
    let name = env.new_string(PLUGIN_CLASS)?;
    let class = env
        .call_method(
            &class_loader,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::Object(&name)],
        )?
        .l()?;
    Ok(JClass::from(class))
}

/// A plugin `()I` result.
fn int(env: &mut JNIEnv<'_>, class: &JClass<'_>, name: &str) -> jni::errors::Result<i32> {
    env.call_static_method(class, name, "()I", &[])?.i()
}

/// A plugin `()Ljava/lang/String;` result, `None` where it is unset.
fn string(
    env: &mut JNIEnv<'_>,
    class: &JClass<'_>,
    name: &str,
) -> jni::errors::Result<Option<String>> {
    let value = env
        .call_static_method(class, name, "()Ljava/lang/String;", &[])?
        .l()?;
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(env.get_string(&JString::from(value))?.into()))
}

/// The permissions the device has not granted, the plugin's joined list.
fn missing_permissions(
    env: &mut JNIEnv<'_>,
    class: &JClass<'_>,
) -> jni::errors::Result<Vec<String>> {
    let Some(text) = string(env, class, "missingPermissions")? else {
        return Ok(Vec::new());
    };
    Ok(text.lines().map(str::to_string).collect())
}

/// The Android backend, over the application's JNI access (R76).
pub(crate) struct AndroidHotspotBackend {
    java: Arc<dyn JavaAccess>,
}

impl AndroidHotspotBackend {
    /// The backend over `java`.
    pub(crate) fn new(java: Arc<dyn JavaAccess>) -> Self {
        Self { java }
    }
}

impl HotspotBackend for AndroidHotspotBackend {
    fn request_host(&self) -> Result<(), HotspotError> {
        // The host's credentials come from the started callback, API 33+.
        if sdk() < 33 {
            return Err(HotspotError::Unsupported);
        }
        let missing = call(&*self.java, |env| {
            let class = plugin(env)?;
            missing_permissions(env, &class)
        })
        .map_err(host_failure)?;
        if let Some(name) = missing.into_iter().next() {
            return Err(HotspotError::MissingPermission(name));
        }
        call(&*self.java, |env| {
            let class = plugin(env)?;
            env.call_static_method(class, "startHost", "()V", &[])?;
            Ok(())
        })
        .map_err(host_failure)
    }

    fn stop_host(&self) {
        let _ = call(&*self.java, |env| {
            let class = plugin(env)?;
            env.call_static_method(class, "stopHost", "()V", &[])?;
            Ok(())
        });
    }

    fn host_status(&self) -> HostStatus {
        let outcome = call(&*self.java, |env| {
            let class = plugin(env)?;
            Ok((
                int(env, &class, "hostState")?,
                string(env, &class, "hostSsid")?,
                string(env, &class, "hostPassphrase")?,
                int(env, &class, "hostSecurity")?,
                string(env, &class, "hostFailure")?,
            ))
        });
        let (state, ssid, passphrase, security, failure) = match outcome {
            Ok(values) => values,
            // The VM is unreachable, so the standing stands as it was.
            Err(_) => return HostStatus::Pending,
        };
        match state {
            HOST_STARTED => {
                let security = if security == SECURITY_WPA3 {
                    HotspotSecurity::Wpa3
                } else {
                    HotspotSecurity::Wpa2
                };
                match (ssid, passphrase) {
                    (Some(ssid), Some(passphrase)) => HostStatus::Started {
                        ssid,
                        passphrase,
                        security,
                    },
                    _ => HostStatus::Pending,
                }
            }
            HOST_FAILED => {
                let permission = failure.as_ref().and_then(|text| permission_in(text));
                let err = match permission {
                    Some(name) => HotspotError::MissingPermission(name),
                    None => match failure.as_deref() {
                        // The plugin's failure codes, `WifiManager`'s.
                        Some("1") => HotspotError::Incompatible,
                        Some("2") => HotspotError::NoChannel,
                        _ => HotspotError::Failed,
                    },
                };
                HostStatus::Failed(err)
            }
            HOST_STOPPED => HostStatus::Stopped,
            // The plugin's idle and pending standings.
            _ => HostStatus::Pending,
        }
    }

    fn request_join(&self, offer: &HotspotOffer) -> Result<(), JoinError> {
        if sdk() < 29 {
            return Err(JoinError::Unsupported);
        }
        let missing = call(&*self.java, |env| {
            let class = plugin(env)?;
            missing_permissions(env, &class)
        })
        .map_err(join_failure)?;
        if let Some(name) = missing.into_iter().next() {
            return Err(JoinError::MissingPermission(name));
        }
        let security = if offer.security == HotspotSecurity::Wpa3 {
            SECURITY_WPA3
        } else {
            SECURITY_WPA2
        };
        call(&*self.java, |env| {
            let class = plugin(env)?;
            let ssid = env.new_string(&offer.ssid)?;
            let passphrase = env.new_string(&offer.passphrase)?;
            env.call_static_method(
                class,
                "join",
                "(Ljava/lang/String;Ljava/lang/String;IJ)V",
                &[
                    JValue::Object(&ssid),
                    JValue::Object(&passphrase),
                    JValue::Int(security),
                    JValue::Long(JOIN_TIMEOUT_MS),
                ],
            )?;
            Ok(())
        })
        .map_err(join_failure)
    }

    fn leave_join(&self) {
        let _ = call(&*self.java, |env| {
            let class = plugin(env)?;
            env.call_static_method(class, "leave", "()V", &[])?;
            Ok(())
        });
    }

    fn join_status(&self) -> JoinStatus {
        let outcome = call(&*self.java, |env| {
            let class = plugin(env)?;
            Ok((
                int(env, &class, "joinState")?,
                string(env, &class, "joinAddress")?,
                int(env, &class, "joinPrefix")?,
                string(env, &class, "joinGateway")?,
            ))
        });
        let (state, address, prefix, gateway) = match outcome {
            Ok(values) => values,
            // The VM is unreachable, so the standing stands as it was.
            Err(_) => return JoinStatus::Pending,
        };
        match state {
            JOIN_AVAILABLE => {
                let address = address.and_then(|address| address.parse().ok());
                let gateway = gateway.and_then(|gateway| gateway.parse().ok());
                let prefix = match u8::try_from(prefix) {
                    Ok(prefix) if prefix <= 32 => prefix,
                    _ => return JoinStatus::Pending,
                };
                match (address, gateway) {
                    (Some(address), Some(gateway)) => JoinStatus::Available {
                        address,
                        prefix,
                        gateway,
                    },
                    _ => JoinStatus::Pending,
                }
            }
            JOIN_UNAVAILABLE => JoinStatus::Unavailable,
            JOIN_LOST => JoinStatus::Lost,
            // The plugin's idle and pending standings.
            _ => JoinStatus::Pending,
        }
    }
}

/// The dials' bind to the joined network, for the targets it lies in (R76).
pub(crate) struct JoinedBind {
    java: Arc<dyn JavaAccess>,
    /// The joined network's subnet, its address and prefix length.
    subnet: (Ipv4Addr, u8),
}

impl JoinedBind {
    /// The bind over `java`, for `subnet`.
    pub(crate) fn new(java: Arc<dyn JavaAccess>, subnet: (Ipv4Addr, u8)) -> Self {
        Self { java, subnet }
    }
}

impl connetto_peer::SocketPrep for JoinedBind {
    fn prepare(&self, sock: SockRef<'_>, target: SocketAddr) -> std::io::Result<()> {
        let SocketAddr::V4(target) = target else {
            return Ok(());
        };
        let Ok(net) = ipnet::Ipv4Net::new(self.subnet.0, self.subnet.1) else {
            return Ok(());
        };
        if !net.contains(target.ip()) {
            return Ok(());
        }
        let fd = sock.as_fd().as_raw_fd();
        call(&*self.java, |env| {
            let class = plugin(env)?;
            env.call_static_method(class, "bindSocket", "(I)Z", &[JValue::from(fd)])?;
            Ok(())
        })
        .map_err(|failure| std::io::Error::new(std::io::ErrorKind::Other, failure.to_string()))
    }
}
