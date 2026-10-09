//! The Android platform's Bluetooth, over the bundled plugin (R76).

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as CHUNKS;
use jni::objects::{JObject, JValue};

use super::{
    BluetoothError, BluetoothState, PeripheralBackend, PeripheralEvent, PromptOutcome,
    ReadinessBackend,
};
use crate::device_key::JavaAccess;
use crate::hotspot::android::{call, int, plugin, string};

/// The bundled plugin's class.
const PLUGIN_CLASS: &str = "dev.connetto.peer.BluetoothPlugin";
/// The Android platform's Bluetooth, over the application's JNI access
/// (R76).
pub(crate) struct AndroidBluetoothBackend {
    java: Arc<dyn JavaAccess>,
}

impl AndroidBluetoothBackend {
    /// A backend reaching the application's plugin through `java`.
    pub(crate) fn new(java: Arc<dyn JavaAccess>) -> Self {
        Self { java }
    }
}

impl ReadinessBackend for AndroidBluetoothBackend {
    fn state(&self) -> BluetoothState {
        match call(&*self.java, |env| {
            let class = plugin(env, PLUGIN_CLASS)?;
            Ok(match int(env, &class, "state")? {
                1 => BluetoothState::Ready,
                2 => BluetoothState::Off,
                3 => BluetoothState::NotPermitted,
                _ => BluetoothState::Unsupported,
            })
        }) {
            Ok(state) => state,
            Err(failure) => {
                tracing::warn!(%failure, "the Bluetooth standing could not be read");
                BluetoothState::Unsupported
            }
        }
    }

    fn missing_permissions(&self) -> Vec<String> {
        match call(&*self.java, |env| {
            let class = plugin(env, PLUGIN_CLASS)?;
            let Some(text) = string(env, &class, "missingPermissions")? else {
                return Ok(Vec::new());
            };
            Ok(text.lines().map(str::to_string).collect())
        }) {
            Ok(missing) => missing,
            Err(failure) => {
                tracing::warn!(%failure, "the Bluetooth permissions could not be read");
                Vec::new()
            }
        }
    }

    fn prompt(&self) -> Result<(), BluetoothError> {
        let started = call(&*self.java, |env| {
            let class = plugin(env, PLUGIN_CLASS)?;
            int(env, &class, "prompt")
        })
        .map_err(|failure| BluetoothError::Failed(failure.to_string()))?;
        match started {
            0 => Ok(()),
            // The action is blocked, so the call's rows stand on the
            // standing's own reason.
            _ => Err(BluetoothError::Failed(
                "the prompt action is blocked".into(),
            )),
        }
    }

    fn prompt_outcome(&self) -> Option<PromptOutcome> {
        call(&*self.java, |env| {
            let class = plugin(env, PLUGIN_CLASS)?;
            Ok(match int(env, &class, "promptOutcome")? {
                0 => Some(PromptOutcome::NotAsked),
                1 => Some(PromptOutcome::Declined),
                2 => Some(PromptOutcome::SentToSettings),
                3 => Some(PromptOutcome::Blocked),
                // The action is in flight, or the platform names a result
                // the client does not.
                _ => None,
            })
        })
        .unwrap_or(None)
    }
}

impl PeripheralBackend for AndroidBluetoothBackend {
    fn start(&self, beacon: [u8; 9]) -> Result<(), BluetoothError> {
        let started = call(&*self.java, |env| {
            let class = plugin(env, PLUGIN_CLASS)?;
            let bytes = env.byte_array_from_slice(&beacon)?;
            env.call_static_method(
                &class,
                "startAdvertising",
                "([B)I",
                &[JValue::Object(&JObject::from(bytes))],
            )?
            .i()
        })
        .map_err(|failure| BluetoothError::Failed(failure.to_string()))?;
        match started {
            0 => Ok(()),
            code => Err(BluetoothError::Failed(format!(
                "the advertisement failed with {code}"
            ))),
        }
    }

    fn stop(&self) {
        if let Err(failure) = call(&*self.java, |env| {
            let class = plugin(env, PLUGIN_CLASS)?;
            env.call_static_method(&class, "stopAdvertising", "()V", &[])
                .map(drop)
        }) {
            tracing::warn!(%failure, "the advertisement could not be stopped");
        }
    }

    fn poll(&self) -> Vec<PeripheralEvent> {
        let events = call(&*self.java, |env| {
            let class = plugin(env, PLUGIN_CLASS)?;
            let Some(text) = string(env, &class, "poll")? else {
                return Ok(Vec::<PeripheralEvent>::new());
            };
            Ok(text
                .lines()
                .filter_map(|line| {
                    let mut parts = line.split('\t');
                    match parts.next()? {
                        // A joiner connected, with the negotiated packet
                        // size.
                        "1" => {
                            let device = parts.next()?.parse().ok()?;
                            let mtu = parts.next()?.parse().ok()?;
                            Some(PeripheralEvent::Connected { device, mtu })
                        }
                        // A joiner disconnected.
                        "2" => {
                            let device = parts.next()?.parse().ok()?;
                            Some(PeripheralEvent::Disconnected { device })
                        }
                        // The advertisement failed, with the platform's
                        // code.
                        "3" => Some(PeripheralEvent::Failed(format!(
                            "the advertisement failed with {}",
                            parts.next().unwrap_or("the platform's code")
                        ))),
                        // A chunk the joiner wrote.
                        "4" => {
                            let device = parts.next()?.parse().ok()?;
                            let bytes = match CHUNKS.decode(parts.next()?) {
                                Ok(bytes) => bytes,
                                Err(_) => return None,
                            };
                            Some(PeripheralEvent::Chunk { device, bytes })
                        }
                        _ => None,
                    }
                })
                .collect())
        })
        .unwrap_or_default();
        if events.len() > 1 {
            tracing::debug!(
                count = events.len(),
                "the Bluetooth service reported its events"
            );
        }
        events
    }

    fn notify(&self, device: u64, bytes: &[u8]) -> Result<(), BluetoothError> {
        // The device key is the platform's 48-bit MAC fold, so it stands in
        // a Long.
        let Ok(device) = i64::try_from(device) else {
            return Err(BluetoothError::Failed(
                "the device key exceeds the platform's Long".into(),
            ));
        };
        let sent = call(&*self.java, |env| {
            let class = plugin(env, PLUGIN_CLASS)?;
            let chunk = env.byte_array_from_slice(bytes)?;
            env.call_static_method(
                &class,
                "notify",
                "(J[B)I",
                &[JValue::Long(device), JValue::Object(&JObject::from(chunk))],
            )?
            .i()
        })
        .map_err(|failure| BluetoothError::Failed(failure.to_string()))?;
        match sent {
            0 => Ok(()),
            _ => Err(BluetoothError::Failed(
                "the notification will not send".into(),
            )),
        }
    }

    fn disconnect(&self, device: u64) {
        let Ok(device) = i64::try_from(device) else {
            tracing::warn!(device, "the device key exceeds the platform's Long");
            return;
        };
        if let Err(failure) = call(&*self.java, |env| {
            let class = plugin(env, PLUGIN_CLASS)?;
            env.call_static_method(
                &class,
                "disconnectPeripheral",
                "(J)V",
                &[JValue::Long(device)],
            )
            .map(drop)
        }) {
            tracing::warn!(%failure, "the joiner could not be disconnected");
        }
    }
}
