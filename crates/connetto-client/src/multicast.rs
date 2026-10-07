//! The Wi-Fi multicast lock the peer discovery's browse holds on Android
//! (R76), through the application's JNI access. Receiving the browse's
//! mDNS traffic needs the lock, so the browse holds it for its standing.

use std::sync::Arc;

use jni::JNIEnv;
use jni::objects::{GlobalRef, JValue};

use crate::device_key::JavaAccess;

/// The tag the lock announces to the Wi-Fi manager.
const LOCK_TAG: &str = "connetto-peer";

/// A failure reaching the Wi-Fi multicast lock through the Java VM.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MulticastFailure {
    /// A refusal from the Java side, kept as the exception's text, else the JNI error's.
    #[error("the multicast lock will not hold: {0}")]
    Java(String),
    /// The process has no reachable Java VM.
    #[error("the multicast lock will not hold: {0}")]
    NoVm(String),
    /// The application's JNI access returned without running the body.
    #[error("the multicast lock will not hold: the JNI access ran nothing")]
    RanNothing,
}

/// The held `WifiManager.MulticastLock`, over the application's JNI access.
pub(crate) struct MulticastLock {
    java: Arc<dyn JavaAccess>,
    lock: GlobalRef,
}

impl MulticastLock {
    /// Take the Wi-Fi service's multicast lock and acquire it, through `java`.
    ///
    /// # Errors
    ///
    /// [`MulticastFailure`] when the VM is unreachable or the service refuses.
    pub(crate) fn acquire(java: Arc<dyn JavaAccess>) -> Result<Self, MulticastFailure> {
        let mut body = Some(|env: &mut JNIEnv| -> jni::errors::Result<GlobalRef> {
            let application = env
                .call_static_method(
                    "android/app/ActivityThread",
                    "currentApplication",
                    "()Landroid/app/Application;",
                    &[],
                )?
                .l()?;
            let wifi = env.new_string("wifi")?;
            let service = env
                .call_method(
                    &application,
                    "getSystemService",
                    "(Ljava/lang/String;)Ljava/lang/Object;",
                    &[JValue::Object(&wifi)],
                )?
                .l()?;
            let tag = env.new_string(LOCK_TAG)?;
            let lock = env
                .call_method(
                    &service,
                    "createMulticastLock",
                    "(Ljava/lang/String;)Landroid/net/wifi/WifiManager$MulticastLock;",
                    &[JValue::Object(&tag)],
                )?
                .l()?;
            env.call_method(&lock, "acquire", "()V", &[])?;
            env.new_global_ref(&lock)
        });
        let mut outcome = None;
        java.with_env(&mut |env| {
            let Some(body) = body.take() else { return };
            outcome = Some(body(env).map_err(|err| exception_text(env, &err)));
        })
        .map_err(|err| MulticastFailure::NoVm(err.to_string()))?;
        let lock = outcome.unwrap_or_else(|| Err(MulticastFailure::RanNothing))?;
        Ok(Self { java, lock })
    }

    /// Let the Wi-Fi service have the multicast again.
    pub(crate) fn release(&self) {
        let _ = self.java.with_env(&mut |env| {
            let _ = env.call_method(&self.lock, "release", "()V", &[]);
        });
    }
}

impl Drop for MulticastLock {
    fn drop(&mut self) {
        self.release();
    }
}

/// The pending Java exception's text, cleared, else the JNI error's.
fn exception_text(env: &mut JNIEnv, err: &jni::errors::Error) -> MulticastFailure {
    let pending = env.exception_occurred().ok().filter(|ex| !ex.is_null());
    let _ = env.exception_clear();
    let text = pending
        .and_then(|ex| {
            env.call_method(&ex, "toString", "()Ljava/lang/String;", &[])
                .ok()
        })
        .and_then(|value| value.l().ok())
        .and_then(|text| env.get_string(&text.into()).ok().map(String::from));
    MulticastFailure::Java(text.unwrap_or_else(|| err.to_string()))
}
