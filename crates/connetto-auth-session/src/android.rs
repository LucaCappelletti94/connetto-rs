//! The Custom Tab and its redirect, through the bundled Kotlin module.

use std::time::Duration;

use manganis::android::with_activity;
use manganis::jni::JNIEnv;
use manganis::jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use tokio::time::{Instant, sleep};

use crate::AuthSessionError;

// Declared for `dx`, which builds and bundles the Kotlin module this names.
// The plugin is constructed through the context's class loader below, since
// a thread Dioxus attached to the VM cannot find app classes with `FindClass`.
#[manganis::ffi("android")]
extern "Kotlin" {
    pub type AuthSessionPlugin;
}

const PLUGIN_CLASS: &str = "dev.connetto.authsession.AuthSessionPlugin";
const UNLOCK_CLASS: &str = "dev.connetto.authsession.UnlockPromptPlugin";
const POLL: Duration = Duration::from_millis(250);

/// The prompt's outcome codes, `UnlockPromptPlugin`'s constants.
const PENDING: i32 = 0;
const APPROVED: i32 = 1;
const CANCELED: i32 = 3;
const NO_SCREEN: i32 = 5;
/// `AuthSessionPlugin.TAB_NO_SCREEN`, a tab that found no screen to open on.
const TAB_NO_SCREEN: i32 = 2;
/// A prompt the system cancels this soon after showing it, as it does to an
/// app launched while the phone settles, is shown again once.
const EARLY_CANCEL: Duration = Duration::from_secs(1);

pub(crate) fn initialize_tls() -> Result<(), AuthSessionError> {
    jni_call(|env, context| {
        let context = env
            .call_method(
                context,
                "getApplicationContext",
                "()Landroid/content/Context;",
                &[],
            )?
            .l()?;
        let raw_vm = env.get_java_vm()?.get_java_vm_pointer();
        let raw_context = context.into_raw();
        #[expect(
            unsafe_code,
            reason = "the verifier uses jni 0.22 and manganis uses jni 0.21"
        )]
        // SAFETY: get_java_vm returns the live process's non-null Android VM, which supports JNI 1.6.
        let vm = unsafe { jni::JavaVM::from_raw(raw_vm.cast()) };
        let initialized = vm.with_top_local_frame(|verifier_env| {
            #[expect(
                unsafe_code,
                reason = "the application context crosses the JNI wrapper boundary"
            )]
            // SAFETY: into_raw transfers the sole wrapper for this thread's local reference, whose parent frame outlives this callback.
            let context =
                unsafe { jni::objects::JObject::from_raw(verifier_env, raw_context.cast()) };
            rustls_platform_verifier::android::init_with_env(verifier_env, context)
        });
        Ok(initialized.map_err(|err| {
            if matches!(err, jni::errors::Error::JavaException) {
                bridge_error(env, &manganis::jni::errors::Error::JavaException)
            } else {
                AuthSessionError::Bridge(err.to_string())
            }
        }))
    })?
}

pub(crate) async fn authorize(url: &str, timeout: Duration) -> Result<String, AuthSessionError> {
    let plugin = construct()?;
    jni_call(|env, _| {
        let url = env.new_string(url)?;
        env.call_method(
            plugin.as_obj(),
            "begin",
            "(Ljava/lang/String;)V",
            &[JValue::Object(&url)],
        )?;
        Ok(())
    })?;
    let deadline = Instant::now() + timeout;
    loop {
        let (redirect, tab) = jni_call(|env, _| {
            let redirect = take_redirect(env, plugin.as_obj())?;
            let tab = env
                .call_method(plugin.as_obj(), "tabState", "()I", &[])?
                .i()?;
            Ok((redirect, tab))
        })?;
        if let Some(redirect) = redirect {
            return Ok(redirect);
        }
        if tab == TAB_NO_SCREEN {
            return Err(AuthSessionError::NoScreen);
        }
        if Instant::now() >= deadline {
            return Err(AuthSessionError::TimedOut(timeout));
        }
        sleep(POLL).await;
    }
}

pub(crate) fn delivered() -> Result<Option<String>, AuthSessionError> {
    let plugin = construct()?;
    jni_call(|env, _| take_redirect(env, plugin.as_obj()))
}

pub(crate) fn device_secure() -> Result<bool, AuthSessionError> {
    let plugin = construct_class(UNLOCK_CLASS)?;
    jni_call(|env, _| {
        env.call_method(plugin.as_obj(), "deviceSecure", "()Z", &[])?
            .z()
    })
}

pub(crate) fn approve_unlock(
    cipher: &JObject<'_>,
    title: &str,
    timeout: Duration,
) -> Result<bool, AuthSessionError> {
    let plugin = construct_class(UNLOCK_CLASS)?;
    let mut retried = false;
    loop {
        let shown = std::time::Instant::now();
        jni_call(|env, _| {
            let title = env.new_string(title)?;
            env.call_method(
                plugin.as_obj(),
                "begin",
                "(Ljavax/crypto/Cipher;Ljava/lang/String;)V",
                &[JValue::Object(cipher), JValue::Object(&title)],
            )?;
            Ok(())
        })?;
        let outcome = loop {
            let outcome = jni_call(|env, _| {
                env.call_method(plugin.as_obj(), "takeOutcome", "()I", &[])?
                    .i()
            })?;
            if outcome != PENDING {
                break outcome;
            }
            if shown.elapsed() >= timeout {
                return Err(AuthSessionError::TimedOut(timeout));
            }
            std::thread::sleep(POLL);
        };
        if outcome == NO_SCREEN {
            return Err(AuthSessionError::NoScreen);
        }
        if outcome == CANCELED && !retried && shown.elapsed() < EARLY_CANCEL {
            retried = true;
            continue;
        }
        return Ok(outcome == APPROVED);
    }
}

fn construct() -> Result<AuthSessionPlugin, AuthSessionError> {
    construct_class(PLUGIN_CLASS).map(AuthSessionPlugin::from_global_ref)
}

/// An instance of the bundled class `name`, loaded through the context's class
/// loader. The plugins look the screen up themselves, so the context only
/// needs to belong to this app.
fn construct_class(name: &str) -> Result<GlobalRef, AuthSessionError> {
    jni_call(|env, context| {
        let loader = env
            .call_method(context, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?
            .l()?;
        let name = env.new_string(name)?;
        let class = env
            .call_method(
                &loader,
                "loadClass",
                "(Ljava/lang/String;)Ljava/lang/Class;",
                &[JValue::Object(&name)],
            )?
            .l()?;
        let instance = env.new_object(JClass::from(class), "()V", &[])?;
        env.new_global_ref(instance)
    })
}

fn take_redirect(
    env: &mut JNIEnv<'_>,
    plugin: &JObject<'_>,
) -> manganis::jni::errors::Result<Option<String>> {
    let value = env
        .call_method(plugin, "takeRedirect", "()Ljava/lang/String;", &[])?
        .l()?;
    if value.is_null() {
        return Ok(None);
    }
    let value = JString::from(value);
    Ok(Some(env.get_string(&value)?.into()))
}

/// Run `f` with a JNI environment attached to this thread and the context
/// manganis took from `ndk-context` on its first call, kept for the process.
fn jni_call<R>(
    f: impl FnOnce(&mut JNIEnv<'_>, &JObject<'_>) -> manganis::jni::errors::Result<R>,
) -> Result<R, AuthSessionError> {
    with_activity(|env, context| Some(f(env, context).map_err(|err| bridge_error(env, &err))))
        .ok_or_else(|| AuthSessionError::Bridge("no Android context".to_owned()))?
}

/// The bridge error for `err`. A Java exception is cleared and reported by its
/// description, since one left pending makes the thread's next JNI call illegal.
fn bridge_error(env: &mut JNIEnv<'_>, err: &manganis::jni::errors::Error) -> AuthSessionError {
    let manganis::jni::errors::Error::JavaException = err else {
        return AuthSessionError::Bridge(err.to_string());
    };
    let Ok(thrown) = env.exception_occurred() else {
        return AuthSessionError::Bridge(err.to_string());
    };
    let _ = env.exception_clear();
    let described = env
        .call_method(&thrown, "toString", "()Ljava/lang/String;", &[])
        .and_then(manganis::jni::objects::JValueGen::l)
        .and_then(|text| env.get_string(&JString::from(text)).map(String::from));
    if described.is_err() {
        let _ = env.exception_clear();
    }
    AuthSessionError::Bridge(described.unwrap_or_else(|_| err.to_string()))
}

/// The Java VM reached through `ndk-context`, for the device key.
#[cfg(feature = "device-identity")]
pub(crate) struct ContextJava;

#[cfg(feature = "device-identity")]
impl connetto_client::device_key::JavaAccess for ContextJava {
    fn with_env(
        &self,
        body: &mut dyn FnMut(&mut JNIEnv<'_>),
    ) -> Result<(), connetto_client::ClientError> {
        with_activity(|env, _| {
            body(env);
            Some(())
        })
        .ok_or_else(|| {
            connetto_client::ClientError::DeviceChip(
                connetto_client::device_key::ChipError::Failed("no Android context".into()),
            )
        })
    }
}
