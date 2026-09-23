//! The Custom Tab and its redirect, through the bundled Kotlin module.

use std::time::Duration;

use manganis::android::with_activity;
use manganis::jni::JNIEnv;
use manganis::jni::objects::{JClass, JObject, JString, JValue};
use tokio::time::{Instant, sleep};

use crate::AuthSessionError;

// Declared for `dx`, which builds and bundles the Kotlin module this names.
// The plugin is constructed through the Activity's class loader below, since
// a thread Dioxus attached to the VM cannot find app classes with `FindClass`.
#[manganis::ffi("android")]
extern "Kotlin" {
    pub type AuthSessionPlugin;
}

const PLUGIN_CLASS: &str = "dev.connetto.authsession.AuthSessionPlugin";
const POLL: Duration = Duration::from_millis(250);

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
        if let Some(redirect) = jni_call(|env, _| take_redirect(env, plugin.as_obj()))? {
            return Ok(redirect);
        }
        if Instant::now() >= deadline {
            return Err(AuthSessionError::TimedOut(timeout));
        }
        sleep(POLL).await;
    }
}

fn construct() -> Result<AuthSessionPlugin, AuthSessionError> {
    jni_call(|env, activity| {
        let loader = env
            .call_method(activity, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?
            .l()?;
        let name = env.new_string(PLUGIN_CLASS)?;
        let class = env
            .call_method(
                &loader,
                "loadClass",
                "(Ljava/lang/String;)Ljava/lang/Class;",
                &[JValue::Object(&name)],
            )?
            .l()?;
        let instance = env.new_object(
            JClass::from(class),
            "(Landroid/app/Activity;)V",
            &[JValue::Object(activity)],
        )?;
        Ok(AuthSessionPlugin::from_global_ref(
            env.new_global_ref(instance)?,
        ))
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

/// Run `f` with a JNI environment attached to this thread and the Activity.
fn jni_call<R>(
    f: impl FnOnce(&mut JNIEnv<'_>, &JObject<'_>) -> manganis::jni::errors::Result<R>,
) -> Result<R, AuthSessionError> {
    with_activity(|env, activity| Some(f(env, activity)))
        .ok_or_else(|| AuthSessionError::Bridge("no Android activity".to_owned()))?
        .map_err(|err| AuthSessionError::Bridge(err.to_string()))
}
