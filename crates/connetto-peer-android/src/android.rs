//! The bundled hotspot Kotlin module, and the prompt for its permissions.

use manganis::android::with_activity;
use manganis::jni::JNIEnv;
use manganis::jni::errors::Error as JniError;
use manganis::jni::objects::{JClass, JValue};

// Declared for `dx`, which builds and bundles the Kotlin module this names.
#[manganis::ffi("android")]
extern "Kotlin" {
    pub type HotspotPlugin;
    pub type BluetoothPlugin;
}

/// The plugin's class, reached through the application's class loader, since
/// a thread Dioxus attached to the VM cannot find app classes with
/// `FindClass`.
const PLUGIN_CLASS: &str = "dev.connetto.peer.HotspotPlugin";

/// Ask the operating system for the peer link's permissions, from the plugin
/// standing behind the Activity (R76).
pub fn request_peer_permissions() {
    let _ = with_activity(|env, activity| {
        let class = plugin(env).ok()?;
        env.call_static_method(
            class,
            "requestPermissions",
            "(Landroid/app/Activity;)V",
            &[JValue::Object(activity)],
        )
        .ok()?;
        Some(())
    });
}

/// The bundled plugin's class, loaded on the Activity's class loader.
fn plugin<'local>(env: &mut JNIEnv<'local>) -> Result<JClass<'local>, JniError> {
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
