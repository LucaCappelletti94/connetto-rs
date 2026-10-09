//! The bundled Kotlin module and btleplug's Java, the prompt for their
//! permissions, and the virtual machine btleplug's jni takes.

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

/// Why btleplug's virtual machine is not at hand.
#[derive(Debug, thiserror::Error)]
pub enum VmError {
    /// The process shows no Activity, so its virtual machine is unknown yet.
    #[error("no Activity stands, so the virtual machine is unknown")]
    NoActivity,
    /// The virtual machine refused a call.
    #[error("the virtual machine refused: {0}")]
    Jni(#[from] JniError),
}

/// The process's virtual machine under the jni btleplug links (R76 decision
/// 22), taken from the one manganis hands out.
///
/// # Errors
///
/// [`VmError::NoActivity`] before the application's Activity stands, and
/// [`VmError::Jni`] when the virtual machine refuses the lookup.
pub fn java_vm() -> Result<jni::JavaVM, VmError> {
    let raw =
        with_activity(|env, _activity| Some(env.get_java_vm().map(|vm| vm.get_java_vm_pointer())))
            .ok_or(VmError::NoActivity)??;
    #[expect(
        unsafe_code,
        reason = "jni 0.22 learns the running virtual machine only through from_raw"
    )]
    // SAFETY: `raw` is the process's one virtual machine, which manganis's jni
    // read from the live environment it handed out, so it is non-null and
    // stays valid for the life of the process. Both jni versions point at the
    // same `JNIInvokeInterface_` table.
    let vm = unsafe { jni::JavaVM::from_raw(raw.cast()) };
    Ok(vm)
}

/// Point the calling thread's context class loader at the application's, so
/// btleplug's class lookups on a thread attached from native code find the
/// bundled Java (R76 decision 22).
///
/// # Errors
///
/// The virtual machine's refusal of any of the framework calls.
pub fn use_application_class_loader(env: &mut jni::Env<'_>) -> jni::errors::Result<()> {
    use jni::{jni_sig, jni_str};
    let application = env
        .call_static_method(
            jni_str!("android/app/ActivityThread"),
            jni_str!("currentApplication"),
            jni_sig!("()Landroid/app/Application;"),
            &[],
        )?
        .l()?;
    let loader = env
        .call_method(
            &application,
            jni_str!("getClassLoader"),
            jni_sig!("()Ljava/lang/ClassLoader;"),
            &[],
        )?
        .l()?;
    let thread = env
        .call_static_method(
            jni_str!("java/lang/Thread"),
            jni_str!("currentThread"),
            jni_sig!("()Ljava/lang/Thread;"),
            &[],
        )?
        .l()?;
    env.call_method(
        &thread,
        jni_str!("setContextClassLoader"),
        jni_sig!("(Ljava/lang/ClassLoader;)V"),
        &[jni::objects::JValue::Object(&loader)],
    )?;
    Ok(())
}
