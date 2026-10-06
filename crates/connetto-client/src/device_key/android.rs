//! The device key in the Android Keystore (R74 decision 6), through JNI.
//!
//! The key is created in the trusted environment every handheld has (CDD 9.11)
//! with no user-authentication requirement and no unlocked-device requirement,
//! so it signs once the device was unlocked since its restart (decision 11).
//! The application hands in its JNI access, since reaching the Java VM takes
//! `unsafe` code this crate forbids, the way it hands in the unlock prompt.

use std::sync::Arc;

use connetto_core::device_cert::{
    ANDROID_ATTESTATION_CHALLENGE, DeviceKey, DeviceKeyError, KeyHome,
};
use connetto_core::messages::DeviceAttestation;
use jni::JNIEnv;
use jni::objects::{GlobalRef, JByteArray, JObject, JObjectArray, JValue};
use jni::sys::jsize;
use serde_bytes::ByteBuf;

use super::{ChipError, ChipKeys};
use crate::ClientError;

const PROVIDER: &str = "AndroidKeyStore";
/// `KeyProperties.PURPOSE_SIGN`.
const PURPOSE_SIGN: i32 = 4;
/// The DER prefix of a P-256 `SubjectPublicKeyInfo` ahead of its point.
const P256_SPKI_PREFIX_LEN: usize = 26;

/// A failure reaching the Android Keystore through the Java VM.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreFailure {
    /// A refusal from the Java side, kept as the exception's text, else the JNI error's.
    #[error("Android Keystore: {0}")]
    Java(String),
    /// The process has no reachable Java VM.
    #[error("Android Keystore: {0}")]
    NoVm(String),
    /// The application's JNI access returned without running the body.
    #[error("Android Keystore: the JNI access ran nothing")]
    RanNothing,
}

/// The application's access to the process's Java VM.
pub trait JavaAccess: Send + Sync {
    /// Run `body` with a JNI environment attached to the calling thread.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when no Java VM is reachable.
    fn with_env(&self, body: &mut dyn FnMut(&mut JNIEnv<'_>)) -> Result<(), ClientError>;
}

/// The Android Keystore, reached through the application's JNI access.
pub(crate) struct AndroidKeystore {
    java: Arc<dyn JavaAccess>,
}

/// A P-256 key the Android Keystore holds and never releases.
pub struct KeystoreKey {
    java: Arc<dyn JavaAccess>,
    /// The alias the Keystore holds the key under.
    alias: String,
    private: GlobalRef,
    point: [u8; 65],
}

impl AndroidKeystore {
    /// The Keystore, reached through `java`.
    pub(crate) fn new(java: Arc<dyn JavaAccess>) -> Self {
        Self { java }
    }
}

impl ChipKeys for AndroidKeystore {
    type Key = KeystoreKey;

    fn find(&self, label: &str) -> Result<Option<KeystoreKey>, ChipError> {
        java(&*self.java, |env| {
            let store = loaded_keystore(env)?;
            let alias = env.new_string(label)?;
            let present = env
                .call_method(
                    &store,
                    "containsAlias",
                    "(Ljava/lang/String;)Z",
                    &[JValue::Object(&alias)],
                )?
                .z()?;
            if !present {
                return Ok(None);
            }
            let private = env
                .call_method(
                    &store,
                    "getKey",
                    "(Ljava/lang/String;[C)Ljava/security/Key;",
                    &[JValue::Object(&alias), JValue::Object(&JObject::null())],
                )?
                .l()?;
            let certificate = env
                .call_method(
                    &store,
                    "getCertificate",
                    "(Ljava/lang/String;)Ljava/security/cert/Certificate;",
                    &[JValue::Object(&alias)],
                )?
                .l()?;
            let public = env
                .call_method(
                    &certificate,
                    "getPublicKey",
                    "()Ljava/security/PublicKey;",
                    &[],
                )?
                .l()?;
            let encoded =
                JByteArray::from(env.call_method(&public, "getEncoded", "()[B", &[])?.l()?);
            let spki = env.convert_byte_array(&encoded)?;
            Ok(Some((env.new_global_ref(private)?, spki)))
        })?
        .map(|(private, spki)| {
            let point = spki
                .get(P256_SPKI_PREFIX_LEN..)
                .and_then(|point| <[u8; 65]>::try_from(point).ok())
                .ok_or_else(|| ChipError::Unavailable("the Keystore key is not P-256".into()))?;
            Ok(KeystoreKey {
                java: Arc::clone(&self.java),
                alias: label.to_string(),
                private,
                point,
            })
        })
        .transpose()
    }

    fn create(&self, label: &str) -> Result<KeystoreKey, ChipError> {
        {
            java(&*self.java, |env| {
                let algorithm = env.new_string("EC")?;
                let provider = env.new_string(PROVIDER)?;
                let generator = env
                    .call_static_method(
                        "java/security/KeyPairGenerator",
                        "getInstance",
                        "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
                        &[JValue::Object(&algorithm), JValue::Object(&provider)],
                    )?
                    .l()?;
                let alias = env.new_string(label)?;
                let builder = env.new_object(
                    "android/security/keystore/KeyGenParameterSpec$Builder",
                    "(Ljava/lang/String;I)V",
                    &[JValue::Object(&alias), JValue::Int(PURPOSE_SIGN)],
                )?;
                let curve = env.new_string("secp256r1")?;
                let curve = env.new_object(
                    "java/security/spec/ECGenParameterSpec",
                    "(Ljava/lang/String;)V",
                    &[JValue::Object(&curve)],
                )?;
                env.call_method(
                    &builder,
                    "setAlgorithmParameterSpec",
                    "(Ljava/security/spec/AlgorithmParameterSpec;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                    &[JValue::Object(&curve)],
                )?;
                let sha256 = env.new_string("SHA-256")?;
                let digests = env.new_object_array(1, "java/lang/String", &sha256)?;
                env.call_method(
                    &builder,
                    "setDigests",
                    "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                    &[JValue::Object(&digests)],
                )?;
                let challenge = env.byte_array_from_slice(ANDROID_ATTESTATION_CHALLENGE)?;
                env.call_method(
                    &builder,
                    "setAttestationChallenge",
                    "([B)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                    &[JValue::Object(&challenge)],
                )?;
                let spec = env
                    .call_method(
                        &builder,
                        "build",
                        "()Landroid/security/keystore/KeyGenParameterSpec;",
                        &[],
                    )?
                    .l()?;
                env.call_method(
                    &generator,
                    "initialize",
                    "(Ljava/security/spec/AlgorithmParameterSpec;)V",
                    &[JValue::Object(&spec)],
                )?;
                env.call_method(
                    &generator,
                    "generateKeyPair",
                    "()Ljava/security/KeyPair;",
                    &[],
                )?;
                Ok(())
            })?;
        }
        self.find(label)?
            .ok_or_else(|| ChipError::Unavailable("the Keystore did not keep the new key".into()))
    }

    fn delete(&self, label: &str) -> Result<(), ChipError> {
        java(&*self.java, |env| {
            let store = loaded_keystore(env)?;
            let alias = env.new_string(label)?;
            let present = env
                .call_method(
                    &store,
                    "containsAlias",
                    "(Ljava/lang/String;)Z",
                    &[JValue::Object(&alias)],
                )?
                .z()?;
            if !present {
                return Ok(());
            }
            env.call_method(
                &store,
                "deleteEntry",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&alias)],
            )?;
            Ok(())
        })?;
        Ok(())
    }
}

impl DeviceKey for KeystoreKey {
    fn public_point(&self) -> [u8; 65] {
        self.point
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
        java(&*self.java, |env| {
            let algorithm = env.new_string("SHA256withECDSA")?;
            let signature = env
                .call_static_method(
                    "java/security/Signature",
                    "getInstance",
                    "(Ljava/lang/String;)Ljava/security/Signature;",
                    &[JValue::Object(&algorithm)],
                )?
                .l()?;
            env.call_method(
                &signature,
                "initSign",
                "(Ljava/security/PrivateKey;)V",
                &[JValue::Object(self.private.as_obj())],
            )?;
            let bytes = env.byte_array_from_slice(message)?;
            env.call_method(&signature, "update", "([B)V", &[JValue::Object(&bytes)])?;
            let signed = JByteArray::from(env.call_method(&signature, "sign", "()[B", &[])?.l()?);
            env.convert_byte_array(&signed)
        })
        .map_err(|err| DeviceKeyError::Platform(Box::new(err)))
    }

    fn home(&self) -> KeyHome {
        KeyHome::AndroidKeystore { strongbox: false }
    }

    fn attestation(&self, _csr: &[u8]) -> Result<Option<DeviceAttestation>, DeviceKeyError> {
        let chain = java(&*self.java, |env| {
            let store = loaded_keystore(env)?;
            let alias = env.new_string(&self.alias)?;
            let chain = JObjectArray::from(
                env.call_method(
                    &store,
                    "getCertificateChain",
                    "(Ljava/lang/String;)[Ljava/security/cert/Certificate;",
                    &[JValue::Object(&alias)],
                )?
                .l()?,
            );
            let len: jsize = env.get_array_length(&chain)?;
            // A negative length fits no size, so the call is a JNI failure.
            let capacity = usize::try_from(len).map_err(|_| {
                jni::errors::Error::JniCall(jni::errors::JniError::Other(jni::sys::JNI_ERR))
            })?;
            let mut certificates = Vec::with_capacity(capacity);
            for index in 0..len {
                let certificate = env.get_object_array_element(&chain, index)?;
                let encoded = JByteArray::from(
                    env.call_method(&certificate, "getEncoded", "()[B", &[])?
                        .l()?,
                );
                certificates.push(env.convert_byte_array(&encoded)?);
            }
            Ok(certificates)
        })
        .map_err(|err| DeviceKeyError::Platform(Box::new(err)))?;
        Ok(Some(DeviceAttestation::AndroidKeyChain(
            chain.into_iter().map(ByteBuf::from).collect(),
        )))
    }
}

/// A loaded `AndroidKeyStore` instance.
fn loaded_keystore<'local>(env: &mut JNIEnv<'local>) -> jni::errors::Result<JObject<'local>> {
    let provider = env.new_string(PROVIDER)?;
    let store = env
        .call_static_method(
            "java/security/KeyStore",
            "getInstance",
            "(Ljava/lang/String;)Ljava/security/KeyStore;",
            &[JValue::Object(&provider)],
        )?
        .l()?;
    env.call_method(
        &store,
        "load",
        "(Ljava/security/KeyStore$LoadStoreParameter;)V",
        &[JValue::Object(&JObject::null())],
    )?;
    Ok(store)
}

/// Run `body` on an attached JNI environment, turning a pending Java
/// exception into its text.
fn java<T>(
    access: &dyn JavaAccess,
    body: impl FnOnce(&mut JNIEnv<'_>) -> jni::errors::Result<T>,
) -> Result<T, KeystoreFailure> {
    let mut body = Some(body);
    let mut outcome = None;
    access
        .with_env(&mut |env| {
            let Some(body) = body.take() else { return };
            outcome = Some(body(env).map_err(|err| exception_text(env, &err)));
        })
        .map_err(|err| KeystoreFailure::NoVm(err.to_string()))?;
    outcome.unwrap_or_else(|| Err(KeystoreFailure::RanNothing))
}

/// The pending Java exception's text, cleared, else the JNI error's.
fn exception_text(env: &mut JNIEnv<'_>, err: &jni::errors::Error) -> KeystoreFailure {
    let pending = env.exception_occurred().ok().filter(|ex| !ex.is_null());
    let _ = env.exception_clear();
    let text = pending
        .and_then(|ex| {
            env.call_method(&ex, "toString", "()Ljava/lang/String;", &[])
                .ok()
        })
        .and_then(|value| value.l().ok())
        .and_then(|text| env.get_string(&text.into()).ok().map(String::from));
    KeystoreFailure::Java(text.unwrap_or_else(|| err.to_string()))
}

impl From<KeystoreFailure> for ChipError {
    fn from(err: KeystoreFailure) -> Self {
        Self::Failed(Box::new(err))
    }
}
