//! Private-port passkey unlock protocol between the DB worker and its tab.
//!
//! The worker cannot call the `WebAuthn` ceremony (`PublicKeyCredential` is
//! `Exposed=Window`), so the flow splits across the boundary:
//!
//! * The worker posts a request over its own `postMessage` port (the dedicated
//!   worker's built-in outgoing channel to the page that spawned it).
//! * The tab runs the ceremony, imports the PRF output as an HKDF key, and
//!   posts the key object back over the same port.
//! * The worker derives the AES-GCM KEK from it, unlocks its key store, and
//!   updates the worker-side custody authority.
//!
//! A `CryptoKey` with no extractable flag survives the structured-clone post
//! intact, so the raw PRF bytes never exist in the worker context. The tab
//! imports them for exactly one `importKey` call and drops the reference.
//!
//! Never a `BroadcastChannel`: a non-extractable key on a shared channel would
//! hand any same-origin script the ability to unwrap the replica key.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{DedicatedWorkerGlobalScope, MessageEvent, Worker};

use connetto_core::custody::{Custody, NoGate};

use crate::auth::{AT_REST_PRF_INPUT, AuthError, IdbKeyStore};

/// How long the platform may keep a ceremony open, in milliseconds.
///
/// A bound rather than the user agent's default, which runs to minutes: an
/// unlock that cannot succeed, because the credential is gone, must fail the
/// boot in observable time instead of hanging it. Long enough that a user still
/// has room to find a sensor and be verified.
const CEREMONY_TIMEOUT_MS: u32 = 60_000;

// ────────────────────────────────────────────────────────── thread locals ──

thread_local! {
    /// The current custody level, set at boot and after a late enrolment.
    static CUSTODY: Cell<Custody> = const { Cell::new(Custody::Unverified(NoGate::Unsupported)) };

    /// Slot for an outstanding tab-answer. The permanent worker handler
    /// fulfils this when it receives a reply to an `unlock` or `enrol` request.
    static PENDING: RefCell<Option<futures_channel::oneshot::Sender<TabAnswer>>> =
        const { RefCell::new(None) };

    /// The worker-side key store, set once during boot so a late enrolment can
    /// call `adopt_derived` without a handle being threaded through every closure.
    static WORKER_KEY_STORE: RefCell<Option<Rc<IdbKeyStore>>> =
        const { RefCell::new(None) };
}

// ─────────────────────────────────────────────────────────── public types ──

/// An answer the tab sends back after receiving an unlock or enrol request.
pub enum TabAnswer {
    /// The tab ran the ceremony and imported the PRF output as an HKDF key.
    Key {
        /// The credential whose PRF output is in `key`.
        credential_id: Vec<u8>,
        /// An HKDF `CryptoKey` imported from the 32-byte PRF output.
        key: web_sys::CryptoKey,
    },
    /// The user dismissed the authenticator dialog or the credential is gone.
    Declined,
    /// This browsing context has no `WebAuthn`, so nothing can be offered here.
    Unsupported,
    /// The ceremony threw something that is neither a dismissal nor absent
    /// support. Kept distinct because collapsing it into `Unsupported` would
    /// silently downgrade custody on a bug and report a platform limitation
    /// that does not exist.
    Failed {
        /// What the platform said, for the boot error that carries it.
        detail: String,
    },
}

// ──────────────────────────────────────────────────────────── worker side ──

/// Read the current custody level from the worker-side authority.
///
/// This is the single source of truth for the browser: nothing else
/// in the worker should construct or set a `Custody` value.
#[must_use]
pub fn custody() -> Custody {
    CUSTODY.with(Cell::get)
}

/// Set the worker-side custody and key store. Called once during
/// `boot_db_worker` before the first unlock interaction.
pub(crate) fn init_worker(key_store: Rc<IdbKeyStore>, initial: Custody) {
    CUSTODY.with(|c| c.set(initial));
    WORKER_KEY_STORE.with(|ks| ks.borrow_mut().replace(key_store));
}

/// Update the worker-side custody after an unlock or enrol outcome.
///
/// Called from `boot_db_worker` once the tab's answer is processed.
pub(crate) fn set_custody(c: Custody) {
    CUSTODY.with(|cell| cell.set(c));
}

/// Install the permanent `onmessage` handler on the dedicated worker global
/// scope. Must be called before any tab-request is sent.
///
/// # Errors
///
/// [`JsValue`] if the global scope cannot be cast to [`DedicatedWorkerGlobalScope`].
pub(crate) fn install_worker_handler() -> Result<(), JsValue> {
    let global: DedicatedWorkerGlobalScope = js_sys::global()
        .dyn_into()
        .map_err(|_| JsValue::from_str("unlock handler: not a dedicated worker scope"))?;
    let handler = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
        handle_worker_message(&event);
    });
    global.set_onmessage(Some(handler.as_ref().unchecked_ref()));
    // The handler lives for the worker's whole life.
    handler.forget();
    Ok(())
}

fn handle_worker_message(event: &MessageEvent) {
    let data = event.data();
    let kind = Reflect::get(&data, &JsValue::from_str("kind"))
        .ok()
        .and_then(|v| v.as_string());
    let answer = match kind.as_deref() {
        Some("key") => {
            let cred_b64 = Reflect::get(&data, &JsValue::from_str("credentialId"))
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_default();
            let cred_id = URL_SAFE_NO_PAD
                .decode(cred_b64.as_bytes())
                .unwrap_or_default();
            let key: web_sys::CryptoKey = match Reflect::get(&data, &JsValue::from_str("key"))
                .ok()
                .and_then(|v| v.dyn_into::<web_sys::CryptoKey>().ok())
            {
                Some(k) => k,
                None => return,
            };
            TabAnswer::Key {
                credential_id: cred_id,
                key,
            }
        }
        Some("declined") => TabAnswer::Declined,
        Some("unsupported") => TabAnswer::Unsupported,
        Some("failed") => TabAnswer::Failed {
            detail: Reflect::get(&data, &JsValue::from_str("detail"))
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_else(|| "no detail".to_owned()),
        },
        _ => return,
    };

    // Route to the pending oneshot if one is waiting, otherwise treat as a
    // late enrolment.
    let sender = PENDING.with(|p| p.borrow_mut().take());
    if let Some(tx) = sender {
        let _ = tx.send(answer);
    } else if let TabAnswer::Key { credential_id, key } = answer {
        // Late enrolment: a tab enrolled while the worker was already running.
        let ks = WORKER_KEY_STORE.with(|s| s.borrow().clone());
        if let Some(ks) = ks {
            spawn_local(async move {
                match ks.adopt_derived(key, &credential_id).await {
                    Ok(()) => {
                        CUSTODY.with(|c| c.set(Custody::Verified));
                    }
                    Err(err) => {
                        tracing::error!(error = %err, "unlock: late enrolment adopt_derived failed");
                    }
                }
            });
        }
    }
}

/// Ask the tab to unlock an enrolled profile and await its response.
///
/// Posts `{ kind: "unlock", credentials: ["<base64url>", ...] }` to the page
/// that owns this worker.
///
/// # Errors
///
/// [`AuthError::Context`] if the global scope cannot be used to post, or if
/// the tab sends no reply.
pub(crate) async fn ask_unlock(credentials: Vec<Vec<u8>>) -> Result<TabAnswer, AuthError> {
    let msg = {
        let obj = Object::new();
        set_str(&obj, "kind", "unlock");
        let arr = js_sys::Array::new();
        for id in &credentials {
            arr.push(&JsValue::from_str(&URL_SAFE_NO_PAD.encode(id)));
        }
        Reflect::set(&obj, &JsValue::from_str("credentials"), &arr).unwrap_throw();
        JsValue::from(obj)
    };
    post_to_tab(&msg)?;
    await_answer().await
}

/// Ask the tab to enrol for the first time and await its response.
///
/// Posts `{ kind: "enrol", label: "<label>" }` to the page. The label is the
/// signed-in identity, used only for the authenticator UI prompt.
///
/// # Errors
///
/// [`AuthError::Context`] if posting fails or no reply arrives.
pub(crate) async fn ask_enrol(label: &str) -> Result<TabAnswer, AuthError> {
    let msg = {
        let obj = Object::new();
        set_str(&obj, "kind", "enrol");
        set_str(&obj, "label", label);
        JsValue::from(obj)
    };
    post_to_tab(&msg)?;
    await_answer().await
}

fn post_to_tab(msg: &JsValue) -> Result<(), AuthError> {
    let global: DedicatedWorkerGlobalScope = js_sys::global()
        .dyn_into()
        .map_err(|_| AuthError::Context("unlock: not a dedicated worker scope".into()))?;
    global
        .post_message(msg)
        .map_err(|e| AuthError::Context(format!("unlock post: {e:?}")))
}

async fn await_answer() -> Result<TabAnswer, AuthError> {
    let (tx, rx) = futures_channel::oneshot::channel::<TabAnswer>();
    PENDING.with(|p| p.borrow_mut().replace(tx));
    rx.await.map_err(|_| AuthError::Cancelled)
}

fn set_str(obj: &Object, key: &str, val: &str) {
    Reflect::set(obj, &JsValue::from_str(key), &JsValue::from_str(val)).unwrap_throw();
}

// ──────────────────────────────────────────────────────────────── tab side ──

/// Install the permanent handler on `worker.onmessage` that answers unlock
/// and enrol requests from the DB worker by running the `WebAuthn` ceremony.
///
/// Both request kinds are handled: an `unlock` request performs an assertion
/// using the listed credential ids, while an `enrol` request creates a new
/// credential. On success the tab imports the PRF output as an HKDF key and
/// posts it back. On failure it posts `declined` or `unsupported`.
///
/// An unsolicited key (received while no request is outstanding) is treated by
/// the worker as a late enrolment.
///
/// # Errors
///
/// [`JsValue`] if the handler cannot be installed.
pub fn serve_unlock(worker: &Worker) -> Result<(), JsValue> {
    let worker_for_handler = worker.clone();
    let handler = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
        let worker = worker_for_handler.clone();
        spawn_local(async move {
            let data = event.data();
            let kind = Reflect::get(&data, &JsValue::from_str("kind"))
                .ok()
                .and_then(|v| v.as_string());
            match kind.as_deref() {
                Some("unlock") => {
                    let credentials = collect_credentials(&data);
                    handle_unlock_request(&worker, credentials).await;
                }
                Some("enrol") => {
                    let label = Reflect::get(&data, &JsValue::from_str("label"))
                        .ok()
                        .and_then(|v| v.as_string())
                        .unwrap_or_default();
                    handle_enrol_request(&worker, &label).await;
                }
                _ => {}
            }
        });
    });
    worker.set_onmessage(Some(handler.as_ref().unchecked_ref()));
    // The handler lives as long as this page does.
    handler.forget();
    Ok(())
}

/// Perform an unsolicited enrolment from the tab side. The worker treats the
/// resulting key as a late enrolment.
///
/// Use this when the application wants to offer gate enrolment after boot
/// (e.g. from a settings screen). The worker's `onmessage` handler routes an
/// unsolicited `key` message to [`IdbKeyStore::adopt_derived`] automatically.
///
/// # Errors
///
/// [`JsValue`] if the ceremony fails or the key cannot be posted.
pub async fn enrol(worker: &Worker, label: &str) -> Result<(), JsValue> {
    let key_and_id = create_credential(label).await?;
    match key_and_id {
        Some((credential_id, hkdf_key)) => post_key_to_worker(worker, &credential_id, &hkdf_key),
        None => post_unsupported(worker),
    }
}

// ─────────────────────────── tab-side ceremony helpers ─────────────────────

async fn handle_unlock_request(worker: &Worker, credential_ids: Vec<Vec<u8>>) {
    if credential_ids.is_empty() {
        let _ = post_unsupported(worker);
        return;
    }
    answer(worker, assert_credential(&credential_ids).await);
}

async fn handle_enrol_request(worker: &Worker, label: &str) {
    answer(worker, create_credential(label).await);
}

/// Post the outcome of a ceremony, keeping the three failure kinds apart.
///
/// `Ok(None)` means the platform ran the ceremony and returned no extension
/// output, which is the honest unsupported case. A thrown `NotAllowedError` is a
/// dismissal or a credential that is gone, which `WebAuthn` deliberately does not
/// distinguish. Anything else is a fault and travels as one, because reporting it
/// as unsupported would downgrade custody over a bug and blame the platform.
fn answer(worker: &Worker, outcome: Result<Option<(Vec<u8>, web_sys::CryptoKey)>, JsValue>) {
    let _ = match outcome {
        Ok(Some((cred_id, hkdf_key))) => post_key_to_worker(worker, &cred_id, &hkdf_key),
        Ok(None) => post_unsupported(worker),
        Err(err) if is_not_allowed(&err) => post_declined(worker),
        Err(err) => post_failed(worker, &format!("{err:?}")),
    };
}

/// Create a new credential with PRF support. Returns the raw credential id and
/// the imported HKDF key on success, or `None` when PRF is not enabled.
async fn create_credential(label: &str) -> Result<Option<(Vec<u8>, web_sys::CryptoKey)>, JsValue> {
    let creds = window_creds()?;

    let challenge = random_challenge()?;
    let challenge_arr = Uint8Array::from(challenge.as_slice());

    // rp.name is the site, not the person, and rp.id is omitted so it defaults
    // to the origin's effective domain. A deployment that moves origins
    // re-enrols, which is a stated property rather than a defect.
    let rp = web_sys::PublicKeyCredentialRpEntity::new(&origin_host());

    // user.name is what a password manager shows the user later, so it carries
    // the account they just signed in as. user.id stays a fixed literal
    // because the gate is one device-scoped credential rather than one per
    // identity, and platform authenticators deduplicate by rp.id plus user.id,
    // so a second sign-in does not mint a second passkey. The bytes spell
    // connetto/gate/v1.
    let user_id_bytes: [u8; 16] = [
        0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x74, 0x74, 0x6f, 0x2f, 0x67, 0x61, 0x74, 0x65, 0x2f, 0x76,
        0x31,
    ];
    let user_id_arr = Uint8Array::from(&user_id_bytes[..]);
    let user =
        web_sys::PublicKeyCredentialUserEntity::new_with_u8_array(label, label, &user_id_arr);

    let params = pub_key_params();
    let opts = web_sys::PublicKeyCredentialCreationOptions::new_with_u8_array(
        &challenge_arr,
        &params,
        &rp,
        &user,
    );

    opts.set_timeout(CEREMONY_TIMEOUT_MS);
    let selection = web_sys::AuthenticatorSelectionCriteria::new();
    // residentKey preferred uniformly (plan decision 2).
    selection.set_resident_key("preferred");
    selection.set_user_verification(web_sys::UserVerificationRequirement::Required);
    opts.set_authenticator_selection(&selection);

    let prf_ext = prf_extension(AT_REST_PRF_INPUT);
    opts.set_extensions(&prf_ext);

    let cc = web_sys::CredentialCreationOptions::new();
    cc.set_public_key(&opts);

    let credential: web_sys::PublicKeyCredential = JsFuture::from(creds.create_with_options(&cc)?)
        .await?
        .dyn_into()?;

    let ext = credential.get_client_extension_results();
    let Some(prf) = ext.get_prf() else {
        return Ok(None);
    };
    // Some platforms return the PRF output at creation time.
    if let Some(results) = prf.get_results() {
        let first_val = results.get_first();
        let first_bytes = Uint8Array::new(first_val.as_ref()).to_vec();
        let raw_id = Uint8Array::new(credential.raw_id().as_ref()).to_vec();
        let hkdf_key = import_hkdf_key(&first_bytes).await?;
        return Ok(Some((raw_id, hkdf_key)));
    }
    // PRF is enabled but the output requires a separate assertion round-trip.
    // Perform the assertion immediately to get the output.
    let raw_id = Uint8Array::new(credential.raw_id().as_ref()).to_vec();
    match assert_for_id(&raw_id).await? {
        Some((_, hkdf_key)) => Ok(Some((raw_id, hkdf_key))),
        None => Ok(None),
    }
}

/// Assert using one of `credential_ids` and return the raw id and HKDF key.
async fn assert_credential(
    credential_ids: &[Vec<u8>],
) -> Result<Option<(Vec<u8>, web_sys::CryptoKey)>, JsValue> {
    let creds = window_creds()?;

    let challenge = random_challenge()?;
    let challenge_arr = Uint8Array::from(challenge.as_slice());

    let opts = web_sys::PublicKeyCredentialRequestOptions::new_with_u8_array(&challenge_arr);
    opts.set_user_verification(web_sys::UserVerificationRequirement::Required);
    opts.set_timeout(CEREMONY_TIMEOUT_MS);

    let allow = js_sys::Array::new();
    for id in credential_ids {
        let id_arr = Uint8Array::from(id.as_slice());
        let desc = web_sys::PublicKeyCredentialDescriptor::new_with_u8_array(
            &id_arr,
            web_sys::PublicKeyCredentialType::PublicKey,
        );
        allow.push(desc.as_ref());
    }
    opts.set_allow_credentials(&allow);

    let prf_ext = prf_extension(AT_REST_PRF_INPUT);
    opts.set_extensions(&prf_ext);

    let rc = web_sys::CredentialRequestOptions::new();
    rc.set_public_key(&opts);

    let assertion: web_sys::PublicKeyCredential = JsFuture::from(creds.get_with_options(&rc)?)
        .await?
        .dyn_into()?;

    let ext = assertion.get_client_extension_results();
    let Some(prf) = ext.get_prf() else {
        return Ok(None);
    };
    let Some(results) = prf.get_results() else {
        return Ok(None);
    };
    let first_val = results.get_first();
    let first_bytes = Uint8Array::new(first_val.as_ref()).to_vec();
    let raw_id = Uint8Array::new(assertion.raw_id().as_ref()).to_vec();
    let hkdf_key = import_hkdf_key(&first_bytes).await?;
    Ok(Some((raw_id, hkdf_key)))
}

/// Assert using a single known `credential_id`. Used when the creation round
/// does not return PRF output directly.
async fn assert_for_id(
    credential_id: &[u8],
) -> Result<Option<(Vec<u8>, web_sys::CryptoKey)>, JsValue> {
    assert_credential(&[credential_id.to_vec()]).await
}

/// Import 32 PRF output bytes as a non-extractable HKDF key.
async fn import_hkdf_key(bytes: &[u8]) -> Result<web_sys::CryptoKey, JsValue> {
    let win = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
    let subtle = win.crypto()?.subtle();

    let params = Object::new();
    Reflect::set(
        &params,
        &JsValue::from_str("name"),
        &JsValue::from_str("HKDF"),
    )
    .unwrap_throw();
    let usages = js_sys::Array::new();
    usages.push(&JsValue::from_str("deriveBits"));
    let raw_arr = Uint8Array::from(bytes);
    let key_js = JsFuture::from(subtle.import_key_with_object(
        "raw",
        raw_arr.unchecked_ref::<Object>(),
        &params,
        false,
        &usages,
    )?)
    .await?;
    Ok(key_js.unchecked_into::<web_sys::CryptoKey>())
}

// The derive is done in the worker, not here. Once the HKDF key is posted the
// tab drops all references and retains nothing.

fn window_creds() -> Result<web_sys::CredentialsContainer, JsValue> {
    let win = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
    Ok(win.navigator().credentials())
}

/// The origin's host, which is what `rp.id` defaults to anyway, so naming the
/// relying party after it cannot disagree with the credential's own scope.
fn origin_host() -> String {
    web_sys::window()
        .and_then(|win| win.location().hostname().ok())
        .filter(|host| !host.is_empty())
        .unwrap_or_else(|| "connetto".to_owned())
}

/// Build a PRF extension input object with `AT_REST_PRF_INPUT` as the first input.
fn prf_extension(input: &[u8]) -> web_sys::AuthenticationExtensionsClientInputs {
    let values =
        web_sys::AuthenticationExtensionsPrfValues::new_with_u8_array(&Uint8Array::from(input));
    let inputs = web_sys::AuthenticationExtensionsPrfInputs::new();
    inputs.set_eval(&values);
    let client = web_sys::AuthenticationExtensionsClientInputs::new();
    client.set_prf(&inputs);
    client
}

fn pub_key_params() -> js_sys::Array {
    let arr = js_sys::Array::new();
    let es256 = web_sys::PublicKeyCredentialParameters::new(
        -7,
        web_sys::PublicKeyCredentialType::PublicKey,
    );
    let rs256 = web_sys::PublicKeyCredentialParameters::new(
        -257,
        web_sys::PublicKeyCredentialType::PublicKey,
    );
    arr.push(es256.as_ref());
    arr.push(rs256.as_ref());
    arr
}

fn random_challenge() -> Result<Vec<u8>, JsValue> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| JsValue::from_str(&format!("rng: {e}")))?;
    Ok(bytes.to_vec())
}

fn collect_credentials(data: &JsValue) -> Vec<Vec<u8>> {
    let arr = Reflect::get(data, &JsValue::from_str("credentials"))
        .ok()
        .and_then(|v| v.dyn_into::<js_sys::Array>().ok());
    let Some(arr) = arr else {
        return Vec::new();
    };
    (0..arr.length())
        .filter_map(|i| {
            arr.get(i)
                .as_string()
                .and_then(|s| URL_SAFE_NO_PAD.decode(s.as_bytes()).ok())
        })
        .collect()
}

fn is_not_allowed(err: &JsValue) -> bool {
    Reflect::get(err, &JsValue::from_str("name"))
        .ok()
        .and_then(|v| v.as_string())
        .as_deref()
        == Some("NotAllowedError")
}

fn post_key_to_worker(
    worker: &Worker,
    credential_id: &[u8],
    hkdf_key: &web_sys::CryptoKey,
) -> Result<(), JsValue> {
    let obj = Object::new();
    Reflect::set(&obj, &JsValue::from_str("kind"), &JsValue::from_str("key")).unwrap_throw();
    Reflect::set(
        &obj,
        &JsValue::from_str("credentialId"),
        &JsValue::from_str(&URL_SAFE_NO_PAD.encode(credential_id)),
    )
    .unwrap_throw();
    Reflect::set(&obj, &JsValue::from_str("key"), hkdf_key.as_ref()).unwrap_throw();
    worker.post_message(&JsValue::from(obj))
}

fn post_declined(worker: &Worker) -> Result<(), JsValue> {
    let obj = Object::new();
    Reflect::set(
        &obj,
        &JsValue::from_str("kind"),
        &JsValue::from_str("declined"),
    )
    .unwrap_throw();
    worker.post_message(&JsValue::from(obj))
}

fn post_unsupported(worker: &Worker) -> Result<(), JsValue> {
    let obj = Object::new();
    Reflect::set(
        &obj,
        &JsValue::from_str("kind"),
        &JsValue::from_str("unsupported"),
    )
    .unwrap_throw();
    worker.post_message(&JsValue::from(obj))
}

fn post_failed(worker: &Worker, detail: &str) -> Result<(), JsValue> {
    let obj = Object::new();
    Reflect::set(
        &obj,
        &JsValue::from_str("kind"),
        &JsValue::from_str("failed"),
    )
    .unwrap_throw();
    Reflect::set(
        &obj,
        &JsValue::from_str("detail"),
        &JsValue::from_str(detail),
    )
    .unwrap_throw();
    worker.post_message(&JsValue::from(obj))
}
