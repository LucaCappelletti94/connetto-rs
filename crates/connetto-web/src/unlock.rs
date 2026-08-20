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
use std::pin::Pin;
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

/// What the application registers to answer the worker's account question.
///
/// It receives every account whose credential is stored and returns who to sign in
/// as.
type AccountChooser = dyn Fn(Vec<String>) -> Pin<Box<dyn Future<Output = AccountChoice>>>;

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

    /// What answers the worker's account question, registered by the application
    /// on the page side. Absent means no picker, which takes the default.
    static CHOOSER: RefCell<Option<Rc<AccountChooser>>> = const { RefCell::new(None) };

    /// An account a switch asked for, answered in place of consulting the
    /// chooser and cleared once used. Only ever set on the page that owns the
    /// worker, so leadership moving cannot resurrect a stale target.
    static PENDING_SWITCH: RefCell<Option<AccountChoice>> = const { RefCell::new(None) };
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
    /// Which account the tab chose to sign in as.
    Account(AccountChoice),
}

/// Who a boot should sign in as, answered by the tab against the accounts the
/// worker offered.
///
/// Three cases rather than an optional account, because "nobody yet" and "the
/// usual one" are different instructions and collapsing them makes a second
/// account unreachable: without [`New`](Self::New) the only way to sign one in is
/// to sign the current one out, which deletes the credential that would have made
/// it the second account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountChoice {
    /// Sign in as this stored account. It must be one the worker offered, and a
    /// name that was not is refused rather than answered with a login, because it
    /// is a caller bug rather than a stale credential.
    Named(String),
    /// Take the last-used account, which is what an application with no picker
    /// gets and what a dismissed picker should fall back to.
    LastUsed,
    /// Sign in as somebody new, leaving every stored credential alone.
    ///
    /// This is what puts a second account on the device. The boot addresses no
    /// stored credential, so it goes straight to an interactive login and the new
    /// credential lands beside the others.
    New,
}

/// What a [`TabAnswer`] is, for an error that has to name an answer it did not
/// expect.
pub(crate) fn answer_kind(answer: &TabAnswer) -> &'static str {
    match answer {
        TabAnswer::Key { .. } => "a derived key",
        TabAnswer::Declined => "a dismissal",
        TabAnswer::Unsupported => "no support",
        TabAnswer::Failed { .. } => "a failure",
        TabAnswer::Account(_) => "an account",
    }
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

/// The worker's own key store, the one whose derived key-encryption key an
/// unlock put in memory.
///
/// Anything in the worker that needs the device key after the gate must use this
/// rather than opening a second store: the derived key lives on the instance, so
/// a freshly opened one is locked on an enrolled profile even though the worker
/// is unlocked.
pub(crate) fn worker_key_store() -> Option<Rc<IdbKeyStore>> {
    WORKER_KEY_STORE.with(|slot| slot.borrow().clone())
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
        Some("account") => TabAnswer::Account(decode_choice(&data)),
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
    ask_tab(msg).await
}

/// Ask the tab to enrol for the first time and await its response.
///
/// Posts `{ kind: "enrol" }` to the page. It carries no identity: the credential
/// is one per device rather than one per account, so the tab names it after the
/// origin. See the plan's R23 decision 10.
///
/// # Errors
///
/// [`AuthError::Context`] if posting fails or no reply arrives.
pub(crate) async fn ask_enrol() -> Result<TabAnswer, AuthError> {
    let msg = {
        let obj = Object::new();
        set_str(&obj, "kind", "enrol");
        JsValue::from(obj)
    };
    ask_tab(msg).await
}

/// Ask the tab which account to sign in as, and await its answer.
///
/// Posts `{ kind: "account", accounts: ["<encoded id>", ...] }` to the page.
/// Sent after the gate, because the list comes out of the credential store and
/// that store does not open until the ceremony has run. One gesture to unlock
/// the device, then a choice of who, which is also the only order that costs a
/// single gesture.
///
/// # Errors
///
/// [`AuthError::Context`] if posting fails or no reply arrives.
pub(crate) async fn ask_account(accounts: &[String]) -> Result<TabAnswer, AuthError> {
    let msg = {
        let obj = Object::new();
        set_str(&obj, "kind", "account");
        let arr = js_sys::Array::new();
        for account in accounts {
            arr.push(&JsValue::from_str(account));
        }
        Reflect::set(&obj, &JsValue::from_str("accounts"), &arr).unwrap_throw();
        JsValue::from(obj)
    };
    ask_tab(msg).await
}

/// Read an [`AccountChoice`] off a tab answer.
///
/// An unrecognised or missing choice reads as [`AccountChoice::LastUsed`], which
/// is the one answer that can never be wrong: it is what an application with no
/// picker gets, so a garbled message costs the default rather than a login or
/// somebody else's account.
fn decode_choice(data: &JsValue) -> AccountChoice {
    let choice = Reflect::get(data, &JsValue::from_str("choice"))
        .ok()
        .and_then(|v| v.as_string());
    match choice.as_deref() {
        Some("new") => AccountChoice::New,
        Some("named") => Reflect::get(data, &JsValue::from_str("account"))
            .ok()
            .and_then(|v| v.as_string())
            .map_or(AccountChoice::LastUsed, AccountChoice::Named),
        _ => AccountChoice::LastUsed,
    }
}

fn post_to_tab(msg: &JsValue) -> Result<(), AuthError> {
    let global: DedicatedWorkerGlobalScope = js_sys::global()
        .dyn_into()
        .map_err(|_| AuthError::Context("unlock: not a dedicated worker scope".into()))?;
    global
        .post_message(msg)
        .map_err(|e| AuthError::Context(format!("unlock post: {e:?}")))
}

async fn ask_tab(msg: JsValue) -> Result<TabAnswer, AuthError> {
    let (tx, rx) = futures_channel::oneshot::channel::<TabAnswer>();
    let installed = PENDING.with(|p| {
        let mut pending = p.borrow_mut();
        if pending.is_some() {
            false
        } else {
            pending.replace(tx);
            true
        }
    });
    if !installed {
        return Err(AuthError::Context("unlock: overlapping tab request".into()));
    }
    if let Err(err) = post_to_tab(&msg) {
        PENDING.with(|p| p.borrow_mut().take());
        return Err(err);
    }
    rx.await.map_err(|_| AuthError::Cancelled)
}

fn set_str(obj: &Object, key: &str, val: &str) {
    Reflect::set(obj, &JsValue::from_str(key), &JsValue::from_str(val)).unwrap_throw();
}

// ──────────────────────────────────────────────────────────────── tab side ──

/// Install the permanent handler on `worker.onmessage` that answers unlock,
/// enrol and account requests from the DB worker.
///
/// An `unlock` request performs an assertion using the listed credential ids, an
/// `enrol` request creates a new credential, and both import the PRF output as an
/// HKDF key and post it back, or post `declined` or `unsupported` on failure. An
/// `account` request is answered by whatever [`serve_account_choice`] registered,
/// or with the default when nothing did.
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
                Some("enrol") => handle_enrol_request(&worker).await,
                Some("account") => handle_account_request(&worker, collect_accounts(&data)).await,
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
pub async fn enrol(worker: &Worker) -> Result<(), JsValue> {
    let key_and_id = create_credential().await?;
    match key_and_id {
        Some((credential_id, hkdf_key)) => post_key_to_worker(worker, &credential_id, &hkdf_key),
        None => post_unsupported(worker),
    }
}

/// Register what answers the worker's "which account?" question.
///
/// The chooser receives every account whose credential this profile holds, each
/// the encoded form of a user id, and returns who to sign in as. Returning
/// [`AccountChoice::LastUsed`] is what happens when no chooser is registered too,
/// so forgetting to register one costs the default rather than the boot, and
/// [`AccountChoice::New`] is how a second account gets onto the device.
///
/// Call it before the worker boots, alongside [`serve_unlock`], and only when the
/// worker configuration asks for the account question. The list arrives after the
/// unlock ceremony, because it comes out of the credential store.
pub fn serve_account_choice<F, Fut>(chooser: F)
where
    F: Fn(Vec<String>) -> Fut + 'static,
    Fut: Future<Output = AccountChoice> + 'static,
{
    let boxed: Rc<AccountChooser> = Rc::new(move |accounts| Box::pin(chooser(accounts)));
    CHOOSER.with(|slot| slot.borrow_mut().replace(boxed));
}

/// Record who the next worker boot must sign in as.
///
/// Set by a switch or by adding an account, both of which replace the worker, so
/// the replacement's account question is answered with this instead of reaching
/// the chooser. It is consumed by the first answer, so it cannot outlive the
/// switch that set it.
pub(crate) fn set_pending_switch(choice: AccountChoice) {
    PENDING_SWITCH.with(|slot| slot.borrow_mut().replace(choice));
}

// ─────────────────────────── tab-side ceremony helpers ─────────────────────

async fn handle_unlock_request(worker: &Worker, credential_ids: Vec<Vec<u8>>) {
    if credential_ids.is_empty() {
        let _ = post_unsupported(worker);
        return;
    }
    answer(worker, assert_credential(&credential_ids).await);
}

async fn handle_enrol_request(worker: &Worker) {
    answer(worker, create_credential().await);
}

/// Answer the worker's account question.
async fn handle_account_request(worker: &Worker, accounts: Vec<String>) {
    let chosen = chosen_account(accounts).await;
    let _ = post_account(worker, &chosen);
}

/// Which account to answer with: the switch target if a switch set one, otherwise
/// whatever the application registered, otherwise the last-used default.
///
/// A switch target wins because it is the more recent statement of intent: the
/// user asked for that account after the chooser was registered. It is consumed by
/// the one answer it was set for, so the boot after a switch reaches the chooser
/// again rather than flipping back.
///
/// Split from the posting so the precedence can be exercised without a worker to
/// post to. Every borrow is released before anything is awaited, because a chooser
/// that re-entered this while a slot was still borrowed would panic.
pub(crate) async fn chosen_account(accounts: Vec<String>) -> AccountChoice {
    if let Some(target) = PENDING_SWITCH.with(|slot| slot.borrow_mut().take()) {
        // A switch names an account the requester already saw in a list, so it
        // travels as-is and the worker refuses it if it is not stored.
        return target;
    }
    let chooser = CHOOSER.with(|slot| slot.borrow().clone());
    match chooser {
        Some(chooser) => chooser(accounts).await,
        None => AccountChoice::LastUsed,
    }
}

/// Post the outcome of a ceremony, keeping the failure kinds apart.
///
/// `Ok(None)` means the platform ran the ceremony and returned no extension
/// output, which is the honest unsupported case. A thrown `NotAllowedError` is a
/// dismissal or a credential that is gone, which `WebAuthn` deliberately does not
/// distinguish.
///
/// A `SecurityError` is unsupported rather than a fault, and it took running a
/// demo to find out: `WebAuthn` refuses an origin whose host is not a registrable
/// domain, so anything served from a bare IP address throws "this is an invalid
/// domain" on every attempt. That is a permanent property of where the
/// application is served, exactly like a browsing context with no `WebAuthn` at
/// all, so it must not fail the boot. Retrying cannot help and the operator's fix
/// is a hostname, which the custody reason is the right place to surface.
///
/// Anything else is a fault and travels as one, because reporting it as
/// unsupported would downgrade custody over a bug and blame the platform.
fn answer(worker: &Worker, outcome: Result<Option<(Vec<u8>, web_sys::CryptoKey)>, JsValue>) {
    let _ = match outcome {
        Ok(Some((cred_id, hkdf_key))) => post_key_to_worker(worker, &cred_id, &hkdf_key),
        Ok(None) => post_unsupported(worker),
        Err(err) if is_not_allowed(&err) => post_declined(worker),
        Err(err) if error_name(&err).as_deref() == Some("SecurityError") => {
            post_unsupported(worker)
        }
        Err(err) => post_failed(worker, &format!("{err:?}")),
    };
}

/// Create a new credential with PRF support. Returns the raw credential id and
/// the imported HKDF key on success, or `None` when PRF is not enabled.
async fn create_credential() -> Result<Option<(Vec<u8>, web_sys::CryptoKey)>, JsValue> {
    let creds = window_creds()?;

    let challenge = random_challenge()?;
    let challenge_arr = Uint8Array::from(challenge.as_slice());

    // rp.name is the site, not the person, and rp.id is omitted so it defaults
    // to the origin's effective domain. A deployment that moves origins
    // re-enrols, which is a stated property rather than a defect.
    let rp = web_sys::PublicKeyCredentialRpEntity::new(&origin_host());

    // The user entity names the device, never a person, because this credential
    // is one per device and unwraps every account's records: labelling it after
    // whoever enrolled first would show one person's name standing for all of
    // them, permanently, since WebAuthn has no rename and a second enrolment is
    // refused. See the plan's R23 decision 10. Both strings are display only,
    // and neither names connetto, which is a library an embedder's users should
    // never be shown.
    //
    // user.id stays a fixed literal for the same reason: platform
    // authenticators deduplicate by rp.id plus user.id, so a second sign-in does
    // not mint a second passkey. The bytes spell connetto/gate/v1.
    let user_id_bytes: [u8; 16] = [
        0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x74, 0x74, 0x6f, 0x2f, 0x67, 0x61, 0x74, 0x65, 0x2f, 0x76,
        0x31,
    ];
    let user_id_arr = Uint8Array::from(&user_id_bytes[..]);
    let user = web_sys::PublicKeyCredentialUserEntity::new_with_u8_array(
        "this device",
        &format!("local data on {}", origin_host()),
        &user_id_arr,
    );

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

fn collect_accounts(data: &JsValue) -> Vec<String> {
    let arr = Reflect::get(data, &JsValue::from_str("accounts"))
        .ok()
        .and_then(|v| v.dyn_into::<js_sys::Array>().ok());
    let Some(arr) = arr else {
        return Vec::new();
    };
    (0..arr.length())
        .filter_map(|i| arr.get(i).as_string())
        .collect()
}

/// The `DOMException` name a rejected ceremony carries, which is what tells a
/// dismissal from an origin that cannot host the gate.
fn error_name(err: &JsValue) -> Option<String> {
    Reflect::get(err, &JsValue::from_str("name"))
        .ok()
        .and_then(|v| v.as_string())
}

fn is_not_allowed(err: &JsValue) -> bool {
    error_name(err).as_deref() == Some("NotAllowedError")
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

/// Post who to sign in as.
///
/// Two fields rather than one nullable account, because three answers have to be
/// told apart and a null cannot carry the difference between "the usual one" and
/// "somebody new".
fn post_account(worker: &Worker, choice: &AccountChoice) -> Result<(), JsValue> {
    let obj = Object::new();
    set_str(&obj, "kind", "account");
    match choice {
        AccountChoice::Named(account) => {
            set_str(&obj, "choice", "named");
            set_str(&obj, "account", account);
        }
        AccountChoice::LastUsed => set_str(&obj, "choice", "last-used"),
        AccountChoice::New => set_str(&obj, "choice", "new"),
    }
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

#[cfg(test)]
mod tests {
    use super::{AccountChoice, chosen_account, serve_account_choice, set_pending_switch};
    use std::cell::RefCell;
    use std::rc::Rc;
    use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_dedicated_worker);

    /// R42: a switch names the account, and it does so exactly once.
    ///
    /// One test rather than three, because the registration is a thread-local with
    /// no way back: a sibling asserting that no chooser is registered would pass or
    /// fail on the order the binary happened to run in.
    ///
    /// The single-use half is what stops a switch from being sticky. Without it the
    /// target would answer every later boot in this page's life, so a user who
    /// switched once could never be asked again, and the chooser an application
    /// registered would be dead code from then on.
    #[wasm_bindgen_test]
    async fn a_switch_target_answers_once_and_then_the_chooser_does() {
        let offered = Rc::new(RefCell::new(Vec::new()));
        let seen = Rc::clone(&offered);
        serve_account_choice(move |accounts: Vec<String>| {
            let seen = Rc::clone(&seen);
            async move {
                seen.borrow_mut().push(accounts.len());
                AccountChoice::Named("\"alice\"".to_owned())
            }
        });

        set_pending_switch(AccountChoice::Named("\"bob\"".to_owned()));
        let accounts = vec!["\"alice\"".to_owned(), "\"bob\"".to_owned()];
        assert_eq!(
            chosen_account(accounts.clone()).await,
            AccountChoice::Named("\"bob\"".to_owned()),
            "the switch target wins over the chooser"
        );
        assert!(
            offered.borrow().is_empty(),
            "and the chooser was not even consulted"
        );

        assert_eq!(
            chosen_account(accounts.clone()).await,
            AccountChoice::Named("\"alice\"".to_owned()),
            "the target was consumed, so the next boot reaches the chooser"
        );
        assert_eq!(
            offered.borrow().as_slice(),
            [2],
            "which was handed both stored accounts to choose between"
        );

        // R54: adding an account travels the same way, and it is the only choice
        // that reaches an interactive login with credentials already stored.
        set_pending_switch(AccountChoice::New);
        assert_eq!(
            chosen_account(accounts).await,
            AccountChoice::New,
            "adding an account overrides the chooser exactly as a switch does"
        );
        assert_eq!(
            offered.borrow().as_slice(),
            [2],
            "and it did not consult the chooser either"
        );
    }
}
