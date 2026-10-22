//! The browser platform: the dedicated DB worker and its boot, the tab
//! attachment behind the leader election, the popup login, the last signed-in
//! account in `localStorage` and the Blob export and import.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use crate::connetto_schema_bundle;
use connetto_client::{
    AccountChoice, Auth, ClientEvent, ConnettoClient, Custody, ExportScope, NoGate, SyncSchema,
    SyncTuning,
    reconnect::ReconnectPolicy,
    teardown::{ExpiryWarning, expiry_warning},
};
use connetto_web::builder::{AttachedTab, TabTopology, WebClientBuilder};
use connetto_web::leader::Membership;
use connetto_web::unlock::serve_account_choice;
use connetto_web::{MessageTransport, TabContent, deliver_login_code, workers};
use dioxus::prelude::*;
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use web_sys::{BroadcastChannel, MessageEvent};

use crate::platform::{Client, DemoContent};
use crate::ui::*;

/// The OPFS file holding the worker's durable synced replica (base name; the
/// worker appends the identity hash so each account gets its own encrypted file).
const DB_NAME: &str = "connetto-relay.sqlite";
/// The OPFS file holding the worker-only refresh token, encrypted at rest.
const AUTH_DB_NAME: &str = "connetto-auth.sqlite";
/// The shared leader lock every window of this app races.
const LEADER_LOCK: &str = "connetto-demo-leader";
/// BroadcastChannel on which the worker publishes the session fields once it
/// has acquired a session.
const DEMO_UID_CHANNEL: &str = "connetto-demo-uid";
/// OIDC provider registered in the dev IdP.
const AUTH_PROVIDER: &str = "dev-idp";
/// Path the dev IdP redirects back to after login.
const AUTH_CALLBACK_PATH: &str = "/auth/callback";
/// Channel the page uses to respond to the worker's provider query at each boot.
const DEMO_PROVIDER_CHANNEL: &str = "connetto-demo-provider";
/// File name the export download is offered under.
pub const EXPORT_FILE_NAME: &str = "connetto-local-data.zip";
/// The `localStorage` key holding the account the last successful sign-in used.
const STORED_ACCOUNT_KEY: &str = "connetto-demo-last-account";
/// How far ahead of the session deadline the expiry warning starts.
const EXPIRY_LEAD: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The one build the worker boots from and every window attaches through.
fn demo_builder() -> WebClientBuilder {
    WebClientBuilder::new(
        crate::DEMO_WS_URL,
        SyncSchema::new(connetto_schema_bundle::bundle()),
    )
    .with_tuning(SyncTuning::default().with_trim_threshold(5))
    .with_reconnect(
        ReconnectPolicy::new()
            .with_initial_backoff(Duration::from_millis(100))
            .with_max_backoff(Duration::from_secs(2)),
    )
    .with_upstream("db-upstream", crate::DEMO_QUERY)
    .with_upstream("db-photos-upstream", crate::PHOTO_QUERY)
    .with_content_namespace("connetto-photo-content")
    .with_content_heal_lost(
        "SELECT content_id FROM photos WHERE content_state = 'lost'",
        "content_id",
    )
}

/// Worker context: ask the page which OIDC provider to use for this boot.
///
/// The page responds with the user's last choice within a few milliseconds.
/// Falls back to [`AUTH_PROVIDER`] after 200 ms so a page that never answers
/// does not stall the boot indefinitely.
async fn worker_provider() -> String {
    let Ok(ch) = BroadcastChannel::new(DEMO_PROVIDER_CHANNEL) else {
        return AUTH_PROVIDER.to_owned();
    };
    let received: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let received_clone = Rc::clone(&received);
    let on_msg = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
        if let Some(text) = e.data().as_string()
            && text != "provider?"
        {
            *received_clone.borrow_mut() = Some(text);
        }
    });
    ch.set_onmessage(Some(on_msg.as_ref().unchecked_ref()));
    let _ = ch.post_message(&JsValue::from_str("provider?"));
    for _ in 0..8 {
        workers::sleep(core::time::Duration::from_millis(25)).await;
        if received.borrow().is_some() {
            break;
        }
    }
    ch.set_onmessage(None);
    ch.close();
    drop(on_msg);
    received
        .borrow()
        .clone()
        .unwrap_or_else(|| AUTH_PROVIDER.to_owned())
}

/// Boot the connetto DB tier in the worker context.
///
/// Signs in against [`crate::AUTH_BASE`]. Once the session is acquired, the
/// boot returns the identity, account key, and session deadline, which are
/// all broadcast on a `BroadcastChannel` so the page can display which account
/// is live and warn before an offline session lapses.
///
/// # Errors
///
/// A JS string describing the VFS, acquisition, upstream connect, or subscribe
/// failure.
pub async fn run_db_worker() -> Result<(), JsValue> {
    let origin = worker_origin();
    let booted = demo_builder()
        .signed_in(
            Auth::new(crate::AUTH_BASE, worker_provider().await).with_account(AccountChoice::Ask),
        )
        .with_redirect_uri(format!("{origin}{AUTH_CALLBACK_PATH}"))
        .with_auth_db_name(AUTH_DB_NAME)
        .durable(DB_NAME)
        .boot::<String>()
        .await?;
    // Post all three session fields in one JS object so the page can show the
    // live account, warn before expiry, and populate the switch buttons.
    if let Ok(ch) = BroadcastChannel::new(DEMO_UID_CHANNEL) {
        let obj = js_sys::Object::new();
        if let Some(uid) = &booted.identity {
            let _ = js_sys::Reflect::set(&obj, &JsValue::from_str("uid"), &JsValue::from_str(uid));
        }
        if let Some(acc) = &booted.account {
            let _ =
                js_sys::Reflect::set(&obj, &JsValue::from_str("account"), &JsValue::from_str(acc));
        }
        if let Some(secs) = booted.session_expires_at {
            // Unix seconds fit in f64 exactly: 2^53 (~9e15) >> any plausible session deadline.
            debug_assert!(
                secs <= (1u64 << 53),
                "session_expires_at exceeds f64 exact range"
            );
            let _ = js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("session_expires_at"),
                &JsValue::from_f64(secs as f64),
            );
        }
        let _ = ch.post_message(&obj);
        ch.close();
    }
    Ok(())
}

/// The served URL of this app's wasm-bindgen glue module, the module script
/// the page itself loads. `dx serve` names it `/wasm/<name>.js`, and a release
/// build hashes it apart from the wasm's own hash, so neither name can be
/// derived from the other, while the page's script tag carries it in both.
/// Only the main thread has the page, which is why the worker receives the
/// glue URL as a spawn parameter.
fn glue_url() -> String {
    js_sys::eval(&format!(
        r#"[...document.querySelectorAll('script[type="module"][src]')].map((s) => s.src).find((s) => s.split("/").pop().startsWith("{}"))"#,
        env!("CARGO_PKG_NAME")
    ))
    .ok()
    .and_then(|value| value.as_string())
    .expect("the page loads the app's glue module")
}

/// The window's live connection to the DB worker, plus the topology tokens it
/// must keep alive: leadership (this window may own the worker) and the tab
/// liveness lock (dropped on unmount, so the worker reaps this tab).
pub struct Boot {
    pub client: ConnettoClient<MessageTransport<web_sys::BroadcastChannel>>,
    /// The tab's content lane, split off the transport before the client took it.
    pub content: Rc<TabContent<web_sys::BroadcastChannel>>,
    /// Shared rather than owned, because the gate ceremony is awaited and the
    /// handle has to outlive the borrow that reaches it.
    pub membership: Rc<Membership>,
    _tab: AttachedTab,
}

/// Join the topology and attach this window's tab client.
///
/// The winner of the leader election spawns the worker from the dx glue,
/// which auto-initializes on import and runs `main`, so no separate bootstrap
/// is needed.
async fn boot_window() -> Result<Boot, JsValue> {
    let glue = glue_url();
    let tab = demo_builder()
        .attach(TabTopology {
            leader_lock: LEADER_LOCK,
            glue_url: &glue,
            bootstrap: workers::WorkerBootstrap::Glue,
        })
        .await
        .map_err(|err| JsValue::from_str(&err.to_string()))?;
    let content = tab
        .content
        .clone()
        .ok_or_else(|| JsValue::from_str("the demo build keeps files"))?;
    Ok(Boot {
        client: tab.client.clone(),
        content,
        membership: Rc::clone(&tab.membership),
        _tab: tab,
    })
}

// --- Auth helpers ------------------------------------------------------------

/// If the page URL carries `?code=...&state=...`, return the pair.
pub fn page_login_callback() -> Option<(String, String)> {
    // Returns [code, state] or null via a self-executing function.
    let result = js_sys::eval(
        "(function(){\
            var p=new URLSearchParams(location.search);\
            var c=p.get('code'),s=p.get('state');\
            return c&&s?[c,s]:null;\
        })()",
    )
    .ok()?;
    if result.is_null() || result.is_undefined() {
        return None;
    }
    let arr = js_sys::Array::from(&result);
    let code = arr.get(0).as_string()?;
    let state = arr.get(1).as_string()?;
    Some((code, state))
}

/// True when this page was opened by another page on this origin, which is how
/// a login popup is distinguished from the application itself.
pub fn is_login_popup() -> bool {
    js_sys::eval("window.opener !== null && window.opener !== undefined")
        .ok()
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

/// Strip the query string from the current URL without a page reload so a
/// spent authorization code is not replayed on refresh.
pub fn clear_url_query() {
    let _ = js_sys::eval("history.replaceState(null,'',location.pathname)");
}

/// Reload the page after logout, dropping the remembered account first.
pub fn reload_page() {
    clear_stored_account();
    let _ = js_sys::eval("location.reload()");
}

/// Open `url` in a popup to run the login there.
///
/// Navigating this tab instead would destroy the page, and with it the
/// dedicated DB worker that asked for the login and holds the PKCE verifier.
/// A popup leaves the opener and its worker alive.
pub fn open_login_popup(url: &str) {
    // Encode the URL as a JSON string literal so it is safe regardless of
    // what characters the IdP URL carries.
    let encoded = js_sys::JSON::stringify(&JsValue::from_str(url))
        .ok()
        .and_then(|s| s.as_string())
        .unwrap_or_else(|| format!("\"{}\"", url.replace('"', "%22")));
    let _ = js_sys::eval(&format!(
        "window.open({encoded},'connetto-login','popup=yes,width=520,height=640')"
    ));
}

/// The origin of the worker's own URL, e.g. `http://127.0.0.1:9912`.
///
/// Same as the page origin because the worker script is served from the same
/// host. The login callback returns here.
fn worker_origin() -> String {
    js_sys::eval("self.location.origin")
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default()
}

/// Offer `blob` to the user as a file download named `name`.
///
/// The worker hands over the archive as a `Blob` already, so the page puts it
/// at an object URL and clicks a synthetic anchor without reading one byte of
/// it. The URL is revoked immediately, since the click has already taken its
/// own reference.
pub fn download_blob(name: &str, blob: &web_sys::Blob) -> Result<(), JsValue> {
    let url = web_sys::Url::create_object_url_with_blob(blob)?;
    let document = web_sys::window()
        .and_then(|window| window.document())
        .ok_or_else(|| JsValue::from_str("no document"))?;
    let anchor: web_sys::HtmlAnchorElement = document.create_element("a")?.dyn_into()?;
    anchor.set_href(&url);
    anchor.set_download(name);
    anchor.click();
    web_sys::Url::revoke_object_url(&url)
}

/// The account the last successful sign-in on this origin used, or `None`.
///
/// Read at first paint, before the worker re-acquires the session.
fn read_stored_account() -> Option<String> {
    let storage = web_sys::window()?.local_storage().ok().flatten()?;
    storage.get_item(STORED_ACCOUNT_KEY).ok().flatten()
}

/// Remember the account a successful sign-in used, so a reload knows a restore is under way.
fn save_stored_account(account: &str) {
    if let Some(window) = web_sys::window()
        && let Some(storage) = window.local_storage().ok().flatten()
    {
        let _ = storage.set_item(STORED_ACCOUNT_KEY, account);
    }
}

/// Drop the remembered account on logout, so the next load shows the sign-in screen.
fn clear_stored_account() {
    if let Some(window) = web_sys::window()
        && let Some(storage) = window.local_storage().ok().flatten()
    {
        let _ = storage.remove_item(STORED_ACCOUNT_KEY);
    }
}

/// A JS number as the whole seconds it names, `0` when it cannot round-trip
/// safely. `Date::now()` and server-sent timestamps are always non-negative
/// and well below `u64::MAX` in practice; this helper rejects every value that
/// could not round-trip, so a malformed broadcast never produces a false
/// far-future deadline.
fn f64_to_u64(v: f64) -> u64 {
    // u64::MAX as f64 rounds up to 2^64 (the nearest representable double above
    // u64::MAX), so values >= this bound saturate on `as u64` and must be
    // rejected.
    const MAX: f64 = u64::MAX as f64;
    if v.is_finite() && (0.0..MAX).contains(&v) {
        v as u64 // deliberate truncation: fractional part discarded
    } else {
        0
    }
}

/// Ask the worker for the expiry warning, skipping the update if a newer
/// session arrived meanwhile.
async fn poll_expiry_warn(
    secs: u64,
    session_expires_at: Signal<Option<u64>>,
    mut expiry_warn: Signal<Option<String>>,
) {
    let expires_at = SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
    let pending = connetto_web::auth::request_unsynced().await;
    if *session_expires_at.read() != Some(secs) {
        return;
    }
    let Ok(pending) = pending else {
        expiry_warn.set(None);
        return;
    };
    let now_f64 = js_sys::Date::now();
    // Deliberate truncation: sub-millisecond time discarded.
    debug_assert!(
        now_f64.is_finite() && now_f64 >= 0.0,
        "Date::now() must be finite"
    );
    let now = SystemTime::UNIX_EPOCH + Duration::from_millis(f64_to_u64(now_f64));
    let warning = expiry_warning(
        now,
        expires_at,
        EXPIRY_LEAD,
        pending.unsynced,
        pending.content_files,
    );
    expiry_warn.set(warning.as_ref().map(format_expiry_line));
}

/// The session expiry warning line shown in the header.
fn format_expiry_line(warn: &ExpiryWarning) -> String {
    let n = warn.pending_count();
    let secs = warn
        .session_expires_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let now_f64 = js_sys::Date::now();
    // Deliberate truncation: sub-second time discarded.
    debug_assert!(
        now_f64.is_finite() && now_f64 >= 0.0,
        "Date::now() must be finite"
    );
    let now_secs = f64_to_u64(now_f64 / 1000.0);
    let days = secs.saturating_sub(now_secs) / 86400;
    format!("Session lapses in {days} day(s). {n} local item(s) at risk. Connect to refresh.")
}

/// Whether the passkey gate can be enrolled here and the header's custody line.
fn custody_description(snap: Option<Custody>) -> (bool, Option<String>) {
    let offerable = matches!(snap, Some(Custody::Unverified(NoGate::Offerable)));
    let text = snap.as_ref().map(|c| match c {
        Custody::Verified => "gate: verified by passkey".to_owned(),
        Custody::Unverified(NoGate::Offerable) => {
            "gate: not verified (passkey available)".to_owned()
        }
        Custody::Unverified(NoGate::Declined) => "gate: not verified (passkey declined)".to_owned(),
        Custody::Unverified(NoGate::Unsupported) => {
            "gate: not verified (passkey not available on this device)".to_owned()
        }
        Custody::Ephemeral => "gate: no persistent key (anonymous session)".to_owned(),
    });
    (offerable, text)
}

/// Export this device's local data through the worker and offer the archive
/// as a download, answering with the line the pane shows.
pub async fn export_data() -> String {
    match workers::request_export(ExportScope::Everything).await {
        Ok(blob) => {
            let size = blob.size();
            match download_blob(EXPORT_FILE_NAME, &blob) {
                Ok(()) => format!("{size} bytes offered as {EXPORT_FILE_NAME}"),
                Err(err) => format!("download refused: {err:?}"),
            }
        }
        Err(err) => format!("export failed: {err}"),
    }
}

/// Restore one archive through the worker, keeping the file's version of
/// every clash, and answer with the line the pane shows.
pub async fn import_data(blob: &web_sys::Blob) -> String {
    match workers::request_import(blob.clone()).await {
        Ok((outcome, clashes)) => {
            let mut msg = format!(
                "{} row(s) restored, {} kept, {} write(s) restored",
                outcome.rows_restored, outcome.rows_kept, outcome.writes_restored
            );
            if clashes > 0 {
                msg.push_str(&format!(" ({clashes} clash(es) resolved to file)"));
            }
            msg
        }
        Err(err) => format!("refused: {err}"),
    }
}

/// The platform's one app-level operation, the header's sign-in and unlock
/// affordances and the account bar's switch, add, enrol and logout buttons,
/// each reaching the worker through it.
#[derive(Clone)]
pub struct Ops {
    user_id: Signal<Option<String>>,
    live_account: Signal<Option<String>>,
    enrol_offerable: Signal<bool>,
    gate_line: Signal<Option<String>>,
    custody_line: Signal<Option<String>>,
    enrol_msg: Signal<Option<String>>,
    logout_state: Signal<LogoutState>,
    login_prompt: Signal<Option<String>>,
    sign_in_ready: Signal<bool>,
    held: Rc<RefCell<Option<Boot>>>,
}

impl Ops {
    /// The boot this window attached through, or `None` while it lands.
    fn boot(&self) -> Option<Rc<Membership>> {
        let held = self.held.borrow();
        held.as_ref().map(|boot| Rc::clone(&boot.membership))
    }

    /// The logout standing the account bar renders.
    pub fn logout_state(&self) -> Signal<LogoutState> {
        self.logout_state
    }

    /// Log out, keeping the local data. The worker drops the credential, and
    /// the replica and its key stay, so a returning user resumes from the
    /// persisted cursor.
    pub async fn logout_keep(&self) {
        let mut state = self.logout_state;
        state.set(LogoutState::Working);
        match connetto_web::auth::request_logout(false, false).await {
            Ok(_) => reload_page(),
            Err(err) => state.set(LogoutState::Error(err.to_string())),
        }
    }

    /// Delete the local data and log out, asking for confirmation while
    /// local work is still unsent.
    pub async fn logout_delete(&self) {
        let mut state = self.logout_state;
        state.set(LogoutState::Working);
        match connetto_web::auth::request_unsynced().await {
            Ok(pending) if pending.is_empty() => {
                match connetto_web::auth::request_logout(true, false).await {
                    Ok(_) => reload_page(),
                    Err(err) => state.set(LogoutState::Error(err.to_string())),
                }
            }
            Ok(pending) => state.set(LogoutState::ConfirmDelete {
                unsynced_count: pending.len(),
            }),
            Err(err) => state.set(LogoutState::Error(err.to_string())),
        }
    }

    /// The confirmed delete, discarding the unsent work.
    pub async fn logout_delete_confirmed(&self) {
        let mut state = self.logout_state;
        state.set(LogoutState::Working);
        match connetto_web::auth::request_logout(true, true).await {
            Ok(_) => reload_page(),
            Err(err) => state.set(LogoutState::Error(err.to_string())),
        }
    }

    /// Drop the standing logout confirmation or error.
    pub async fn dismiss(&self) {
        let mut state = self.logout_state;
        state.set(LogoutState::Idle);
    }

    /// Sign the page back in as another stored account, through the worker.
    /// The page clears its session fields while the replacement worker
    /// re-acquires them and broadcasts the new ones.
    pub async fn switch_account(&self, key: &str) {
        let mut user_id = self.user_id;
        let mut live_account = self.live_account;
        user_id.set(None);
        live_account.set(None);
        let Some(membership) = self.boot() else {
            return;
        };
        if let Err(err) = membership.switch_account(key) {
            tracing::warn!(error = %err, "asking the worker to switch accounts");
        }
    }

    /// Ask the worker to open a fresh sign-in for a new account.
    pub async fn add_account(&self) {
        let Some(membership) = self.boot() else {
            return;
        };
        if let Err(err) = membership.add_account() {
            tracing::warn!(error = %err, "asking the worker to add an account");
        }
    }

    /// Run the passkey gate enrolment ceremony in this window. The ceremony
    /// runs for as long as the user takes to present a finger, so the
    /// membership handle is cloned out and the borrow released before the
    /// await.
    pub async fn enrol_gate(&self) {
        let mut enrol_offerable = self.enrol_offerable;
        let mut gate_line = self.gate_line;
        let mut custody_line = self.custody_line;
        let mut enrol_msg = self.enrol_msg;
        let Some(membership) = self.boot() else {
            return;
        };
        match membership.enrol_gate().await {
            Ok(true) => {
                if let Ok(level) = workers::request_custody().await {
                    let (offerable, gate) = custody_description(Some(level));
                    let custody = format!("custody: {level}");
                    enrol_offerable.set(offerable);
                    gate_line.set(gate);
                    custody_line.set(Some(custody));
                }
            }
            Ok(false) => {
                enrol_msg.set(Some(
                    "the passkey gate can only be set up in the window that owns the database"
                        .to_owned(),
                ));
            }
            Err(err) => enrol_msg.set(Some(format!("enrolment failed: {err}"))),
        }
    }

    /// The stored-secrets gate is the worker's to hold, and a web build never
    /// locks it, so the header's unlock affordance never offers here.
    pub async fn unlock(&self) {}

    /// Open the parked login URL in a popup, or no-op when none is parked yet.
    pub async fn sign_in(&self) {
        let mut login_prompt = self.login_prompt;
        let Some(url) = login_prompt.read().clone() else {
            return;
        };
        open_login_popup(&url);
        login_prompt.set(None);
        let mut sign_in_ready = self.sign_in_ready;
        sign_in_ready.set(false);
    }
}

/// The browser app: boots the tab, wires the channels and provides the
/// contexts every pane reads.
#[component]
pub fn App() -> Element {
    // Read ?code=...&state=... from the URL once, then clear it so a reload
    // does not attempt to redeem a spent authorization code.
    let pending = page_login_callback();
    if pending.is_some() {
        clear_url_query();
    }

    let mut client_slot: Signal<Option<Client>> = use_signal(|| None);
    let mut status: Signal<String> = use_signal(|| "connecting to the connetto stack".to_owned());
    let mut user_id: Signal<Option<String>> = use_signal(|| None);
    let mut login_prompt: Signal<Option<String>> = use_signal(|| None);
    let mut sign_in_ready: Signal<bool> = use_signal(|| false);
    let mut live_account: Signal<Option<String>> = use_signal(|| None);
    let mut stored_account: Signal<Option<String>> = use_signal(read_stored_account);
    let mut session_expires_at: Signal<Option<u64>> = use_signal(|| None);
    let mut all_accounts: Signal<Vec<String>> = use_signal(Vec::new);
    let accounts: Signal<Vec<(String, String, bool)>> = use_signal(Vec::new);
    let mut picker_active: Signal<bool> = use_signal(|| false);
    let mut account_answer: Signal<Option<AccountChoice>> = use_signal(|| None);
    let mut content_slot: Signal<Option<DemoContent>> = use_signal(|| None);
    let expiry_warn: Signal<Option<String>> = use_signal(|| None);
    let mut footprint: Signal<(i64, i64)> = use_signal(|| (0_i64, 0_i64));
    let mut enrol_offerable: Signal<bool> = use_signal(|| false);
    let mut custody_line: Signal<Option<String>> = use_signal(|| None);
    let enrol_msg: Signal<Option<String>> = use_signal(|| None);
    let mut gate_line: Signal<Option<String>> = use_signal(|| None);
    let device_line: Signal<String> = use_signal(|| "no device identity in this build".to_owned());
    let logout_state: Signal<LogoutState> = use_signal(|| LogoutState::Idle);
    let gate: Signal<&'static str> = use_signal(|| "open");
    let clock: Signal<Option<&'static str>> = use_signal(|| None);

    use_context_provider(|| Status(status));
    use_context_provider(|| UserId(user_id));
    use_context_provider(|| AccountKey(live_account));
    use_context_provider(|| Accounts(accounts));
    use_context_provider(|| PickerActive(picker_active));
    use_context_provider(|| AccountAnswer(account_answer));
    use_context_provider(|| CustodyLine(custody_line));
    use_context_provider(|| GateLine(gate_line));
    use_context_provider(|| DeviceLine(device_line));
    use_context_provider(|| ExpiryWarn(expiry_warn));
    use_context_provider(|| ClientSlot(client_slot));
    use_context_provider(|| ContentSlot(content_slot));
    use_context_provider(|| Footprint(footprint));
    use_context_provider(|| EnrolAvailable(enrol_offerable));
    use_context_provider(|| EnrolMsg(enrol_msg));
    use_context_provider(|| Gate(gate));
    use_context_provider(|| Clock(clock));
    use_context_provider(|| SignInReady(sign_in_ready));

    // The account bar's list of every stored account as key, decoded label
    // and signed in right now, refreshed as the worker's list or the live
    // account moves.
    {
        let mut accounts_signal = accounts;
        use_effect(move || {
            let known = all_accounts.read().clone();
            let current = live_account.read().clone();
            accounts_signal.set(
                known
                    .iter()
                    .map(|key| {
                        (
                            key.clone(),
                            crate::account_label(key),
                            current.as_deref() == Some(key.as_str()),
                        )
                    })
                    .collect(),
            );
        });
    }

    // Register the account chooser before the worker boots. For a single
    // stored credential the chooser returns immediately; for several it parks
    // the list in the picker and polls for the button click.
    use_hook(|| {
        serve_account_choice(move |accounts| async move {
            all_accounts.set(accounts.clone());
            if accounts.len() <= 1 {
                return AccountChoice::LastUsed;
            }
            picker_active.set(true);
            loop {
                let choice = account_answer.read().clone();
                if let Some(choice) = choice {
                    picker_active.set(false);
                    account_answer.set(None);
                    return choice;
                }
                workers::sleep(Duration::from_millis(50)).await;
            }
        });
    });

    // Respond to the worker's provider query. The worker sends "provider?" on
    // DEMO_PROVIDER_CHANNEL at each boot, and this page always replies with
    // the one provider the dev stack registers.
    let _provider_listener = use_hook(move || {
        Rc::new(RefCell::new({
            let ch = BroadcastChannel::new(DEMO_PROVIDER_CHANNEL).expect("provider channel");
            let resp = ch.clone();
            let on_msg = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
                if e.data().as_string().as_deref() == Some("provider?") {
                    let _ = resp.post_message(&JsValue::from_str(AUTH_PROVIDER));
                }
            });
            ch.set_onmessage(Some(on_msg.as_ref().unchecked_ref()));
            (ch, on_msg)
        }))
    });

    // Listen for the session fields the worker broadcasts after its boot.
    // uid, account key and session_expires_at ride one JS object, so a single
    // listener wires every signal.
    let _uid_listener = use_hook(move || {
        Rc::new(RefCell::new({
            let ch = BroadcastChannel::new(DEMO_UID_CHANNEL).expect("uid channel");
            let on_msg = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
                let data = e.data();
                if let Some(uid) = js_sys::Reflect::get(&data, &JsValue::from_str("uid"))
                    .ok()
                    .and_then(|v| v.as_string())
                {
                    user_id.set(Some(uid));
                }
                let account = js_sys::Reflect::get(&data, &JsValue::from_str("account"))
                    .ok()
                    .and_then(|v| v.as_string());
                if let Some(account) = account {
                    save_stored_account(&account);
                    stored_account.set(Some(account.clone()));
                    live_account.set(Some(account));
                } else {
                    live_account.set(None);
                }
                session_expires_at.set(
                    js_sys::Reflect::get(&data, &JsValue::from_str("session_expires_at"))
                        .ok()
                        .and_then(|v| v.as_f64())
                        .map(|f| {
                            debug_assert!(
                                f.is_finite() && f >= 0.0,
                                "session_expires_at from broadcast must be finite"
                            );
                            f64_to_u64(f)
                        }),
                );
            });
            ch.set_onmessage(Some(on_msg.as_ref().unchecked_ref()));
            (ch, on_msg)
        }))
    });

    // Listen on the login channel. When the worker broadcasts its login URL:
    //   - If this page load is the OAuth callback, deliver the code and state
    //     to the worker.
    //   - Otherwise park the URL so a button can offer it. A popup opened
    //     from this handler would be blocked, because a message is not user
    //     activation.
    let _login_listener = use_hook(move || {
        Rc::new(RefCell::new({
            let login_ch =
                BroadcastChannel::new(connetto_web::LOGIN_CHANNEL).expect("login channel");
            let on_msg = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
                let Some(text) = e.data().as_string() else {
                    return;
                };
                // Parse LoginMessage::Request via js_sys::JSON to avoid a
                // serde dependency in the page.
                let val = match js_sys::JSON::parse(&text) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let kind = js_sys::Reflect::get(&val, &JsValue::from_str("kind"))
                    .ok()
                    .and_then(|v| v.as_string());
                if kind.as_deref() != Some("request") {
                    return;
                }
                let Some(url) = js_sys::Reflect::get(&val, &JsValue::from_str("url"))
                    .ok()
                    .and_then(|v| v.as_string())
                else {
                    return;
                };
                if let Some((code, state)) = &pending {
                    // This page IS the callback: deliver the code to the worker.
                    let _ = deliver_login_code(code, state);
                } else {
                    login_prompt.set(Some(url));
                    sign_in_ready.set(true);
                }
            });
            login_ch.set_onmessage(Some(on_msg.as_ref().unchecked_ref()));
            (login_ch, on_msg)
        }))
    });

    let raw_boot_hold: Rc<RefCell<Option<Boot>>> = use_hook(|| Rc::new(RefCell::new(None)));
    let ops = Ops {
        user_id,
        live_account,
        enrol_offerable,
        gate_line,
        custody_line,
        enrol_msg,
        logout_state,
        login_prompt,
        sign_in_ready,
        held: raw_boot_hold.clone(),
    };
    use_context_provider(|| ops);

    use_hook(move || {
        let boot_inner = raw_boot_hold.clone();
        spawn(async move {
            match boot_window().await {
                Ok(boot) => {
                    // Fetch the custody level now that the worker has settled.
                    if let Ok(level) = workers::request_custody().await {
                        let (offerable, gate) = custody_description(Some(level));
                        enrol_offerable.set(offerable);
                        gate_line.set(gate);
                        custody_line.set(Some(format!("custody: {level}")));
                    }
                    content_slot.set(Some(DemoContent::new(Rc::clone(&boot.content))));
                    let mut events = boot.client.events();
                    client_slot.set(Some(boot.client.clone()));
                    status.set("connected".to_owned());
                    *boot_inner.borrow_mut() = Some(boot);
                    while let Ok(event) = events.recv().await {
                        if let Some(label) = crate::status_label(&event) {
                            status.set(label);
                        }
                        // The stop names its cause, and the `Closed` that
                        // follows it would only replace that.
                        if matches!(event, ClientEvent::Stopped { .. }) {
                            break;
                        }
                    }
                }
                Err(err) => status.set(format!("boot failed: {err:?}")),
            }
        });
    });

    // The session expiry warning and the replica footprint, polled on a slow
    // pace while the session is known.
    {
        use_hook(move || {
            spawn(async move {
                loop {
                    workers::sleep(Duration::from_secs(5)).await;
                    if let Some(secs) = *session_expires_at.read() {
                        poll_expiry_warn(secs, session_expires_at, expiry_warn).await;
                    }
                    if let Some(client) = client_slot.read().clone() {
                        footprint.set(crate::replica_footprint(&client).await);
                    }
                }
            })
        });
    }

    let ready = client_slot.read().is_some();
    let restoring = stored_account.read().is_some();
    rsx! {
        Page { ready: ready, restoring: restoring }
    }
}
