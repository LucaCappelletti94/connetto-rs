//! R90: a cross-site page cannot spend the refresh cookie.
//!
//! The suite's requests go to `http://localhost` on the auth port, a loopback-resolving
//! host name, while the test page is served from `http://127.0.0.1:PORT`. For
//! cookie scoping those are different sites, so every request here is genuinely
//! cross-site and the `SameSite=Strict` cookie the login set must never ride.
//! Proven headless-Chrome-only: the withholding is Chrome's cookie rule, and
//! `localhost` and `127.0.0.1` are one interface with two names.
//!
//! Two refusals. A marked refresh from this page cannot resume: the login
//! worked and set its cookie, and the silent refresh afterwards still ends at
//! `Acquired::NeedLogin`, because the browser withholds the cookie. And an
//! unmarked cross-site refresh, the form-post shape the latch exists for, never
//! reaches the service: no marker header means the native contract, and the
//! native contract needs a body token that a cross-site page cannot read.

#![cfg(target_arch = "wasm32")]

use connetto_web::auth::{AccountStore, Acquired, BrowserAuthenticator, WorkerAuthConfig};
use connetto_web::storage::ReplicaStorage;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{Request, RequestInit, Response, WorkerGlobalScope};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The auth stack under its cross-site name. Same process, same listener,
/// different site.
fn cross_base() -> String {
    let port = connetto_wasm_smoke::AUTH_BASE
        .strip_prefix("http://127.0.0.1:")
        .expect("the stack serves auth on 127.0.0.1");
    format!("http://localhost:{port}")
}

const PROVIDER: &str = "dev-idp";
const CROSS_DB: &str = "r90-cross-site.sqlite";

fn cross_config() -> WorkerAuthConfig {
    let base = cross_base();
    WorkerAuthConfig::new(&base, PROVIDER, format!("{base}/dev/landing"))
}

/// Walk the login as `subject` and return the code and state, over the
/// cross-site host so the whole chain lands cookies under `localhost`.
async fn walk_cross_login(login_url: &str, subject: &str) -> (String, String) {
    let global: WorkerGlobalScope = js_sys::global()
        .dyn_into()
        .expect("this test runs in a worker");
    let response: Response = JsFuture::from(global.fetch_with_str(login_url))
        .await
        .expect("the auth server must be running")
        .dyn_into()
        .expect("a fetch resolves to a Response");
    assert!(response.ok(), "the login form loaded cross-site");
    let form_url = response.url();
    let init = RequestInit::new();
    init.set_method("POST");
    init.set_body(&format!("username={subject}").into());
    let request = Request::new_with_str_and_init(&form_url, &init).expect("build form request");
    request
        .headers()
        .set("content-type", "application/x-www-form-urlencoded")
        .expect("set form content type");
    let response: Response = JsFuture::from(global.fetch_with_request(&request))
        .await
        .expect("submit the login form")
        .dyn_into()
        .expect("a fetch resolves to a Response");
    let final_url = response.url();
    let parsed = web_sys::Url::new(&final_url).expect("a parseable final url");
    let params = parsed.search_params();
    (
        params
            .get("code")
            .unwrap_or_else(|| panic!("no code in {final_url}")),
        params
            .get("state")
            .unwrap_or_else(|| panic!("no state in {final_url}")),
    )
}

/// A login through the cross-site host sets its cookie, and no marked refresh
/// from this page can spend it: `SameSite=Strict` withholds the cookie from
/// every cross-site request, so the resume asks for a login again.
#[wasm_bindgen_test]
async fn a_cross_site_page_never_carries_the_refresh_cookie() {
    let storage = ReplicaStorage::install().await;
    storage.delete_db(CROSS_DB).expect("clear an earlier index");
    let store = AccountStore::open(&storage.db_url(CROSS_DB)).expect("open the account index");

    let authenticator = BrowserAuthenticator::new(cross_config(), None);
    let pending = match authenticator
        .acquire::<String>(&store)
        .await
        .expect("acquire")
    {
        Acquired::NeedLogin(pending) => pending,
        Acquired::Access(_) => panic!("an empty index cannot refresh"),
    };
    let (code, state) = walk_cross_login(&pending.login_url, "cross-site-user").await;
    let session = authenticator
        .complete::<String>(&pending, &code, &state, &store)
        .await
        .expect("the login itself completes cross-site");
    let account = connetto_client::encode_identity(&session.user_id).expect("encode the account");

    // Same account, same marked contract, same browser: the only difference is
    // that the request is cross-site to its cookies, and that is enough.
    match BrowserAuthenticator::new(cross_config(), Some(account))
        .acquire::<String>(&store)
        .await
        .expect("a withheld cookie is a fall-through, not an error")
    {
        Acquired::NeedLogin(_) => {}
        Acquired::Access(resumed) => panic!(
            "a Strict cookie rode a cross-site request as {}",
            resumed.user_id
        ),
    }
}

/// The latch the RFC demands: an unmarked cross-site refresh, whose `Strict`
/// cookie the browser withholds, is treated as the native contract, and the
/// native contract without a body token is refused before any session is
/// touched.
#[wasm_bindgen_test]
async fn a_cookie_only_request_reaches_nothing() {
    let global: WorkerGlobalScope = js_sys::global()
        .dyn_into()
        .expect("this test runs in a worker");
    // Sent with `include`, the shape a cookie-carrying form post takes. The
    // browser still withholds the `Strict` cookie cross-site, so this proves
    // the unmarked cross-site refresh is refused. `mixed_contracts_are_400`
    // pins the same refusal natively with the cookie present.
    let init = RequestInit::new();
    init.set_method("POST");
    init.set_body(&r#"{"user_id":"someone"}"#.into());
    init.set_credentials(web_sys::RequestCredentials::Include);
    let request = Request::new_with_str_and_init(&format!("{}/auth/refresh", cross_base()), &init)
        .expect("request");
    request
        .headers()
        .set("content-type", "application/json")
        .expect("content type");
    let response: Response = JsFuture::from(global.fetch_with_request(&request))
        .await
        .expect("the auth server must be running")
        .dyn_into()
        .expect("a response");
    assert!(
        !response.ok(),
        "an unmarked request with a body id is refused, got {}",
        response.status()
    );
    let text = JsFuture::from(response.text().expect("body promise"))
        .await
        .expect("read body")
        .as_string()
        .expect("utf-8 body");
    assert!(
        !text.contains("access_token"),
        "the refusal mints nothing, got {text}"
    );
}
