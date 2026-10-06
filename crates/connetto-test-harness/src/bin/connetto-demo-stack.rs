//! Runs the dev stack `examples/dioxus-desktop-demo` signs in and syncs
//! against, which is Postgres, the authorization service, the dev identity
//! provider and `connetto-server`, provisioned with the demo's own deployment.
//!
//! ```text
//! cargo run -p connetto-test-harness --bin connetto-demo-stack
//! cargo run -p connetto-test-harness --bin connetto-demo-stack -- <program> [args]
//! ```
//!
//! Bare, it serves until interrupted and prints the environment a desktop run
//! or a web build needs and the `adb reverse` lines that put every service on
//! a phone's loopback at the address the demo dials. Given a program, it runs
//! that program against the stack with `CONNETTO_DEMO_SERVER`,
//! `CONNETTO_DEMO_AUTH_ORIGIN`, `CONNETTO_DEMO_WS`, `CONNETTO_DEMO_PG`,
//! `CONNETTO_DEMO_ADB_REVERSE` (comma-separated `device:host` port pairs) and
//! `CONNETTO_DEMO_ISSUER` set, then stops.
//!
//! It mints the demo's device certificate authority under
//! `target/demo-device-ca` on its first run, serves the issuer from it, and
//! names the root to the program as `CONNETTO_DEMO_BUILD_DEVICE_ROOT`, which a
//! demo build with the `device-identity` feature ships (R74 decision 30). With
//! `CONNETTO_IOS_TEAM_ID` set, the server accepts App Attest from the demo's
//! development builds under that team (R74 decision 32).
//!
//! `CONNETTO_STACK_SYNC_PORT` moves its listener off 7777.
//! `CONNETTO_STACK_PUBLIC_HOST` puts it on the LAN for a phone that has no
//! `adb reverse`, binding every interface and naming that host in every
//! address it hands out. With it, `CONNETTO_STACK_TLS_CERT` and
//! `CONNETTO_STACK_TLS_KEY` name a certificate for that host. The listener,
//! which carries the login callback and the file routes, is then served over
//! TLS in front of the server's plain one, and the identity provider serves
//! the same certificate itself.
//!
//! Where Docker cannot run, `CONNETTO_STACK_POSTGRES_URL`,
//! `CONNETTO_STACK_OPENFGA_URL` and `CONNETTO_STACK_ISSUER` together name a
//! running Postgres cluster with `wal_level=logical`, an authorization service
//! and a mock identity provider, which it uses in place of containers. That
//! identity provider cannot take the TLS certificate.

use std::ffi::OsString;

use anyhow::{Context as _, Result, anyhow, bail};
use connetto_test_harness::relay::Relay;
use connetto_test_harness::stack::{
    DemoDeviceCa, Deployment, PUBLIC_HOST_VAR, RunningServices, SYNC_PORT_VAR, TLS_CERT_VAR,
    TLS_KEY_VAR, demo_device_ca, ensure_server_bin, ports, provision, provision_enrolment_tables,
    require_free, run_process, spawn_server,
};
use connetto_test_harness::{MockOauth, with_host};

/// The port the demo dials unless told otherwise, which a phone keeps. The
/// server serves sync, login and files on it all.
const DEMO_SYNC_PORT: u16 = 7777;
const PROVIDER: &str = "dev-idp";
/// The port in the demo's default `CONNETTO_DEMO_PG`.
const DEMO_PG_PORT: u16 = 55456;
/// The demo's redirect on a phone, its bundle identifier as the scheme. The
/// server lists it by exact match, as RFC 8252 section 7.1 has an operator
/// register an app's scheme.
const APP_REDIRECT: &str = "dev.connetto.dioxusdemo:/oauth2redirect";
/// The demo's bundle identifier, the App ID App Attest names after the team.
const DEMO_BUNDLE: &str = "dev.connetto.dioxusdemo";

const DEPLOYMENT: Deployment = Deployment {
    schema: include_str!("../../../../examples/dioxus-desktop-demo/schema.sql"),
    roles: include_str!("../../../../examples/dioxus-desktop-demo/roles.sql"),
    content: include_str!("../../../../examples/dioxus-desktop-demo/content.sql"),
    policies: include_str!("../../../../examples/dioxus-desktop-demo/policies.sql"),
    published: &["orders", "order_lines", "photos"],
    writable: "orders,photos",
};

#[tokio::main]
async fn main() -> Result<()> {
    connetto_core::logging::init_stdout();
    let plan = Addresses::from_env()?;
    let Addresses {
        bind_port,
        public_host,
        tls,
        server_bind,
        public_bind,
        address,
        base,
    } = plan;

    let mut args = std::env::args_os().skip(1).collect::<Vec<OsString>>();
    if args.first().is_some_and(|arg| arg == "--") {
        args.remove(0);
    }

    let running = RunningServices::from_env()?;
    if running.is_some() && tls.is_some() {
        bail!("a running identity provider cannot serve {TLS_CERT_VAR}");
    }
    let server_bin = ensure_server_bin().await?;
    let provisioned = provision(&DEPLOYMENT, "connetto-demo-stack", running.as_ref()).await?;
    provision_enrolment_tables(&provisioned.fixture).await;
    let device_ca = demo_device_ca(std::time::SystemTime::now())?;
    let idp = identity_provider(running, public_host.as_deref(), tls.as_ref()).await?;
    let mut envs = provisioned.server_env(&DEPLOYMENT, &server_bind, &base);
    envs.extend(device_env(&device_ca));
    envs.extend(idp.env_pairs(PROVIDER, &format!("{base}/auth/callback")));
    envs.push((
        "CONNETTO_AUTH_REDIRECT_ALLOWLIST".to_owned(),
        APP_REDIRECT.to_owned(),
    ));
    let _server = spawn_server(&server_bin, &envs, &server_bind).await?;
    let _tls = match &tls {
        Some((cert, key)) => Some(
            Relay::start_tls(
                &public_bind,
                &server_bind,
                std::path::Path::new(cert),
                std::path::Path::new(key),
            )
            .await?,
        ),
        None => None,
    };

    let pg_url = public_host.as_deref().map_or_else(
        || provisioned.fixture.admin_url().to_owned(),
        |host| with_host(provisioned.fixture.admin_url(), host),
    );
    let reverse = device_reverse(bind_port, url_port(idp.issuer())?, url_port(&pg_url)?)?;
    let reverse_spec = reverse
        .iter()
        .map(|(device, host)| format!("{device}:{host}"))
        .collect::<Vec<_>>()
        .join(",");
    let demo_env = vec![
        ("CONNETTO_DEMO_SERVER".to_owned(), address.clone()),
        ("CONNETTO_DEMO_AUTH_ORIGIN".to_owned(), base),
        (
            "CONNETTO_DEMO_WS".to_owned(),
            demo_ws_url(&address, tls.as_ref()),
        ),
        ("CONNETTO_DEMO_PG".to_owned(), pg_url),
        ("CONNETTO_DEMO_ADB_REVERSE".to_owned(), reverse_spec),
        ("CONNETTO_DEMO_ISSUER".to_owned(), idp.issuer().to_owned()),
        (
            "CONNETTO_DEMO_BUILD_DEVICE_ROOT".to_owned(),
            device_ca.root.display().to_string(),
        ),
    ];

    if args.is_empty() {
        println!("connetto demo stack is up, Ctrl-C stops it");
        println!();
        println!("desktop and web builds:");
        for (key, value) in &demo_env[..4] {
            println!("  export {key}={value}");
        }
        println!();
        println!("a build with --features device-identity also needs:");
        let (key, value) = &demo_env[6];
        println!("  export {key}={value}");
        println!();
        println!("phone:");
        for (device, host) in reverse {
            println!("  adb reverse tcp:{device} tcp:{host}");
        }
        tokio::signal::ctrl_c()
            .await
            .context("waiting for Ctrl-C")?;
    } else {
        let program = args.remove(0);
        run_process(&program, &args, &demo_env).await?;
    }
    Ok(())
}

/// The server's device identity settings: the demo CA, and App Attest for
/// the demo's development builds when `CONNETTO_IOS_TEAM_ID` names the team.
fn device_env(device_ca: &DemoDeviceCa) -> Vec<(String, String)> {
    let mut envs = vec![
        (
            "CONNETTO_DEVICE_ROOT".to_owned(),
            device_ca.root.display().to_string(),
        ),
        (
            "CONNETTO_DEVICE_ISSUER_DIR".to_owned(),
            device_ca.issuer.display().to_string(),
        ),
    ];
    if let Ok(team) = std::env::var("CONNETTO_IOS_TEAM_ID") {
        envs.push((
            "CONNETTO_DEVICE_APP_ATTEST_APP_IDS".to_owned(),
            format!("{team}.{DEMO_BUNDLE}"),
        ));
        envs.push((
            "CONNETTO_DEVICE_APP_ATTEST_ENVIRONMENT".to_owned(),
            "development".to_owned(),
        ));
    }
    envs
}

/// The running provider `running` names, or else a container, advertised on
/// `public_host` and serving `tls` when given.
async fn identity_provider(
    running: Option<RunningServices>,
    public_host: Option<&str>,
    tls: Option<&(String, String)>,
) -> Result<MockOauth> {
    Ok(match (running, public_host, tls) {
        (Some(services), host, _) => {
            let idp = MockOauth::running(services.issuer);
            match host {
                Some(host) => idp.advertised_on(host),
                None => idp,
            }
        }
        (None, Some(host), Some((cert, key))) => {
            MockOauth::start_tls(host, pkcs12(cert, key).await?).await
        }
        (None, Some(host), None) => MockOauth::start().await.advertised_on(host),
        (None, None, _) => MockOauth::start().await,
    })
}

/// The PEM certificate chain and key at `cert` and `key` as PKCS #12 under
/// an empty password, the keystore the identity provider reads.
async fn pkcs12(cert: &str, key: &str) -> Result<Vec<u8>> {
    let output = tokio::process::Command::new("openssl")
        .args([
            "pkcs12", "-export", "-inkey", key, "-in", cert, "-passout", "pass:",
        ])
        .output()
        .await
        .context("starting openssl")?;
    if !output.status.success() {
        bail!(
            "packing {cert} for the identity provider failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

/// Where the stack listens and what it tells clients, from the environment.
struct Addresses {
    /// The port the demo dials and the listener answers on.
    bind_port: u16,
    public_host: Option<String>,
    tls: Option<(String, String)>,
    /// The address the server binds, on loopback behind a TLS relay when
    /// there is one.
    server_bind: String,
    /// The address clients reach, which a TLS relay owns when there is one.
    public_bind: String,
    /// The `host:port` a phone dials for sync.
    address: String,
    /// The base URL login and file routes answer on.
    base: String,
}

impl Addresses {
    fn from_env() -> Result<Self> {
        let [bind_port] = ports(
            |name| std::env::var(name).ok(),
            [(SYNC_PORT_VAR, DEMO_SYNC_PORT)],
        )?;
        let public_host = std::env::var(PUBLIC_HOST_VAR).ok();
        let host_present = public_host.is_some();
        let (bind_host, host) = match public_host.as_deref() {
            Some(host) => ("0.0.0.0".to_owned(), host.to_owned()),
            None => ("127.0.0.1".to_owned(), "127.0.0.1".to_owned()),
        };
        let tls = match (
            std::env::var(TLS_CERT_VAR).ok(),
            std::env::var(TLS_KEY_VAR).ok(),
        ) {
            (Some(cert), Some(key)) if host_present => Some((cert, key)),
            (None, None) => None,
            _ => bail!("{TLS_CERT_VAR} and {TLS_KEY_VAR} go together, with {PUBLIC_HOST_VAR}"),
        };
        let public_bind = format!("{bind_host}:{bind_port}");
        require_free(&public_bind, SYNC_PORT_VAR)?;
        let server_bind = if tls.is_some() {
            format!("127.0.0.1:{}", free_port()?)
        } else {
            public_bind.clone()
        };
        let scheme = if tls.is_some() { "https" } else { "http" };
        Ok(Self {
            bind_port,
            public_host,
            tls,
            server_bind,
            public_bind,
            address: format!("{host}:{bind_port}"),
            base: format!("{scheme}://{host}:{bind_port}"),
        })
    }
}

/// The `adb reverse` pairs, each the device port then the host port. The
/// demo dials the default port for sync, login and files, while the server
/// builds its login callback and other absolute URLs from the port it
/// binds, which a phone's browser follows, so a moved port is reversed at
/// its own number too.
///
/// # Errors
///
/// When a moved port is a device port the demo already dials, since one
/// device port cannot reach two listeners.
fn device_reverse(bind_port: u16, issuer_port: u16, pg_port: u16) -> Result<Vec<(u16, u16)>> {
    let mut pairs = vec![
        (DEMO_SYNC_PORT, bind_port),
        (issuer_port, issuer_port),
        (DEMO_PG_PORT, pg_port),
    ];
    if bind_port != DEMO_SYNC_PORT {
        if pairs.iter().any(|(device, _)| *device == bind_port) {
            bail!(
                "{SYNC_PORT_VAR}={bind_port} is a port the demo dials on a phone, move the listener elsewhere"
            );
        }
        pairs.push((bind_port, bind_port));
    }
    Ok(pairs)
}

fn free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").context("finding a free port")?;
    Ok(listener.local_addr()?.port())
}

/// The port in a `host:port` or a URL with an explicit port.
fn url_port(address: &str) -> Result<u16> {
    let rest = address.split_once("://").map_or(address, |(_, rest)| rest);
    let authority = rest.split('/').next().unwrap_or(rest);
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host_port)| host_port);
    host_port
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .ok_or_else(|| anyhow!("{address} names no port"))
}

/// The `CONNETTO_DEMO_WS` value, whose scheme follows the TLS relay that
/// fronts the listener.
fn demo_ws_url(address: &str, tls: Option<&(String, String)>) -> String {
    let scheme = if tls.is_some() { "wss" } else { "ws" };
    format!("{scheme}://{address}/sync")
}

#[cfg(test)]
mod tests {
    use super::{DEMO_PG_PORT, DEMO_SYNC_PORT, demo_ws_url, device_reverse};

    /// The server builds its login callback and every other absolute URL
    /// from the port it binds, and a phone's browser follows them. So a
    /// moved port is reachable on the device at its own number as well as
    /// at the one the demo dials.
    #[test]
    fn a_moved_bind_port_is_reachable_on_the_device_at_its_own_number() {
        let pairs = device_reverse(18181, 40000, 50000).expect("pairs");
        assert!(pairs.contains(&(DEMO_SYNC_PORT, 18181)), "{pairs:?}");
        assert!(pairs.contains(&(18181, 18181)), "{pairs:?}");
    }

    /// On the default port each device port is reversed once.
    #[test]
    fn default_port_reverses_each_device_port_once() {
        let pairs = device_reverse(DEMO_SYNC_PORT, 40000, DEMO_PG_PORT).expect("pairs");
        let mut devices = pairs.iter().map(|(device, _)| *device).collect::<Vec<_>>();
        devices.sort_unstable();
        devices.dedup();
        assert_eq!(devices.len(), pairs.len(), "{pairs:?}");
    }

    /// A phone cannot reach two listeners at one device port, so a listener
    /// port moved onto a port another service owns is refused.
    #[test]
    fn a_bind_port_on_a_port_the_demo_dials_is_refused() {
        for issuer in [40000, 50000] {
            let refused = device_reverse(issuer, issuer, 50000);
            assert!(refused.is_err(), "bind on {issuer}: {refused:?}");
        }
        let refused = device_reverse(55456, 40000, DEMO_PG_PORT);
        assert!(refused.is_err(), "bind on the pg port: {refused:?}");
    }

    /// The demo WebSocket address takes `wss` only when a TLS relay fronts
    /// the listener.
    #[test]
    fn the_demo_ws_url_takes_its_scheme_from_the_tls_relay() {
        assert_eq!(
            demo_ws_url("192.168.1.4:9443", None),
            "ws://192.168.1.4:9443/sync"
        );
        let pair = (String::new(), String::new());
        assert_eq!(
            demo_ws_url("192.168.1.4:9443", Some(&pair)),
            "wss://192.168.1.4:9443/sync"
        );
    }
}
