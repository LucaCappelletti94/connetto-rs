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
//! `CONNETTO_STACK_SYNC_PORT` and `CONNETTO_STACK_AUTH_PORT` move its
//! listeners off 7777 and 18081.

use std::ffi::OsString;

use anyhow::{Context as _, Result, anyhow, bail};
use connetto_test_harness::MockOauth;
use connetto_test_harness::stack::{
    AUTH_PORT_VAR, Deployment, SYNC_PORT_VAR, ensure_server_bin, ports, provision, require_free,
    run_process, spawn_server,
};

/// The sync port the demo dials unless told otherwise, which a phone keeps.
const DEMO_SYNC_PORT: u16 = 7777;
/// The auth port of the demo's default `AUTH_SERVER`, which a phone keeps. The
/// server's auth listener serves content too.
const DEMO_AUTH_PORT: u16 = 18081;
const PROVIDER: &str = "dev-idp";
/// The port in the demo's default `CONNETTO_DEMO_PG`.
const DEMO_PG_PORT: u16 = 55456;
/// The demo's redirect on a phone, its bundle identifier as the scheme. The
/// server lists it by exact match, as RFC 8252 section 7.1 has an operator
/// register an app's scheme.
const APP_REDIRECT: &str = "dev.connetto.dioxusdemo:/oauth2redirect";

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
    let [sync_port, auth_port] = ports(
        |name| std::env::var(name).ok(),
        [
            (SYNC_PORT_VAR, DEMO_SYNC_PORT),
            (AUTH_PORT_VAR, DEMO_AUTH_PORT),
        ],
    )?;
    let sync_bind = format!("127.0.0.1:{sync_port}");
    let auth_bind = format!("127.0.0.1:{auth_port}");
    let auth_base = format!("http://{auth_bind}");
    require_free(&sync_bind, SYNC_PORT_VAR)?;
    require_free(&auth_bind, AUTH_PORT_VAR)?;

    let mut args = std::env::args_os().skip(1).collect::<Vec<OsString>>();
    if args.first().is_some_and(|arg| arg == "--") {
        args.remove(0);
    }

    let server_bin = ensure_server_bin().await?;
    let provisioned = provision(&DEPLOYMENT, "connetto-demo-stack").await?;
    let idp = MockOauth::start().await;
    let mut envs = provisioned.server_env(&DEPLOYMENT, &sync_bind, &auth_bind, &auth_base);
    envs.extend(idp.env_pairs(PROVIDER, &format!("{auth_base}/auth/callback")));
    envs.push((
        "CONNETTO_AUTH_REDIRECT_ALLOWLIST".to_owned(),
        APP_REDIRECT.to_owned(),
    ));
    let _server = spawn_server(&server_bin, &envs, &sync_bind, &auth_bind).await?;

    let pg_url = provisioned.fixture.admin_url();
    let reverse = device_reverse(
        sync_port,
        auth_port,
        url_port(idp.issuer())?,
        url_port(pg_url)?,
    )?;
    let reverse_spec = reverse
        .iter()
        .map(|(device, host)| format!("{device}:{host}"))
        .collect::<Vec<_>>()
        .join(",");
    let demo_env = vec![
        ("CONNETTO_DEMO_SERVER".to_owned(), sync_bind.clone()),
        ("CONNETTO_DEMO_AUTH_ORIGIN".to_owned(), auth_base),
        ("CONNETTO_DEMO_WS".to_owned(), format!("ws://{sync_bind}/")),
        ("CONNETTO_DEMO_PG".to_owned(), pg_url.to_owned()),
        ("CONNETTO_DEMO_ADB_REVERSE".to_owned(), reverse_spec),
        ("CONNETTO_DEMO_ISSUER".to_owned(), idp.issuer().to_owned()),
    ];

    if args.is_empty() {
        println!("connetto demo stack is up, Ctrl-C stops it");
        println!();
        println!("desktop and web builds:");
        for (key, value) in &demo_env[..4] {
            println!("  export {key}={value}");
        }
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

/// The `adb reverse` pairs, each the device port then the host port. The
/// demo dials the default ports, while the server builds its login callback
/// and other absolute URLs from the auth port it binds, which a phone's browser
/// follows, so a moved auth port is reversed at its own number too.
///
/// # Errors
///
/// When a moved auth port is a device port the demo already dials, since one
/// device port cannot reach two listeners.
fn device_reverse(
    sync_port: u16,
    auth_port: u16,
    issuer_port: u16,
    pg_port: u16,
) -> Result<Vec<(u16, u16)>> {
    let mut pairs = vec![
        (DEMO_SYNC_PORT, sync_port),
        (DEMO_AUTH_PORT, auth_port),
        (issuer_port, issuer_port),
        (DEMO_PG_PORT, pg_port),
    ];
    if auth_port != DEMO_AUTH_PORT {
        if pairs.iter().any(|(device, _)| *device == auth_port) {
            bail!(
                "{AUTH_PORT_VAR}={auth_port} is a port the demo dials on a phone, move the auth listener elsewhere"
            );
        }
        pairs.push((auth_port, auth_port));
    }
    Ok(pairs)
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

#[cfg(test)]
mod tests {
    use super::{DEMO_AUTH_PORT, DEMO_PG_PORT, DEMO_SYNC_PORT, device_reverse};

    /// The server builds its login callback and every other absolute URL from
    /// the auth port it binds, and a phone's browser follows them. So a moved
    /// auth port is reachable on the device at its own number as well as at
    /// the one the demo dials.
    #[test]
    fn a_moved_auth_port_is_reachable_on_the_device_at_its_own_number() {
        let pairs = device_reverse(17777, 18181, 40000, 50000).expect("pairs");
        assert!(pairs.contains(&(DEMO_AUTH_PORT, 18181)), "{pairs:?}");
        assert!(pairs.contains(&(18181, 18181)), "{pairs:?}");
    }

    /// On the default ports each device port is reversed once.
    #[test]
    fn default_ports_reverse_each_device_port_once() {
        let pairs =
            device_reverse(DEMO_SYNC_PORT, DEMO_AUTH_PORT, 40000, DEMO_PG_PORT).expect("pairs");
        let mut devices = pairs.iter().map(|(device, _)| *device).collect::<Vec<_>>();
        devices.sort_unstable();
        devices.dedup();
        assert_eq!(devices.len(), pairs.len(), "{pairs:?}");
    }

    /// A phone cannot reach two listeners at one device port, so an auth port
    /// moved onto a port the demo already dials is refused.
    #[test]
    fn an_auth_port_on_a_port_the_demo_dials_is_refused() {
        for dialed in [DEMO_SYNC_PORT, DEMO_PG_PORT, 40000] {
            let refused = device_reverse(17777, dialed, 40000, 50000);
            assert!(refused.is_err(), "auth on {dialed}: {refused:?}");
        }
    }
}
