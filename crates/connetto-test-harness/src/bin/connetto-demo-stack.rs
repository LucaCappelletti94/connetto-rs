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
//! needs and the `adb reverse` lines that put every service on a phone's
//! loopback at the address the demo dials. Given a program, it runs that
//! program against the stack with `CONNETTO_DEMO_SERVER`, `CONNETTO_DEMO_PG`,
//! `CONNETTO_DEMO_ADB_REVERSE` (comma-separated `device:host` port pairs) and
//! `CONNETTO_DEMO_ISSUER` set, then stops.

use std::ffi::OsString;

use anyhow::{Context as _, Result, anyhow};
use connetto_test_harness::MockOauth;
use connetto_test_harness::stack::{
    Deployment, ensure_server_bin, provision, require_free, run_process, spawn_server,
};

const SYNC_BIND: &str = "127.0.0.1:7777";
/// The demo's `AUTH_SERVER`. The server's auth listener serves content too.
const AUTH_BIND: &str = "127.0.0.1:18081";
const AUTH_BASE: &str = "http://127.0.0.1:18081";
const CALLBACK: &str = "http://127.0.0.1:18081/auth/callback";
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
    require_free(SYNC_BIND)?;
    require_free(AUTH_BIND)?;

    let mut args = std::env::args_os().skip(1).collect::<Vec<OsString>>();
    if args.first().is_some_and(|arg| arg == "--") {
        args.remove(0);
    }

    let server_bin = ensure_server_bin().await?;
    let provisioned = provision(&DEPLOYMENT, "connetto-demo-stack").await?;
    let idp = MockOauth::start().await;
    let mut envs = provisioned.server_env(&DEPLOYMENT, SYNC_BIND, AUTH_BIND, AUTH_BASE);
    envs.extend(idp.env_pairs(PROVIDER, CALLBACK));
    envs.push((
        "CONNETTO_AUTH_REDIRECT_ALLOWLIST".to_owned(),
        APP_REDIRECT.to_owned(),
    ));
    let _server = spawn_server(&server_bin, &envs, SYNC_BIND, AUTH_BIND).await?;

    let pg_url = provisioned.fixture.admin_url();
    // Each pair is the device port, where the demo dials, then the host port.
    let reverse = [
        (url_port(SYNC_BIND)?, url_port(SYNC_BIND)?),
        (url_port(AUTH_BIND)?, url_port(AUTH_BIND)?),
        (url_port(idp.issuer())?, url_port(idp.issuer())?),
        (DEMO_PG_PORT, url_port(pg_url)?),
    ];
    let reverse_spec = reverse
        .iter()
        .map(|(device, host)| format!("{device}:{host}"))
        .collect::<Vec<_>>()
        .join(",");
    let demo_env = vec![
        ("CONNETTO_DEMO_SERVER".to_owned(), SYNC_BIND.to_owned()),
        ("CONNETTO_DEMO_PG".to_owned(), pg_url.to_owned()),
        ("CONNETTO_DEMO_ADB_REVERSE".to_owned(), reverse_spec),
        ("CONNETTO_DEMO_ISSUER".to_owned(), idp.issuer().to_owned()),
    ];

    if args.is_empty() {
        println!("connetto demo stack is up, Ctrl-C stops it");
        println!();
        println!("desktop:");
        for (key, value) in &demo_env[..2] {
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
