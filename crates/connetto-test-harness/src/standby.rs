//! A Postgres primary with a streaming standby, and a switchboard that moves one address between them (R73).
//!
//! Its own image because failover slots need a newer Postgres than the fixture pins, and labelled so the sweep reaps it.

use std::net::SocketAddr;
use std::process::Command as BlockingCommand;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::task::JoinHandle;

use crate::{STARTUP_TIMEOUT, container_labels, sweep_abandoned_containers, uuid_like};

/// The image the pair runs. Failover slots need 17 or later.
const IMAGE: &str = "postgres:18";

/// The physical slot the standby streams through, so the primary keeps the
/// log the standby has not received and slot synchronization can name it.
const STANDBY_SLOT: &str = "standby";

/// How often a wait asks again.
const POLL: Duration = Duration::from_millis(250);

/// Run `docker` and return what it printed.
///
/// # Panics
///
/// When `docker` cannot be run or reports a failure, which is a test setup
/// failure.
async fn docker(args: &[&str]) -> String {
    let output = Command::new("docker")
        .args(args)
        .output()
        .await
        .unwrap_or_else(|err| panic!("running docker {args:?}: {err}"));
    assert!(
        output.status.success(),
        "docker {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// The `--label` arguments one object carries.
fn label_args(role: &str) -> Vec<String> {
    container_labels(role)
        .into_iter()
        .flat_map(|(key, value)| ["--label".to_owned(), format!("{key}={value}")])
        .collect()
}

/// Run one statement in `container` and return its unaligned output.
///
/// Through `docker exec` rather than a pool, so it reaches a standby the test
/// has cut off from the network. These are replication-management and recovery
/// functions the diesel query DSL cannot express.
async fn sql(container: &str, statement: &str) -> String {
    docker(&[
        "exec", container, "psql", "-U", "postgres", "-Atc", statement,
    ])
    .await
}

/// Wait until `container` accepts TCP connections, which the temporary server
/// `initdb` runs never does.
async fn wait_accepting(container: &str) {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        let ready = Command::new("docker")
            .args([
                "exec",
                container,
                "pg_isready",
                "-h",
                "127.0.0.1",
                "-U",
                "postgres",
            ])
            .output()
            .await
            .is_ok_and(|output| output.status.success());
        if ready {
            return;
        }
        tokio::time::sleep(POLL).await;
    }
    panic!(
        "{container} did not accept connections within {STARTUP_TIMEOUT:?}: {}",
        docker(&["logs", "--tail", "30", container]).await
    );
}

/// Wait until `question` answers true in `container`.
async fn wait_until(container: &str, question: &str, what: &str) {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        if sql(container, question).await == "t" {
            return;
        }
        tokio::time::sleep(POLL).await;
    }
    panic!("{container} did not {what} within {STARTUP_TIMEOUT:?}");
}

/// Where the host reaches `container`'s Postgres.
async fn address(container: &str) -> SocketAddr {
    let mapped = docker(&["port", container, "5432/tcp"]).await;
    mapped
        .lines()
        .find_map(|line| line.parse().ok())
        .unwrap_or_else(|| panic!("{container} publishes no IPv4 port: {mapped}"))
}

/// A primary and its streaming standby.
pub struct Pair {
    network: String,
    primary: String,
    standby: String,
}

impl Pair {
    /// Start a primary with logical decoding on, then a standby built from it
    /// that streams through a physical slot and synchronizes failover slots.
    ///
    /// # Panics
    ///
    /// When Docker is unreachable or either server does not come up within
    /// the harness's startup timeout, which are test setup failures.
    pub async fn start() -> Self {
        sweep_abandoned_containers();
        let network = format!("connetto-standby-{}", uuid_like());
        let network_labels = label_args("network");
        let mut args = vec!["network", "create"];
        args.extend(network_labels.iter().map(String::as_str));
        args.push(&network);
        docker(&args).await;
        // Built before either container so that a panic from here on leaves
        // cleanup to `Drop`, which skips an id not yet assigned.
        let mut pair = Self {
            network,
            primary: String::new(),
            standby: String::new(),
        };

        let primary_name = format!("{}-primary", pair.network);
        let primary_labels = label_args("postgres-primary");
        let mut args = vec![
            "run",
            "-d",
            "--network",
            &pair.network,
            "--name",
            &primary_name,
            "-e",
            "POSTGRES_PASSWORD=postgres",
            "-p",
            "127.0.0.1::5432",
        ];
        args.extend(primary_labels.iter().map(String::as_str));
        args.extend([IMAGE, "-c", "wal_level=logical", "-c", "fsync=off"]);
        pair.primary = docker(&args).await;
        wait_accepting(&pair.primary).await;
        docker(&[
            "exec",
            &pair.primary,
            "bash",
            "-c",
            r#"echo "host replication all all scram-sha-256" >> "$PGDATA/pg_hba.conf""#,
        ])
        .await;
        sql(&pair.primary, "SELECT pg_reload_conf()").await;
        sql(
            &pair.primary,
            &format!("SELECT pg_create_physical_replication_slot('{STANDBY_SLOT}')"),
        )
        .await;

        let script = format!(
            "set -e\n\
             pg_basebackup -h {primary_name} -U postgres -D \"$PGDATA\" -R -X stream \
             -S {STANDBY_SLOT} -d 'dbname=postgres'\n\
             chmod 700 \"$PGDATA\"\n\
             exec postgres -c wal_level=logical -c hot_standby_feedback=on \
             -c sync_replication_slots=on -c primary_slot_name={STANDBY_SLOT}"
        );
        let standby_name = format!("{}-standby", pair.network);
        let standby_labels = label_args("postgres-standby");
        let mut args = vec![
            "run",
            "-d",
            "--network",
            &pair.network,
            "--name",
            &standby_name,
            "--user",
            "postgres",
            "-e",
            "PGPASSWORD=postgres",
            "-p",
            "127.0.0.1::5432",
            "--entrypoint",
            "bash",
        ];
        args.extend(standby_labels.iter().map(String::as_str));
        args.extend([IMAGE, "-c", &script]);
        pair.standby = docker(&args).await;
        wait_accepting(&pair.standby).await;
        pair
    }

    /// Where the host reaches the primary.
    pub async fn primary_address(&self) -> SocketAddr {
        address(&self.primary).await
    }

    /// Where the host reaches the standby.
    pub async fn standby_address(&self) -> SocketAddr {
        address(&self.standby).await
    }

    /// The primary's current write position, as Postgres prints it.
    pub async fn primary_position(&self) -> String {
        sql(&self.primary, "SELECT pg_current_wal_lsn()").await
    }

    /// Wait until the standby has replayed through `position`.
    ///
    /// # Panics
    ///
    /// When it has not within the harness's startup timeout.
    pub async fn wait_replayed(&self, position: &str) {
        let question = format!("SELECT pg_last_wal_replay_lsn() >= '{position}'::pg_lsn");
        wait_until(&self.standby, &question, "replay the primary's log").await;
    }

    /// Wait until the standby holds a synchronized copy of `slot` that a
    /// promotion would keep, which it makes only once the consumer on the
    /// primary has moved past the standby's catalog horizon.
    ///
    /// # Panics
    ///
    /// When it has not within the harness's startup timeout.
    pub async fn wait_slot_synced(&self, slot: &str) {
        let question = format!(
            "SELECT count(*) = 1 FROM pg_replication_slots \
             WHERE slot_name = '{slot}' AND synced AND NOT temporary"
        );
        wait_until(&self.standby, &question, "synchronize the failover slot").await;
    }

    /// Whether the standby's copy of `slot` came from synchronization, which a
    /// slot recreated by hand after a promotion never does.
    pub async fn slot_was_synced(&self, slot: &str) -> bool {
        let question =
            format!("SELECT synced FROM pg_replication_slots WHERE slot_name = '{slot}'");
        sql(&self.standby, &question).await == "t"
    }

    /// Cut the standby off, so what the primary writes next never reaches it.
    pub async fn partition_standby(&self) {
        docker(&["network", "disconnect", &self.network, &self.standby]).await;
    }

    /// Kill the primary without a shutdown, then reconnect the standby and
    /// promote it, so it becomes a primary on a new timeline holding only what
    /// it received before the partition.
    ///
    /// # Panics
    ///
    /// When the promotion does not complete, which is a test setup failure.
    pub async fn fail_over(&self) {
        docker(&["kill", &self.primary]).await;
        docker(&["network", "connect", &self.network, &self.standby]).await;
        assert_eq!(
            sql(&self.standby, "SELECT pg_promote(true, 60)").await,
            "t",
            "the standby must finish promoting"
        );
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        let containers = [self.primary.as_str(), self.standby.as_str()];
        let _ = BlockingCommand::new("docker")
            .args(["rm", "-f", "-v"])
            .args(containers.iter().filter(|id| !id.is_empty()))
            .output();
        let _ = BlockingCommand::new("docker")
            .args(["network", "rm", &self.network])
            .output();
    }
}

/// One local address whose connections are forwarded to a target the test
/// moves, standing in for the address a deployment repoints at a promoted
/// standby.
pub struct Switchboard {
    address: SocketAddr,
    target: Arc<Mutex<SocketAddr>>,
    flows: Arc<Mutex<Vec<JoinHandle<()>>>>,
    accept: JoinHandle<()>,
}

impl Switchboard {
    /// Listen locally and forward every connection to `target`.
    ///
    /// # Panics
    ///
    /// When no local port can be bound.
    pub async fn to(target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the switchboard");
        let address = listener.local_addr().expect("the switchboard's address");
        let target = Arc::new(Mutex::new(target));
        let flows: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
        let accept = {
            let (target, flows) = (Arc::clone(&target), Arc::clone(&flows));
            tokio::spawn(async move {
                while let Ok((mut inbound, _)) = listener.accept().await {
                    let to = *target.lock();
                    let flow = tokio::spawn(async move {
                        if let Ok(mut outbound) = TcpStream::connect(to).await {
                            let _ =
                                tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                        }
                    });
                    flows.lock().push(flow);
                }
            })
        };
        Self {
            address,
            target,
            flows,
            accept,
        }
    }

    /// The conninfo that reaches whichever server the switchboard points at.
    #[must_use]
    pub fn url(&self) -> String {
        format!("postgres://postgres:postgres@{}/postgres", self.address)
    }

    /// Send new connections to `target` and end every open one, the way moving
    /// an address to another host ends the flows the old host held.
    pub fn point_at(&self, target: SocketAddr) {
        *self.target.lock() = target;
        self.end_flows();
    }

    fn end_flows(&self) {
        for flow in self.flows.lock().drain(..) {
            flow.abort();
        }
    }
}

impl Drop for Switchboard {
    fn drop(&mut self) {
        self.accept.abort();
        self.end_flows();
    }
}
