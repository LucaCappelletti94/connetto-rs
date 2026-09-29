//! Postgres clusters started as plain processes, for machines that cannot run
//! Docker, such as a macOS runner driving an iOS simulator.

use std::ffi::OsString;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::{fs, io};

use tokio::process::Command;

use crate::stack::TempDir;

/// The variable naming the directory holding `pg_ctl`. With
/// [`POSTGRES_TEMPLATE_VAR`] it has every fixture run on a cluster of its own
/// in place of a container.
pub const POSTGRES_BIN_VAR: &str = "CONNETTO_POSTGRES_BIN";

/// The variable naming a stopped cluster made by `initdb -U postgres
/// --auth=trust`, which each fixture copies. A process in the iOS simulator
/// cannot run `initdb` itself, since the host's user lookup fails there, yet
/// it can start the server on a copy.
pub const POSTGRES_TEMPLATE_VAR: &str = "CONNETTO_POSTGRES_TEMPLATE";

/// Starts on a fresh port each, since another process can take a free port
/// between choosing it and the server binding it.
const ATTEMPTS: u32 = 3;

/// The programs and template [`POSTGRES_BIN_VAR`] and
/// [`POSTGRES_TEMPLATE_VAR`] name.
pub(crate) struct NativePrograms {
    pub(crate) bin: PathBuf,
    pub(crate) template: PathBuf,
}

impl NativePrograms {
    /// The programs `var` names, or `None` when it names neither.
    ///
    /// # Panics
    ///
    /// When `var` names one of the two without the other.
    pub(crate) fn from_lookup(var: impl Fn(&str) -> Option<OsString>) -> Option<Self> {
        match (var(POSTGRES_BIN_VAR), var(POSTGRES_TEMPLATE_VAR)) {
            (Some(bin), Some(template)) => Some(Self {
                bin: bin.into(),
                template: template.into(),
            }),
            (None, None) => None,
            _ => panic!("{POSTGRES_BIN_VAR} and {POSTGRES_TEMPLATE_VAR} go together"),
        }
    }
}

/// A cluster in a directory of its own, stopped on drop before the directory
/// goes.
pub(crate) struct NativeCluster {
    pg_ctl: PathBuf,
    data: PathBuf,
    port: u16,
    /// Removed after [`Drop`] stopped the server in it.
    _dir: TempDir,
}

impl NativeCluster {
    /// Copy `template` and start a server on the copy with the `pg_ctl` in
    /// `bin`, with `wal_level=logical` and `fsync=off` as the container runs.
    ///
    /// # Panics
    ///
    /// Panics when the copy fails or the server does not start on any of
    /// [`ATTEMPTS`] ports, printing the server's log, all setup failures.
    pub(crate) async fn start(bin: &Path, template: &Path) -> Self {
        let dir = TempDir::create("connetto-postgres")
            .await
            .expect("a directory for the cluster");
        let from = template.to_owned();
        let data = dir.path.join("data");
        let data = tokio::task::spawn_blocking(move || copy_tree(&from, &data).map(|()| data))
            .await
            .expect("the copy task")
            .unwrap_or_else(|err| {
                panic!("copying the template cluster {}: {err}", template.display())
            });
        let pg_ctl = bin.join("pg_ctl");
        let log = dir.path.join("postgres.log");
        for attempt in 1..=ATTEMPTS {
            let port = free_port();
            // No Unix socket: a simulator's temporary directory is longer than
            // a socket path may be, and every client connects over TCP.
            let options = format!(
                "-c wal_level=logical -c fsync=off -c port={port} \
                 -c listen_addresses=127.0.0.1 -c unix_socket_directories=''"
            );
            let status = Command::new(&pg_ctl)
                .arg("-D")
                .arg(&data)
                .arg("-l")
                .arg(&log)
                .args(["-w", "-o", &options, "start"])
                .stdout(Stdio::null())
                .status()
                .await
                .unwrap_or_else(|err| panic!("starting {}: {err}", pg_ctl.display()));
            if status.success() {
                return Self {
                    pg_ctl,
                    data,
                    port,
                    _dir: dir,
                };
            }
            assert!(
                attempt < ATTEMPTS,
                "postgres did not start on {ATTEMPTS} ports: {}",
                std::fs::read_to_string(&log).unwrap_or_default()
            );
        }
        unreachable!("the last attempt returns or panics")
    }

    /// The superuser conninfo, which trust authentication admits.
    pub(crate) fn admin_url(&self) -> String {
        format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            self.port
        )
    }
}

impl Drop for NativeCluster {
    fn drop(&mut self) {
        let _ = std::process::Command::new(&self.pg_ctl)
            .arg("-D")
            .arg(&self.data)
            .args(["-m", "immediate", "stop"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// A port the loopback interface has free right now.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a free loopback port")
        .port()
}

/// Copy the directory `from` to `to` with every file's and directory's mode,
/// since the server refuses a data directory more open than 0700.
fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir(to)?;
    fs::set_permissions(to, fs::metadata(from)?.permissions())?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use diesel::QueryDsl as _;
    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl as _;

    use super::{NativePrograms, POSTGRES_BIN_VAR, POSTGRES_TEMPLATE_VAR};
    use crate::Fixture;
    use crate::stack::TempDir;
    use crate::watermark::_connetto_mutations;

    /// The newest server programs of the Debian and Ubuntu layout, which the
    /// CI runners ship.
    fn postgres_bin() -> PathBuf {
        std::fs::read_dir("/usr/lib/postgresql")
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path().join("bin"))
            .filter(|bin| bin.join("pg_ctl").exists())
            .max()
            .expect("no /usr/lib/postgresql/*/bin/pg_ctl, install the PostgreSQL server")
    }

    fn lookup(set: &[&str]) -> impl Fn(&str) -> Option<OsString> {
        let set: Vec<String> = set.iter().map(|name| (*name).to_owned()).collect();
        move |name| {
            set.iter()
                .any(|set| set == name)
                .then(|| format!("/{name}").into())
        }
    }

    #[test]
    fn both_variables_name_the_programs_and_neither_leaves_the_containers() {
        let programs =
            NativePrograms::from_lookup(lookup(&[POSTGRES_BIN_VAR, POSTGRES_TEMPLATE_VAR]))
                .expect("both are set");
        assert_eq!(programs.bin, PathBuf::from(format!("/{POSTGRES_BIN_VAR}")));
        assert_eq!(
            programs.template,
            PathBuf::from(format!("/{POSTGRES_TEMPLATE_VAR}"))
        );
        assert!(NativePrograms::from_lookup(lookup(&[])).is_none());
    }

    #[test]
    #[should_panic(expected = "go together")]
    fn the_programs_without_a_template_are_refused() {
        NativePrograms::from_lookup(lookup(&[POSTGRES_BIN_VAR]));
    }

    #[test]
    #[should_panic(expected = "go together")]
    fn a_template_without_the_programs_is_refused() {
        NativePrograms::from_lookup(lookup(&[POSTGRES_TEMPLATE_VAR]));
    }

    #[tokio::test]
    async fn a_native_fixture_is_provisioned_on_a_copy_and_stopped_on_drop() {
        let bin = postgres_bin();
        let dir = TempDir::create("native-cluster-test").await.unwrap();
        let template = dir.path.join("template");
        let initdb = std::process::Command::new(bin.join("initdb"))
            .arg("-D")
            .arg(&template)
            .args(["-U", "postgres", "--auth=trust", "--no-sync"])
            .output()
            .unwrap();
        assert!(
            initdb.status.success(),
            "{}",
            String::from_utf8_lossy(&initdb.stderr)
        );
        let programs = NativePrograms {
            bin,
            template: template.clone(),
        };

        let fixture = Fixture::on_native(&programs, None, None).await;
        let port: u16 = fixture
            .admin_url()
            .rsplit_once(':')
            .and_then(|(_, rest)| rest.split_once('/'))
            .and_then(|(port, _)| port.parse().ok())
            .expect("the admin URL names a port");
        let mut conn = fixture.admin.get().await.unwrap();
        let wal_level: String =
            diesel::select(diesel::dsl::sql::<Text>("current_setting('wal_level')"))
                .get_result(&mut conn)
                .await
                .unwrap();
        assert_eq!(wal_level, "logical");
        let pending: i64 = _connetto_mutations::table
            .count()
            .get_result(&mut conn)
            .await
            .expect("the watermark table was provisioned");
        assert_eq!(pending, 0);
        assert!(
            template.join("postmaster.pid").metadata().is_err(),
            "the server ran on the template itself"
        );

        drop(conn);
        drop(fixture);
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    }
}
