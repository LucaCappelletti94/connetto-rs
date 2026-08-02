//! The stdout destination every native connetto program installs.
//!
//! Libraries emit through `tracing` and install nothing. A program calls
//! [`init_stdout`] once at startup, and every event emitted anywhere in its
//! process, this crate's consumers included, lands on stdout as one JSON
//! object per line.
//!
//! Browser programs have no stdout and install `connetto_web::logging`
//! instead. See `docs/architecture/08-authorization.md` under "Audit" for the
//! values an event carries.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

/// Level selection when `RUST_LOG` is unset.
const DEFAULT_FILTER: &str = "info";

/// Install the stdout destination for this process.
///
/// One JSON object per line, filtered by `RUST_LOG` and defaulting to `info`.
/// The enclosing span's values, which is where a connection puts its session
/// handle and the caller's identity, ride each line under `span`.
///
/// Calling this a second time leaves the first destination in place, so a
/// program with more than one entry path cannot lose its logging to a panic.
pub fn init_stdout() {
    init_stdout_with_default(DEFAULT_FILTER);
}

/// [`init_stdout`] with a different default for an unset `RUST_LOG`.
///
/// A program whose dependencies are chatty at `info` quiets them here rather
/// than losing its own events among theirs. `RUST_LOG` still overrides the
/// whole thing, so nothing is unreachable.
pub fn init_stdout_with_default(default_directives: &str) {
    let directives = std::env::var("RUST_LOG").unwrap_or_else(|_| default_directives.to_owned());
    install(std::io::stdout, &directives);
}

/// [`init_stdout`] against an arbitrary writer and filter, for a program
/// logging somewhere other than stdout.
///
/// `directives` takes `RUST_LOG` syntax.
pub fn install<W>(writer: W, directives: &str)
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let _ = tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(false)
        .with_writer(writer)
        .with_env_filter(EnvFilter::new(directives))
        .try_init();
}
