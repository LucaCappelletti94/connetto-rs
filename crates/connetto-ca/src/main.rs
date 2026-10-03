//! `connetto-ca`, run on the operator's offline machine.
//!
//! ```text
//! connetto-ca init <ca-dir> [--passphrase-file PATH]
//! connetto-ca issuer <ca-dir> <out-dir> [--passphrase-file PATH]
//! ```
//!
//! `init` creates the deployment's root in `<ca-dir>` and prints the
//! deployment UUID. `issuer` signs a new issuer with that root and writes the
//! certificate and plain key the server is given into `<out-dir>`. Without
//! `--passphrase-file` the passphrase is read from the terminal.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use zeroize::Zeroizing;

/// Why the command could not run.
#[derive(Debug, thiserror::Error)]
enum CommandError {
    /// The arguments do not name a ceremony.
    #[error("{0}")]
    Usage(&'static str),
    /// The passphrase could not be read.
    #[error("reading the passphrase")]
    Passphrase(#[source] std::io::Error),
    /// The two passphrases typed at `init` differ.
    #[error("the passphrases differ")]
    Mismatch,
    /// The ceremony failed.
    #[error(transparent)]
    Ca(#[from] connetto_ca::CaError),
}

const USAGE: &str = "usage: connetto-ca init <ca-dir> [--passphrase-file PATH]\n       connetto-ca issuer <ca-dir> <out-dir> [--passphrase-file PATH]";

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("connetto-ca: {err}");
            let mut source = std::error::Error::source(&err);
            while let Some(cause) = source {
                eprintln!("  caused by: {cause}");
                source = cause.source();
            }
            ExitCode::FAILURE
        }
    }
}

fn run(mut args: Vec<String>) -> Result<(), CommandError> {
    let passphrase_file = match args.iter().position(|arg| arg == "--passphrase-file") {
        Some(at) if at + 1 < args.len() => {
            let path = PathBuf::from(args.remove(at + 1));
            args.remove(at);
            Some(path)
        }
        Some(_) => return Err(CommandError::Usage(USAGE)),
        None => None,
    };
    match args.as_slice() {
        [command, ca_dir] if command == "init" => {
            let passphrase = passphrase(passphrase_file.as_deref(), true)?;
            let deployment = connetto_ca::init(Path::new(ca_dir), &passphrase, SystemTime::now())?;
            println!("{deployment}");
            Ok(())
        }
        [command, ca_dir, out_dir] if command == "issuer" => {
            let passphrase = passphrase(passphrase_file.as_deref(), false)?;
            connetto_ca::sign_issuer(
                Path::new(ca_dir),
                &passphrase,
                Path::new(out_dir),
                SystemTime::now(),
            )?;
            Ok(())
        }
        _ => Err(CommandError::Usage(USAGE)),
    }
}

/// The passphrase from `file`, else typed at the terminal, twice when `confirm`.
fn passphrase(file: Option<&Path>, confirm: bool) -> Result<Zeroizing<String>, CommandError> {
    if let Some(file) = file {
        let text = Zeroizing::new(std::fs::read_to_string(file).map_err(CommandError::Passphrase)?);
        return Ok(Zeroizing::new(
            text.trim_end_matches(['\n', '\r']).to_owned(),
        ));
    }
    let first = Zeroizing::new(
        rpassword::prompt_password("root key passphrase: ").map_err(CommandError::Passphrase)?,
    );
    if confirm {
        let second = Zeroizing::new(
            rpassword::prompt_password("again: ").map_err(CommandError::Passphrase)?,
        );
        if *first != *second {
            return Err(CommandError::Mismatch);
        }
    }
    Ok(first)
}
