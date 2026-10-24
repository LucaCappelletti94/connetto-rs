//! The build host that writes and checks the tier exports a history holds.
//!
//! `connetto-schema export-tier` translates the local tier exactly the way
//! the build translates it and writes the export for the schema source's
//! major into the history directory, so a build that runs over the same
//! sources finds its current export already there. `--check` writes nothing
//! and fails when the current export is missing or differs, which is the
//! CI gate that keeps a history fresh.

use std::path::PathBuf;
use std::process::ExitCode;

use connetto_schema::TextIds;

const USAGE: &str = "connetto-schema export-tier --schema <schema.sql> --tier <tier.sql> --dir <tier_history> [--check]";

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let Some(command) = args.first().map(std::string::String::as_str) else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };
    if command != "export-tier" {
        eprintln!("unknown command {command:?}\n{USAGE}");
        return ExitCode::FAILURE;
    }
    let mut schema = None;
    let mut tier = None;
    let mut dir = None;
    let mut check = false;
    let mut rest = args.iter().skip(1);
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--schema" => schema = rest.next().map(PathBuf::from),
            "--tier" => tier = rest.next().map(PathBuf::from),
            "--dir" => dir = rest.next().map(PathBuf::from),
            "--check" => check = true,
            other => {
                eprintln!("unknown argument {other:?}\n{USAGE}");
                return ExitCode::FAILURE;
            }
        }
    }
    let (Some(schema), Some(tier), Some(dir)) = (schema, tier, dir) else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };
    match connetto_schema::export_tier::<String, TextIds>(&schema, &tier, &dir, check) {
        Ok(outcome) => {
            if !check {
                println!("wrote {}", outcome.path.display());
            }
        }
        Err(err) => {
            eprintln!("connetto-schema: {err}");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
