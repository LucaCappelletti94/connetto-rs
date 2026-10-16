//! The parts of the Android and iOS two-phone peer proofs (R76) that run
//! without a phone, which are the offer's lines off a page's text, the run's
//! commit and its summary. The phone-driving steps live in
//! [`peer_devices`](crate::peer_devices).

use std::time::Duration;

use anyhow::Result;
use tokio::process::Command;

/// The offer a hosting phone shows, its lines read off the page.
pub struct HotspotOfferLines {
    /// The hotspot's ssid.
    pub ssid: String,
    /// The hotspot's passphrase.
    pub passphrase: String,
    /// The host's peer port.
    pub port: u16,
    /// The offer as one `WIFI:` payload, where the page shows it.
    pub payload: Option<String>,
}

/// The offer's lines off a page's text, all three present and the port a
/// number, or none while they are not.
pub fn parse_offer_lines(page: &str) -> Option<HotspotOfferLines> {
    let line = |label: &str| -> Option<String> {
        page.lines()
            .find_map(|line| line.strip_prefix(label).map(|rest| rest.trim().to_owned()))
    };
    let ssid = line("hotspot ssid: ")?;
    let passphrase = line("hotspot passphrase: ")?;
    let port = line("hotspot port: ")?;
    if port == "none" {
        return None;
    }
    Some(HotspotOfferLines {
        ssid,
        passphrase,
        port: port.parse::<u16>().ok()?,
        payload: line("hotspot payload: "),
    })
}

/// The commit the run built, marked `-dirty` over local changes, and
/// `unknown` where git does not answer.
pub async fn commit() -> String {
    let Ok(root) = crate::stack::repo_path(&[]) else {
        return "unknown".to_owned();
    };
    match Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["describe", "--always", "--dirty", "--abbrev=40"])
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        _ => "unknown".to_owned(),
    }
}

/// The run's summary: the commit, the single-phone proof, each join with
/// its time and, where it failed, why, and the restore after the joins
/// where it failed.
pub fn summary(
    commit: &str,
    (proof_took, proof): &(Duration, Result<(), String>),
    joins: Result<&[JoinReport], &anyhow::Error>,
    restore: Result<(), &anyhow::Error>,
) -> String {
    use std::fmt::Write as _;
    let line = |name: &str, took: Duration, outcome: Result<(), String>| match outcome {
        Ok(()) => format!("{name}: passed in {}s\n", took.as_secs()),
        Err(err) => format!("{name}: failed in {}s: {err}\n", took.as_secs()),
    };
    let mut text = format!("commit: {commit}\n");
    text += &line("single-phone proof", *proof_took, proof.clone());
    match joins {
        Ok(reports) => {
            for report in reports {
                let name = format!("{} join", report.name);
                match (report.took, &report.outcome) {
                    (Some(took), outcome) => {
                        text += &line(
                            &name,
                            took,
                            outcome.as_ref().map(drop).map_err(|err| format!("{err:#}")),
                        );
                    }
                    (None, Err(err)) => {
                        let _ = writeln!(text, "{name}: not run: {err:#}");
                    }
                    (None, Ok(())) => {
                        let _ = writeln!(text, "{name}: not run");
                    }
                }
            }
        }
        Err(err) => {
            let _ = writeln!(text, "joins: not run, the setup failed: {err:#}");
        }
    }
    if let Err(err) = restore {
        let _ = writeln!(text, "restore: failed: {err:#}");
    }
    text
}

/// One join's result, for the run's summary.
pub struct JoinReport {
    /// The join's name, as the summary and the evidence show it.
    pub name: &'static str,
    /// How long the join ran, or `None` for a join never started.
    pub took: Option<Duration>,
    /// How it ended.
    pub outcome: Result<()>,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{JoinReport, parse_offer_lines, summary};

    /// The summary lists the commit, the single-phone proof, and each join
    /// with its time and, where it failed, why.
    #[test]
    fn the_summary_names_every_step_and_why_a_join_failed() {
        let reports = [
            JoinReport {
                name: "form",
                took: Some(Duration::from_secs(201)),
                outcome: Ok(()),
            },
            JoinReport {
                name: "beacon",
                took: Some(Duration::from_secs(95)),
                outcome: Err(anyhow::anyhow!(
                    "the second phone never saw the first phone's beacon"
                )),
            },
            JoinReport {
                name: "payload",
                took: None,
                outcome: Err(anyhow::anyhow!("the beacon join's cleanup failed")),
            },
        ];
        assert_eq!(
            summary(
                "c0626b2",
                &(Duration::from_secs(180), Ok(())),
                Ok(&reports),
                Ok(())
            ),
            "commit: c0626b2\n\
             single-phone proof: passed in 180s\n\
             form join: passed in 201s\n\
             beacon join: failed in 95s: the second phone never saw the first phone's beacon\n\
             payload join: not run: the beacon join's cleanup failed\n"
        );
        let setup = anyhow::anyhow!("devicectl install exited with 1");
        assert_eq!(
            summary(
                "c0626b2",
                &(Duration::from_secs(180), Ok(())),
                Err(&setup),
                Ok(())
            ),
            "commit: c0626b2\n\
             single-phone proof: passed in 180s\n\
             joins: not run, the setup failed: devicectl install exited with 1\n"
        );
    }

    /// Joins that ran keep their lines when the run's own restore fails after
    /// them, and the restore's failure gets its own line.
    #[test]
    fn a_failed_restore_keeps_the_joins_that_ran() {
        let reports = [JoinReport {
            name: "form",
            took: Some(Duration::from_secs(201)),
            outcome: Ok(()),
        }];
        let restore = anyhow::anyhow!("the browser role did not return");
        assert_eq!(
            summary(
                "c0626b2",
                &(Duration::from_secs(180), Ok(())),
                Ok(&reports),
                Err(&restore)
            ),
            "commit: c0626b2\n\
             single-phone proof: passed in 180s\n\
             form join: passed in 201s\n\
             restore: failed: the browser role did not return\n"
        );
    }

    /// The offer's lines parse off a page's text, and an unfinished offer
    /// stays none.
    #[test]
    fn the_offer_lines_are_read_off_the_page() {
        let page = "\npeer: listening on 41234\n\
            hotspot ssid: iPhone di Luca\n\
            hotspot passphrase: s3cr3t pass\n\
            hotspot port: 41234\n\
            hotspot payload: WIFI:T:WPA;S:iPhone di Luca;P:s3cr3t pass;X:41234;;\n\
            hotspot: hosting\n";
        let offer = parse_offer_lines(page).expect("all three lines are there");
        assert_eq!(offer.ssid, "iPhone di Luca");
        assert_eq!(offer.passphrase, "s3cr3t pass");
        assert_eq!(offer.port, 41234);
        assert_eq!(
            offer.payload.as_deref(),
            Some("WIFI:T:WPA;S:iPhone di Luca;P:s3cr3t pass;X:41234;;")
        );
        assert!(parse_offer_lines("hotspot ssid: only\n").is_none());
        assert!(parse_offer_lines("hotspot port: none\n").is_none());
    }
}
