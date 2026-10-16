//! The two-phone peer proof's phone-driving steps (R76), which read a host's
//! offer off its page and the page's own identity, and wait for the link's
//! end.

use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use tokio::time::{Instant, sleep};

use crate::inspector::PageSession;
use crate::peer_proof::{HotspotOfferLines, parse_offer_lines};

/// How long both pages get to drop their linked lines after a leave.
pub const LINK_END_BOUND: Duration = Duration::from_secs(120);

/// The offer a hosting phone shows, its lines read off the page, bounded.
///
/// # Errors
///
/// When the page does not show the whole offer within its bound, or does not
/// answer.
pub async fn read_hotspot_offer(app: &mut PageSession) -> Result<HotspotOfferLines> {
    app.wait_for_text("hotspot ssid: ", Duration::from_secs(45))
        .await
        .context("the host never showed its offer")?;
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let page = app.page_text().await?;
        if let Some(offer) = parse_offer_lines(&page) {
            return Ok(offer);
        }
        if Instant::now() >= deadline {
            bail!("the offer's lines never finished showing, the page shows:\n{page}");
        }
        sleep(Duration::from_millis(500)).await;
    }
}

/// The page's own peer identity, `account/key prefix`, from its listening
/// line, which the wait polls until the line carries it.
///
/// # Errors
///
/// When the page names no peer identity within its bound, or does not
/// answer.
pub async fn own_identity(app: &mut PageSession) -> Result<String> {
    // The peer panel updates the listening line on its own poll, which the
    // device label does not wait for, so the wait polls the line itself.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let page = app.page_text().await?;
        if let Some(identity) = page
            .lines()
            .find_map(|line| line.strip_prefix("peer: listening on "))
            .and_then(|rest| rest.split_once(" as "))
            .map(|(_, identity)| identity.trim().to_owned())
        {
            return Ok(identity);
        }
        if Instant::now() >= deadline {
            bail!("the page names no peer identity");
        }
        sleep(Duration::from_millis(500)).await;
    }
}

/// Wait for both pages to drop their linked lines, which the leave and stop
/// end the link.
///
/// # Errors
///
/// When a link line stays past [`LINK_END_BOUND`], or a page does not answer.
pub async fn wait_link_ends(app: &mut PageSession, peer_app: &mut PageSession) -> Result<()> {
    let deadline = Instant::now() + LINK_END_BOUND;
    loop {
        let host_page = app.page_text().await?;
        let peer_page = peer_app.page_text().await?;
        if !host_page.contains("linked: ") && !peer_page.contains("linked: ") {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("the link did not end after the phones left the hotspot");
        }
        sleep(Duration::from_secs(2)).await;
    }
}
