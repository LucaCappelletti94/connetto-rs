//! What the device proofs read from the demo's Postgres.

use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use diesel::QueryDsl as _;
use diesel_async::RunQueryDsl as _;
use tokio::time::{Instant, sleep};

use crate::pool_for;

diesel::table! {
    /// The demo's orders, as far as the proofs count them.
    orders (id) {
        /// Key.
        id -> diesel::sql_types::Uuid,
        /// Ordered amount.
        quantity -> diesel::sql_types::BigInt,
    }
}

/// How many orders Postgres holds.
///
/// # Errors
///
/// When Postgres cannot be reached or counted.
pub async fn order_count(pg_url: &str) -> Result<i64> {
    let pool = pool_for(pg_url).await;
    let mut conn = pool.get().await.context("a Postgres connection")?;
    orders::table
        .count()
        .get_result(&mut conn)
        .await
        .context("counting orders")
}

/// Wait up to a minute for Postgres to hold `expected` orders.
///
/// # Errors
///
/// When the count differs after a minute, naming it.
pub async fn wait_for_count(pg_url: &str, expected: i64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let count = order_count(pg_url).await?;
        if count == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("Postgres holds {count} orders, expected {expected}");
        }
        sleep(Duration::from_millis(500)).await;
    }
}
