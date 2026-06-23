//! `hermesd` — the Hermes daemon entry point (HERMES-L-S1).
//!
//! Reads `DISCORD_BOT_TOKEN` and `OWNER_DISCORD_ID` from the environment (the operator
//! sources the gitignored `.env.hermes` first), then runs the gateway adapter. Intended
//! to run under a hardened, unprivileged systemd unit (ADR-H6) — not as root.

use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .init();

    let token = env::var("DISCORD_BOT_TOKEN")
        .map_err(|_| anyhow::anyhow!("DISCORD_BOT_TOKEN not set — source .env.hermes first"))?;
    let owner = env::var("OWNER_DISCORD_ID").ok();

    hermes_discord::run(token, owner).await
}
