//! `hermes-discord` — the serenity gateway adapter + daemon for Hermes (HERMES-L-S1).
//!
//! Transport only. It connects to the Discord gateway, normalizes events into
//! [`hermes_core`] types, asks the guard what to do, and carries out the result. All
//! authorization and routing live in `hermes-core` (ADR-H3); this crate decides nothing.

pub mod classify;
pub mod handler;
pub mod preflight;

use hermes_core::guard::OwnerAuth;
use serenity::all::{Client, GatewayIntents, Http};

pub use handler::Handler;
pub use preflight::{preflight, PreflightError};

/// Run the Hermes daemon: preflight the config (fail-closed), resolve the bot's own id,
/// then connect to the gateway with least-privilege intents and dispatch events through
/// the guard. Returns only on shutdown or fatal gateway error.
pub async fn run(token: String, owner_id_cfg: Option<String>) -> anyhow::Result<()> {
    let auth = OwnerAuth::from_config(owner_id_cfg.as_deref());
    // WP-S1.2 doctor: do not accept traffic unless the security-critical config is valid.
    preflight(&token, &auth).map_err(|e| anyhow::anyhow!("preflight failed: {e}"))?;

    // Resolve our own id up front so self-events can be dropped (T17).
    let http = Http::new(&token);
    let me = http.get_current_user().await?;
    let bot_id = me.id.get();
    tracing::info!(bot = %me.name, bot_id, "preflight ok — owner configured, token valid");

    // Least-privilege intents for S1: read + members (for later onboarding). No
    // moderation/manage intents until the sprints that need them (ADR-H8).
    let intents = GatewayIntents::GUILDS
        | GatewayIntents::GUILD_MESSAGES
        | GatewayIntents::MESSAGE_CONTENT
        | GatewayIntents::GUILD_MEMBERS
        | GatewayIntents::DIRECT_MESSAGES;

    let mut client = Client::builder(&token, intents)
        .event_handler(Handler::new(auth, bot_id))
        .await?;

    tracing::info!("hermes daemon starting");
    client.start().await?;
    Ok(())
}
