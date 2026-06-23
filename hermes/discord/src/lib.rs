//! `hermes-discord` — the serenity gateway adapter + daemon for Hermes (HERMES-L-S1).
//!
//! Transport only. It connects to the Discord gateway, normalizes events into
//! [`hermes_core`] types, asks the guard what to do, and carries out the result. All
//! authorization and routing live in `hermes-core` (ADR-H3); this crate decides nothing.

pub mod classify;
pub mod handler;
pub mod preflight;
pub mod sink;
pub mod store;

use std::sync::Arc;

use hermes_core::guard::OwnerAuth;
use hermes_core::memory::{restore_into, MemoryStore, NullMemoryStore};
use hermes_core::{AgendaStore, ApprovalQueue, RoomScope};
use hermes_llm::LlmClient;
use serenity::all::{Client, GatewayIntents, Http};
use tokio::sync::Mutex;

pub use handler::Handler;
pub use preflight::{preflight, PreflightError};
pub use sink::{FanoutDecisionSink, TracingDecisionSink, TracingTrail};
pub use store::JsonMemoryStore;

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

    // WP-S2.1 — local LLM for the command plane. A down model is a warning, not a fatal
    // error: the owner boundary must run regardless; commands just report the model is
    // unreachable until it's back.
    let llm = Arc::new(LlmClient::from_env());
    if llm.health().await {
        tracing::info!(endpoint = llm.endpoint(), model = llm.model(), "local LLM reachable");
    } else {
        tracing::warn!(endpoint = llm.endpoint(), "local LLM NOT reachable — owner commands will report an error until it's up");
    }

    // Least-privilege intents for S1: read + members (for later onboarding). No
    // moderation/manage intents until the sprints that need them (ADR-H8).
    let intents = GatewayIntents::GUILDS
        | GatewayIntents::GUILD_MESSAGES
        | GatewayIntents::MESSAGE_CONTENT
        | GatewayIntents::GUILD_MEMBERS
        | GatewayIntents::DIRECT_MESSAGES;

    // WP-S2.2 — the approval queue + its (optional) dedicated channel. Without a
    // configured channel, proposals post in-place where the owner is talking.
    let queue = Arc::new(ApprovalQueue::new());
    let approval_channel = std::env::var("HERMES_APPROVAL_CHANNEL")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());
    if let Some(ch) = approval_channel {
        tracing::info!(channel = ch, "approval queue → dedicated channel");
    } else {
        tracing::info!("approval queue → in-place (set HERMES_APPROVAL_CHANNEL to dedicate one)");
    }

    let trail = Arc::new(TracingTrail);

    // WP-S2.2b — decision anchoring. The tracing sink is always on (a local append-only
    // record of every approve/deny). An on-chain anchor (hermes-anchor → RecorderClient)
    // is layered on only when the owner supplies a registry address + signer; until then
    // every decision is still durably recorded locally.
    let decisions = build_decision_sink();

    // WP-S2.5 — the research room. Rich, multi-turn command handling is confined to private
    // surfaces (the research channel + agenda threads + DMs), so a public channel can never
    // become an owner-id oracle (H-A16). Without a research channel configured, only DMs are
    // a rich surface.
    let research_channel = std::env::var("HERMES_RESEARCH_CHANNEL")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());
    match research_channel {
        Some(ch) => tracing::info!(channel = ch, "research room → #hermes-research"),
        None => tracing::info!("research room → DMs only (set HERMES_RESEARCH_CHANNEL to add a channel)"),
    }
    let room = RoomScope::new(research_channel);

    // WP-S2.3 — durable memory. With HERMES_MEMORY_PATH set, agenda + approval-queue state
    // is persisted (crash-atomically) and restored on startup, so a restart or context
    // clear resumes exactly where it left off. Restored state is re-validated through the
    // guard (restore_into, T21) — never trusted as resumed intent. Without the env var,
    // memory is in-process only.
    let memory: Arc<dyn MemoryStore> = match std::env::var("HERMES_MEMORY_PATH") {
        Ok(p) if !p.trim().is_empty() => {
            tracing::info!(path = %p.trim(), "durable memory → JSON file");
            Arc::new(JsonMemoryStore::new(p.trim()))
        }
        _ => {
            tracing::info!("durable memory → disabled (set HERMES_MEMORY_PATH to persist agendas)");
            Arc::new(NullMemoryStore)
        }
    };

    let mut agenda_store = AgendaStore::new();
    match memory.load() {
        Ok(Some(snapshot)) => {
            let agenda_count = snapshot.agendas.len();
            let pending_count = snapshot.pending.len();
            restore_into(snapshot, &mut agenda_store, &queue);
            tracing::info!(agenda_count, pending_count, "restored durable memory (re-validated)");
        }
        Ok(None) => tracing::info!("no prior memory snapshot — starting fresh"),
        Err(e) => tracing::warn!(error = %e, "failed to load memory — starting fresh"),
    }
    let agendas = Arc::new(Mutex::new(agenda_store));

    let mut client = Client::builder(&token, intents)
        .event_handler(Handler::new(
            auth,
            bot_id,
            trail,
            decisions,
            Some(llm),
            queue,
            approval_channel,
            room,
            agendas,
            memory,
        ))
        .await?;

    tracing::info!("hermes daemon starting");
    client.start().await?;
    Ok(())
}

/// Build the decision-anchoring sink. The tracing sink is always present (a local,
/// append-only record of every owner decision). When the `anchor` feature is built **and**
/// the owner has supplied `HERMES_DECISION_REGISTRY` + a signer (`DEPLOYER_PRIVATE_KEY` /
/// `.env.testnet`), an on-chain anchor is layered on top via [`hermes_anchor`]. Without
/// either, decisions are still durably recorded locally — anchoring is additive, never the
/// only record (WP-S2.2b).
fn build_decision_sink() -> Arc<dyn hermes_core::decision::DecisionSink> {
    let tracing_sink: Arc<dyn hermes_core::decision::DecisionSink> = Arc::new(TracingDecisionSink);

    #[cfg(feature = "anchor")]
    {
        match hermes_anchor::ChainDecisionSink::from_env() {
            Some(chain) => {
                tracing::info!(
                    registry = chain.registry_addr(),
                    signer = chain.signer_address(),
                    "decision anchoring → on-chain (AgentDecisionRegistryV2) + journald"
                );
                return Arc::new(FanoutDecisionSink::new(vec![tracing_sink, Arc::new(chain)]));
            }
            None => {
                tracing::info!(
                    "decision anchoring → journald only (set HERMES_DECISION_REGISTRY + a signer to anchor on-chain)"
                );
            }
        }
    }
    #[cfg(not(feature = "anchor"))]
    {
        tracing::info!("decision anchoring → journald only (built without the `anchor` feature)");
    }

    tracing_sink
}
