//! The serenity event handler: normalize → ask the guard → carry out the [`Action`].
//! This is the only place serenity types meet hermes-core; it decides nothing itself.

use std::time::Instant;

use hermes_core::event::{InteractionEvent, InteractionKind, MessageEvent};
use hermes_core::guard::{route_interaction, InteractionDecision, OwnerAuth, REFUSAL};
use hermes_core::{decide, Action, RefusalCooldown};
use serenity::all::{Context, EventHandler, Interaction, Message, Ready};
use serenity::async_trait;
use tokio::sync::Mutex;

use crate::classify::{classify_addressed, classify_author, classify_channel};

/// Default per-user refusal cooldown: 10 minutes.
const REFUSAL_WINDOW_MS: u64 = 10 * 60 * 1000;

/// The Hermes gateway handler. Holds the owner authority, the refusal cooldown, and the
/// bot's own id (to drop self-events). The cooldown is behind an async mutex because
/// serenity dispatches events concurrently.
pub struct Handler {
    auth: OwnerAuth,
    cooldown: Mutex<RefusalCooldown>,
    bot_id: u64,
    start: Instant,
}

impl Handler {
    /// Build the handler for a known owner authority and the bot's own user id.
    pub fn new(auth: OwnerAuth, bot_id: u64) -> Self {
        Self {
            auth,
            cooldown: Mutex::new(RefusalCooldown::new(REFUSAL_WINDOW_MS)),
            bot_id,
            start: Instant::now(),
        }
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Normalize a serenity message into the transport-agnostic event the guard reasons
    /// over. Content is carried verbatim — it is data, never instructions (ADR-H4).
    fn normalize(&self, msg: &Message) -> MessageEvent {
        let (author, is_bot_self) =
            classify_author(msg.webhook_id.is_some(), msg.author.id.get(), self.bot_id);
        let in_guild = msg.guild_id.is_some();
        let channel_kind = classify_channel(in_guild, false);
        let mentions_bot = msg.mentions.iter().any(|u| u.id.get() == self.bot_id);
        let replies_to_bot = msg
            .referenced_message
            .as_ref()
            .map(|m| m.author.id.get() == self.bot_id)
            .unwrap_or(false);
        let addressed = classify_addressed(!in_guild, mentions_bot, replies_to_bot);
        MessageEvent {
            author,
            is_bot_self,
            channel: msg.channel_id.get(),
            channel_kind,
            message_id: msg.id.get(),
            content: msg.content.clone(),
            addressed,
            edited: false,
        }
    }
}

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, _ctx: Context, ready: Ready) {
        tracing::info!(bot = %ready.user.name, guilds = ready.guilds.len(), "hermes gateway connected");
    }

    async fn message(&self, ctx: Context, msg: Message) {
        let ev = self.normalize(&msg);
        let action = {
            let mut cd = self.cooldown.lock().await;
            decide(&self.auth, &mut cd, &ev, self.now_ms())
        };
        match action {
            Action::Refuse => {
                // Fixed string, no LLM round-trip — cannot be prompt-injected (T1).
                if let Err(e) = msg.reply(&ctx, REFUSAL).await {
                    tracing::warn!(error = %e, "failed to send refusal");
                }
            }
            Action::Command { message_id } => {
                // S1 acknowledges; the command plane executes in S2 (research room).
                tracing::info!(message_id, "command-plane message accepted (owner)");
            }
            Action::Moderate => {
                // S1 observes only; the moderation plane acts in S3.
                tracing::trace!(channel = ev.channel, "moderation-plane observe");
            }
            Action::Ignore => {}
        }
    }

    async fn interaction_create(&self, _ctx: Context, interaction: Interaction) {
        // Interactions are a separate auth surface — guard on the interacting user id,
        // never channel visibility (T15 / ADR-H9).
        let ev = match &interaction {
            Interaction::Command(c) => InteractionEvent {
                user: c.user.id.get(),
                channel: c.channel_id.get(),
                kind: InteractionKind::Slash { name: c.data.name.clone() },
            },
            Interaction::Component(c) => InteractionEvent {
                user: c.user.id.get(),
                channel: c.channel_id.get(),
                kind: InteractionKind::Button { custom_id: c.data.custom_id.clone() },
            },
            _ => return,
        };
        match route_interaction(&self.auth, &ev) {
            InteractionDecision::Allow => {
                tracing::info!(user = ev.user, "owner interaction allowed (S1: no handlers yet)");
            }
            InteractionDecision::Deny => {
                tracing::warn!(user = ev.user, "non-owner interaction denied");
            }
        }
    }
}
