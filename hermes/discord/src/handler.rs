//! The serenity event handler: normalize → ask the guard → carry out the [`Action`].
//! This is the only place serenity types meet hermes-core; it decides nothing itself.

use std::sync::Arc;
use std::time::Instant;

use hermes_core::event::{InteractionEvent, InteractionKind, MessageEvent};
use hermes_core::guard::{route_interaction, InteractionDecision, OwnerAuth, REFUSAL};
use hermes_core::trail::{Outcome, Trail, TrailEntry};
use hermes_core::{decide, Action, RefusalCooldown};
use hermes_llm::LlmClient;
use serenity::all::{Context, EventHandler, Interaction, Message, Ready};
use serenity::async_trait;
use tokio::sync::Mutex;

use crate::classify::{classify_addressed, classify_author, classify_channel};

/// Default per-user refusal cooldown: 10 minutes.
const REFUSAL_WINDOW_MS: u64 = 10 * 60 * 1000;

/// Truncate to at most `max` characters (Discord's message limit is 2000), appending an
/// ellipsis when cut. Operates on chars so a multibyte boundary is never split.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// The Hermes gateway handler. Holds the owner authority, the refusal cooldown, and the
/// bot's own id (to drop self-events). The cooldown is behind an async mutex because
/// serenity dispatches events concurrently.
pub struct Handler {
    auth: OwnerAuth,
    cooldown: Mutex<RefusalCooldown>,
    bot_id: u64,
    start: Instant,
    trail: Arc<dyn Trail>,
    llm: Option<Arc<LlmClient>>,
}

impl Handler {
    /// Build the handler for a known owner authority, the bot's own user id, an
    /// append-only audit trail (WP-S1.4), and an optional local LLM for the command
    /// plane (WP-S2.1; `None` ⇒ the owner gets a plain acknowledgement).
    pub fn new(
        auth: OwnerAuth,
        bot_id: u64,
        trail: Arc<dyn Trail>,
        llm: Option<Arc<LlmClient>>,
    ) -> Self {
        Self {
            auth,
            cooldown: Mutex::new(RefusalCooldown::new(REFUSAL_WINDOW_MS)),
            bot_id,
            start: Instant::now(),
            trail,
            llm,
        }
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Strip the bot's own @mention from a command so the model sees the intent, not the
    /// ping token.
    fn strip_self_mention(&self, content: &str) -> String {
        content
            .replace(&format!("<@{}>", self.bot_id), "")
            .replace(&format!("<@!{}>", self.bot_id), "")
            .trim()
            .to_string()
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
        let now = self.now_ms();
        let action = {
            let mut cd = self.cooldown.lock().await;
            decide(&self.auth, &mut cd, &ev, now)
        };
        // WP-S1.4 — record every decision (append-only). Non-owner command attempts are
        // flagged as security signals by the trail.
        let principal = self.auth.authorize_author(ev.author);
        self.trail
            .record(TrailEntry::for_message(now, principal, ev.author, ev.channel, &action));
        match action {
            Action::Refuse => {
                // Fixed string, no LLM round-trip — cannot be prompt-injected (T1).
                if let Err(e) = msg.reply(&ctx, REFUSAL).await {
                    tracing::warn!(error = %e, "failed to send refusal");
                }
            }
            Action::Command { message_id } => {
                tracing::info!(message_id, "command-plane message accepted (owner)");
                match &self.llm {
                    Some(llm) => {
                        // Show a typing indicator while the local model thinks.
                        let _ = msg.channel_id.broadcast_typing(&ctx.http).await;
                        let prompt = self.strip_self_mention(&ev.content);
                        match llm.respond(&[prompt]).await {
                            Ok(reply) => {
                                let out = if reply.is_empty() {
                                    "(the model returned nothing)".to_string()
                                } else {
                                    truncate(&reply, 1900)
                                };
                                if let Err(e) = msg.reply(&ctx, out).await {
                                    tracing::warn!(error = %e, "failed to send command reply");
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "llm error");
                                let _ = msg
                                    .reply(&ctx, "I hit an error reaching my local model.")
                                    .await;
                            }
                        }
                    }
                    None => {
                        let _ = msg.reply(&ctx, "Command received (no local model configured).").await;
                    }
                }
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
        let decision = route_interaction(&self.auth, &ev);
        let (principal, outcome) = match decision {
            InteractionDecision::Allow => (self.auth.authorize_user(ev.user), Outcome::InteractionAllowed),
            InteractionDecision::Deny => (self.auth.authorize_user(ev.user), Outcome::InteractionDenied),
        };
        self.trail.record(TrailEntry {
            at_ms: self.now_ms(),
            principal,
            actor: Some(ev.user),
            channel: ev.channel,
            outcome,
        });
        match decision {
            InteractionDecision::Allow => {
                tracing::info!(user = ev.user, "owner interaction allowed (S1: no handlers yet)");
            }
            InteractionDecision::Deny => {
                tracing::warn!(user = ev.user, "non-owner interaction denied");
            }
        }
    }
}
