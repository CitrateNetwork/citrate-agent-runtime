//! The serenity event handler: normalize → ask the guard → carry out the [`Action`],
//! and run the approval-queue button loop. This is the only place serenity types meet
//! hermes-core; it decides nothing itself (authorization is the guard, ADR-H3).

use std::sync::Arc;
use std::time::Instant;

use hermes_core::approval::{custom_id, parse_custom_id};
use hermes_core::event::{InteractionEvent, InteractionKind, MessageEvent};
use hermes_core::guard::{route_interaction, InteractionDecision, OwnerAuth, REFUSAL};
use hermes_core::trail::{Outcome, Trail, TrailEntry};
use hermes_core::{
    decide, Action, ActionEffect, ApprovalQueue, Decision, PendingAction, Provenance,
    RefusalCooldown,
};
use hermes_llm::{LlmClient, LlmOutcome};
use serenity::all::{
    ButtonStyle, ChannelId, ComponentInteraction, Context, CreateActionRow, CreateButton,
    CreateInteractionResponse, CreateInteractionResponseMessage, CreateMessage, EventHandler,
    Interaction, Message, Ready,
};
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

/// The Hermes gateway handler.
pub struct Handler {
    auth: OwnerAuth,
    cooldown: Mutex<RefusalCooldown>,
    bot_id: u64,
    start: Instant,
    trail: Arc<dyn Trail>,
    llm: Option<Arc<LlmClient>>,
    queue: Arc<ApprovalQueue>,
    /// Channel proposals are posted to. `None` ⇒ post in the channel the command came from.
    approval_channel: Option<u64>,
}

impl Handler {
    /// Build the handler. `llm` `None` ⇒ the owner gets a plain acknowledgement;
    /// `approval_channel` `None` ⇒ proposals post in-place.
    pub fn new(
        auth: OwnerAuth,
        bot_id: u64,
        trail: Arc<dyn Trail>,
        llm: Option<Arc<LlmClient>>,
        queue: Arc<ApprovalQueue>,
        approval_channel: Option<u64>,
    ) -> Self {
        Self {
            auth,
            cooldown: Mutex::new(RefusalCooldown::new(REFUSAL_WINDOW_MS)),
            bot_id,
            start: Instant::now(),
            trail,
            llm,
            queue,
            approval_channel,
        }
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn strip_self_mention(&self, content: &str) -> String {
        content
            .replace(&format!("<@{}>", self.bot_id), "")
            .replace(&format!("<@!{}>", self.bot_id), "")
            .trim()
            .to_string()
    }

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

    fn record_interaction(&self, ev: &InteractionEvent, decision: InteractionDecision) {
        let outcome = match decision {
            InteractionDecision::Allow => Outcome::InteractionAllowed,
            InteractionDecision::Deny => Outcome::InteractionDenied,
        };
        self.trail.record(TrailEntry {
            at_ms: self.now_ms(),
            principal: self.auth.authorize_user(ev.user),
            actor: Some(ev.user),
            channel: ev.channel,
            outcome,
        });
    }

    /// Handle an owner command: ask the model, then either reply or stage a proposal.
    async fn handle_command(&self, ctx: &Context, msg: &Message, ev: &MessageEvent) {
        let Some(llm) = &self.llm else {
            let _ = msg.reply(ctx, "Command received (no local model configured).").await;
            return;
        };
        let _ = msg.channel_id.broadcast_typing(&ctx.http).await;
        let prompt = self.strip_self_mention(&ev.content);
        match llm.respond_or_propose(&[prompt]).await {
            Ok(LlmOutcome::Reply(text)) => {
                let out = if text.is_empty() {
                    "(the model returned nothing)".to_string()
                } else {
                    truncate(&text, 1900)
                };
                if let Err(e) = msg.reply(ctx, out).await {
                    tracing::warn!(error = %e, "failed to send command reply");
                }
            }
            Ok(LlmOutcome::ProposePost { channel_id, content }) => {
                self.stage_post_proposal(ctx, msg, ev, channel_id, content).await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "llm error");
                let _ = msg.reply(ctx, "I hit an error reaching my local model.").await;
            }
        }
    }

    /// Create a pending action for a proposed post and surface it with Approve/Deny.
    async fn stage_post_proposal(
        &self,
        ctx: &Context,
        msg: &Message,
        ev: &MessageEvent,
        channel_id: Option<u64>,
        content: String,
    ) {
        let target = channel_id.unwrap_or(ev.channel);
        let effect = ActionEffect::PostMessage { channel: target, content };
        let provenance = Provenance {
            triggered_by_message: Some(ev.message_id),
            triggered_in_channel: Some(ev.channel),
        };
        let action = self.queue.propose(effect, provenance, self.now_ms());
        let dest = self.approval_channel.unwrap_or(ev.channel);
        match self.post_proposal(ctx, dest, &action).await {
            Ok(()) => {
                let where_ = if self.approval_channel.is_some() {
                    " in the approval channel".to_string()
                } else {
                    String::new()
                };
                let _ = msg
                    .reply(ctx, format!("Proposed (#{}) — awaiting your approval{where_}.", action.id))
                    .await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to post proposal");
                let _ = msg.reply(ctx, "I drafted that but couldn't post it to the approval queue.").await;
            }
        }
    }

    /// Post a proposal message with the concrete effect (H-A12) and Approve/Deny buttons.
    async fn post_proposal(
        &self,
        ctx: &Context,
        dest: u64,
        action: &PendingAction,
    ) -> anyhow::Result<()> {
        let trig = action.provenance.triggered_in_channel.unwrap_or(0);
        let body = format!(
            "🟡 **Pending approval #{}**\n{}\n\n_Triggered by your message in <#{trig}>._",
            action.id,
            action.effect.describe()
        );
        let row = CreateActionRow::Buttons(vec![
            CreateButton::new(custom_id(Decision::Approve, action.id))
                .label("Approve")
                .style(ButtonStyle::Success),
            CreateButton::new(custom_id(Decision::Deny, action.id))
                .label("Deny")
                .style(ButtonStyle::Danger),
        ]);
        ChannelId::new(dest)
            .send_message(&ctx.http, CreateMessage::new().content(body).components(vec![row]))
            .await?;
        Ok(())
    }

    /// Carry out an approved effect.
    async fn execute(&self, ctx: &Context, effect: &ActionEffect) -> anyhow::Result<()> {
        match effect {
            ActionEffect::PostMessage { channel, content } => {
                ChannelId::new(*channel).say(&ctx.http, content).await?;
                Ok(())
            }
        }
    }

    /// Handle a button press on an approval-queue item.
    async fn handle_component(&self, ctx: &Context, c: &ComponentInteraction) {
        let ev = InteractionEvent {
            user: c.user.id.get(),
            channel: c.channel_id.get(),
            kind: InteractionKind::Button { custom_id: c.data.custom_id.clone() },
        };
        let decision = route_interaction(&self.auth, &ev);
        self.record_interaction(&ev, decision);

        // T15 — only the owner can act on the queue, regardless of channel visibility.
        if decision == InteractionDecision::Deny {
            let _ = c
                .create_response(
                    &ctx.http,
                    CreateInteractionResponse::Message(
                        CreateInteractionResponseMessage::new()
                            .ephemeral(true)
                            .content("You're not authorized to act on Hermes's queue."),
                    ),
                )
                .await;
            return;
        }

        let Some((dec, action_id)) = parse_custom_id(&c.data.custom_id) else {
            let _ = c.create_response(&ctx.http, CreateInteractionResponse::Acknowledge).await;
            return;
        };

        // resolve() returns the action at most once — a double-click can't double-execute.
        let Some(action) = self.queue.resolve(action_id, dec) else {
            let _ = c
                .create_response(
                    &ctx.http,
                    CreateInteractionResponse::UpdateMessage(
                        CreateInteractionResponseMessage::new()
                            .content("This item was already handled.")
                            .components(vec![]),
                    ),
                )
                .await;
            return;
        };

        let result_line = match dec {
            Decision::Approve => match self.execute(ctx, &action.effect).await {
                Ok(()) => format!("✅ **Approved & executed** — {}", action.effect.kind()),
                Err(e) => {
                    tracing::warn!(error = %e, "execution failed after approval");
                    format!("⚠️ Approved, but execution failed: {e}")
                }
            },
            Decision::Deny => format!("❌ **Denied** — {}", action.effect.kind()),
        };
        let _ = c
            .create_response(
                &ctx.http,
                CreateInteractionResponse::UpdateMessage(
                    CreateInteractionResponseMessage::new().content(result_line).components(vec![]),
                ),
            )
            .await;
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
        let principal = self.auth.authorize_author(ev.author);
        self.trail
            .record(TrailEntry::for_message(now, principal, ev.author, ev.channel, &action));
        match action {
            Action::Refuse => {
                if let Err(e) = msg.reply(&ctx, REFUSAL).await {
                    tracing::warn!(error = %e, "failed to send refusal");
                }
            }
            Action::Command { message_id } => {
                tracing::info!(message_id, "command-plane message accepted (owner)");
                self.handle_command(&ctx, &msg, &ev).await;
            }
            Action::Moderate => {
                tracing::trace!(channel = ev.channel, "moderation-plane observe");
            }
            Action::Ignore => {}
        }
    }

    async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
        match interaction {
            Interaction::Component(c) => self.handle_component(&ctx, &c).await,
            Interaction::Command(c) => {
                // No slash handlers yet (S2); record the guarded decision for the trail.
                let ev = InteractionEvent {
                    user: c.user.id.get(),
                    channel: c.channel_id.get(),
                    kind: InteractionKind::Slash { name: c.data.name.clone() },
                };
                let decision = route_interaction(&self.auth, &ev);
                self.record_interaction(&ev, decision);
            }
            _ => {}
        }
    }
}
