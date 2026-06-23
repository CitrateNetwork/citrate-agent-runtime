//! The serenity event handler: normalize → ask the guard → carry out the [`Action`],
//! and run the approval-queue button loop. This is the only place serenity types meet
//! hermes-core; it decides nothing itself (authorization is the guard, ADR-H3).

use std::sync::Arc;
use std::time::Instant;

use hermes_core::agenda::{AgendaStore, AgendaTurn};
use hermes_core::approval::{custom_id, parse_custom_id};
use hermes_core::decision::{ApprovalDecision, DecisionSink};
use hermes_core::event::{Addressed, InteractionEvent, InteractionKind, MessageEvent};
use hermes_core::guard::{route_interaction, InteractionDecision, OwnerAuth, REFUSAL};
use hermes_core::memory::{MemorySnapshot, MemoryStore};
use hermes_core::principal::Principal;
use hermes_core::room::{is_new_agenda_post, is_private_surface, RoomScope};
use hermes_core::trail::{Outcome, Trail, TrailEntry};
use hermes_core::{
    decide, Action, ActionEffect, ApprovalQueue, Decision, PendingAction, Provenance,
    RefusalCooldown,
};
use hermes_llm::{LlmClient, LlmOutcome};
use serenity::all::{
    ButtonStyle, ChannelId, ComponentInteraction, Context, CreateActionRow, CreateButton,
    CreateInteractionResponse, CreateInteractionResponseMessage, CreateMessage, CreateThread,
    EventHandler, GetMessages, Interaction, Message, Ready,
};
use serenity::async_trait;
use tokio::sync::Mutex;

use crate::classify::{classify_addressed, classify_author, classify_channel};

/// Default per-user refusal cooldown: 10 minutes.
const REFUSAL_WINDOW_MS: u64 = 10 * 60 * 1000;
/// Most recent owner turns fed to the planner per agenda reply (bounds the prompt, T18).
const MAX_CONTEXT_TURNS: usize = 12;
/// Max characters in a derived agenda/thread title.
const TITLE_MAX: usize = 80;

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

/// Fetch up to `limit` recent messages from a channel as `"author: content"` lines (newest
/// first, the order serenity returns). Bot/own messages are kept — the caller frames the
/// result as data. Each line is single-lined + bounded so one giant message can't dominate.
async fn fetch_recent(ctx: &Context, channel: u64, limit: u32) -> anyhow::Result<Vec<String>> {
    let n = limit.clamp(1, 50) as u8;
    let msgs = ChannelId::new(channel)
        .messages(&ctx.http, GetMessages::new().limit(n))
        .await?;
    Ok(msgs
        .into_iter()
        .map(|m| {
            let content = m.content.replace('\n', " ");
            let content = truncate(&content, 240);
            format!("{}: {}", m.author.name, content)
        })
        .collect())
}

/// The Hermes gateway handler.
pub struct Handler {
    auth: OwnerAuth,
    cooldown: Mutex<RefusalCooldown>,
    bot_id: u64,
    start: Instant,
    trail: Arc<dyn Trail>,
    decisions: Arc<dyn DecisionSink>,
    llm: Option<Arc<LlmClient>>,
    queue: Arc<ApprovalQueue>,
    /// Channel proposals are posted to. `None` ⇒ post in the channel the command came from.
    approval_channel: Option<u64>,
    /// The research-room boundary (H-A16): which surfaces are private enough for rich,
    /// multi-turn command handling.
    room: RoomScope,
    /// Open agendas (one thread each) with their running owner-authored context (S2.5).
    agendas: Arc<Mutex<AgendaStore>>,
    /// Durable memory backend (S2.3); persisted after every agenda/queue mutation.
    memory: Arc<dyn MemoryStore>,
    /// Allowlisted channels a digest may be posted to (T13). Empty ⇒ digests are refused.
    digest_targets: Vec<u64>,
}

impl Handler {
    /// Build the handler. `llm` `None` ⇒ the owner gets a plain acknowledgement;
    /// `approval_channel` `None` ⇒ proposals post in-place. `decisions` is the
    /// decision-anchoring sink (always at least the tracing sink; an on-chain anchor is
    /// layered on when configured, WP-S2.2b). `room` + `agendas` drive the research-room
    /// command plane (S2.5).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auth: OwnerAuth,
        bot_id: u64,
        trail: Arc<dyn Trail>,
        decisions: Arc<dyn DecisionSink>,
        llm: Option<Arc<LlmClient>>,
        queue: Arc<ApprovalQueue>,
        approval_channel: Option<u64>,
        room: RoomScope,
        agendas: Arc<Mutex<AgendaStore>>,
        memory: Arc<dyn MemoryStore>,
        digest_targets: Vec<u64>,
    ) -> Self {
        Self {
            auth,
            cooldown: Mutex::new(RefusalCooldown::new(REFUSAL_WINDOW_MS)),
            bot_id,
            start: Instant::now(),
            trail,
            decisions,
            llm,
            queue,
            approval_channel,
            room,
            agendas,
            memory,
            digest_targets,
        }
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Persist the current agenda + approval-queue state to durable memory (S2.3). Snapshots
    /// under the agenda lock, then writes outside it (the write is crash-atomic). A write
    /// failure is a warning, never a dropped event — the live state stands.
    async fn persist(&self) {
        let snapshot = {
            let store = self.agendas.lock().await;
            MemorySnapshot::capture(&store, &self.queue)
        };
        if let Err(e) = self.memory.save(&snapshot) {
            tracing::warn!(error = %e, "failed to persist memory snapshot");
        }
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

    /// Whether `channel` is a known agenda thread (one Hermes opened). Takes the agenda
    /// lock briefly.
    async fn is_agenda_thread(&self, channel: u64) -> bool {
        self.agendas.lock().await.is_agenda_thread(channel)
    }

    /// Route an owner command through the research-room model (S2.5):
    ///   - **public surface** → downgrade to ambient (no rich reply): no public owner-id
    ///     oracle (H-A16);
    ///   - **new agenda post** (top-level in the research channel) → open a thread and work
    ///     it there;
    ///   - **inside an agenda thread** → append the turn and reply with multi-turn context;
    ///   - **DM / research channel chatter** → a plain rich reply (stateless).
    async fn handle_command(&self, ctx: &Context, msg: &Message, ev: &MessageEvent) {
        let is_agenda_thread = self.is_agenda_thread(ev.channel).await;

        if !is_private_surface(ev, &self.room, is_agenda_thread) {
            // H-A16: the owner addressed Hermes on a public surface. Reasoning richly here
            // would tell any observer who the owner is. Stay silent — it was already
            // recorded on the trail as an (ignored) command.
            tracing::info!(
                channel = ev.channel,
                "owner command on a public surface — downgraded to ambient (H-A16, no rich reply)"
            );
            return;
        }

        if self.llm.is_none() {
            let _ = msg.reply(ctx, "Command received (no local model configured).").await;
            return;
        }

        if is_new_agenda_post(ev, &self.room, is_agenda_thread) {
            self.open_agenda(ctx, msg, ev).await;
        } else if is_agenda_thread {
            self.continue_agenda(ctx, msg, ev).await;
        } else {
            // DM or research-channel chatter not bound to an agenda: a stateless rich reply.
            let prompt = self.strip_self_mention(&ev.content);
            self.respond_with_turns(ctx, msg, ev, &[prompt], ev.channel).await;
        }
    }

    /// Open a new agenda: create a thread off the owner's post, register it, and kick off
    /// the work there with the opening post as the first context turn.
    async fn open_agenda(&self, ctx: &Context, msg: &Message, ev: &MessageEvent) {
        let content = self.strip_self_mention(&ev.content);
        let title = hermes_core::agenda::derive_title(&content, TITLE_MAX);
        let thread = match msg
            .channel_id
            .create_thread_from_message(&ctx.http, msg.id, CreateThread::new(title.clone()))
            .await
        {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, "failed to open agenda thread");
                let _ = msg.reply(ctx, "I couldn't open a thread for that agenda.").await;
                return;
            }
        };
        let thread_id = thread.id.get();
        {
            let mut store = self.agendas.lock().await;
            store.open(ev.message_id, thread_id, &content, TITLE_MAX, self.now_ms());
        }
        self.persist().await;
        let _ = thread
            .id
            .say(&ctx.http, format!("📌 **Agenda:** {title}\nWorking this here. Add intent any time; I'll keep the thread as the running record."))
            .await;
        // First pass over the opening intent, in-thread.
        self.respond_with_turns(ctx, msg, ev, &[content], thread_id).await;
    }

    /// Continue an agenda: append the owner's turn, then reply in-thread with the most
    /// recent owner-authored context (ADR-H9: only owner turns are planner input).
    async fn continue_agenda(&self, ctx: &Context, msg: &Message, ev: &MessageEvent) {
        let content = self.strip_self_mention(&ev.content);
        let turns = {
            let mut store = self.agendas.lock().await;
            store.append_turn(
                ev.channel,
                AgendaTurn {
                    message_id: ev.message_id,
                    principal: Principal::Owner,
                    content: content.clone(),
                    at_ms: self.now_ms(),
                },
            );
            store
                .get_by_thread(ev.channel)
                .map(|a| a.context_window(MAX_CONTEXT_TURNS))
                .unwrap_or_else(|| vec![content.clone()])
        };
        self.persist().await;
        self.respond_with_turns(ctx, msg, ev, &turns, ev.channel).await;
    }

    /// Ask the model over `turns` and deliver the result to `reply_channel`: either a rich
    /// reply or a staged approval-queue proposal. Shared by every command surface.
    async fn respond_with_turns(
        &self,
        ctx: &Context,
        msg: &Message,
        ev: &MessageEvent,
        turns: &[String],
        reply_channel: u64,
    ) {
        let Some(llm) = &self.llm else { return };
        let _ = ChannelId::new(reply_channel).broadcast_typing(&ctx.http).await;
        match llm.respond_or_propose(turns).await {
            Ok(LlmOutcome::Reply(text)) => {
                let out = if text.is_empty() {
                    "(the model returned nothing)".to_string()
                } else {
                    truncate(&text, 1900)
                };
                if let Err(e) = ChannelId::new(reply_channel).say(&ctx.http, out).await {
                    tracing::warn!(error = %e, "failed to send command reply");
                }
            }
            Ok(LlmOutcome::ProposePost { channel_id, content }) => {
                self.stage_post_proposal(ctx, msg, ev, channel_id, content).await;
            }
            Ok(LlmOutcome::ReadChannel { channel_id, limit }) => {
                let target = channel_id.unwrap_or(ev.channel);
                self.read_channel_for_owner(ctx, target, limit, reply_channel).await;
            }
            Ok(LlmOutcome::ProposeDigest { source_channel, target_channel }) => {
                let source = source_channel.unwrap_or(ev.channel);
                self.stage_digest_proposal(ctx, msg, ev, source, target_channel).await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "llm error");
                let _ = ChannelId::new(reply_channel)
                    .say(&ctx.http, "I hit an error reaching my local model.")
                    .await;
            }
        }
    }

    /// Read recent messages from `channel` and show them to the owner (S2.4 discord-read).
    /// Read-only: nothing is posted to the source. The content is shown to the owner as
    /// **data** — it is never fed back to the model as instructions (T22).
    async fn read_channel_for_owner(
        &self,
        ctx: &Context,
        channel: u64,
        limit: u32,
        reply_channel: u64,
    ) {
        match fetch_recent(ctx, channel, limit).await {
            Ok(lines) if lines.is_empty() => {
                let _ = ChannelId::new(reply_channel)
                    .say(&ctx.http, format!("No readable recent messages in <#{channel}>."))
                    .await;
            }
            Ok(lines) => {
                // Oldest-first, framed as a quoted read so it's visibly data, not Hermes.
                let body = format!(
                    "🔎 **Recent messages in <#{channel}>** (latest {}):\n{}",
                    lines.len(),
                    lines.iter().rev().map(|l| format!("> {l}")).collect::<Vec<_>>().join("\n")
                );
                let _ = ChannelId::new(reply_channel).say(&ctx.http, truncate(&body, 1900)).await;
            }
            Err(e) => {
                tracing::warn!(error = %e, channel, "read_channel failed");
                let _ = ChannelId::new(reply_channel)
                    .say(&ctx.http, format!("I couldn't read <#{channel}> (no access?)."))
                    .await;
            }
        }
    }

    /// Stage a digest proposal (S2.4 discord-digest). The target must be on the allowlist
    /// (T13) — checked here at propose time and again at execute time (defense in depth). If
    /// it isn't, Hermes refuses and names the allowed targets rather than staging anything.
    async fn stage_digest_proposal(
        &self,
        ctx: &Context,
        msg: &Message,
        ev: &MessageEvent,
        source: u64,
        target: u64,
    ) {
        if !self.digest_targets.contains(&target) {
            let allowed = if self.digest_targets.is_empty() {
                "no digest targets are configured".to_string()
            } else {
                self.digest_targets.iter().map(|c| format!("<#{c}>")).collect::<Vec<_>>().join(", ")
            };
            let _ = msg
                .reply(ctx, format!("I can't post a digest to <#{target}> — it's not an allowed target. Allowed: {allowed}."))
                .await;
            return;
        }
        let effect = ActionEffect::Digest { source_channel: source, target_channel: target };
        let provenance = Provenance {
            triggered_by_message: Some(ev.message_id),
            triggered_in_channel: Some(ev.channel),
        };
        let action = self.queue.propose(effect, provenance, self.now_ms());
        self.persist().await;
        let dest = self.approval_channel.unwrap_or(ev.channel);
        match self.post_proposal(ctx, dest, &action).await {
            Ok(()) => {
                let _ = msg
                    .reply(ctx, format!("Proposed (#{}) — awaiting your approval.", action.id))
                    .await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to post digest proposal");
                let _ = msg.reply(ctx, "I drafted that digest but couldn't queue it.").await;
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
        self.persist().await;
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
            ActionEffect::Digest { source_channel, target_channel } => {
                // T13 re-check at execute time: the allowlist could have changed, or a
                // restored proposal could name a now-disallowed target. Never post off-list.
                if !self.digest_targets.contains(target_channel) {
                    anyhow::bail!("digest target <#{target_channel}> is not allowlisted");
                }
                let llm = self
                    .llm
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("no model configured to summarize"))?;
                let lines = fetch_recent(ctx, *source_channel, 50)
                    .await
                    .map_err(|e| anyhow::anyhow!("read source failed: {e}"))?;
                if lines.is_empty() {
                    ChannelId::new(*target_channel)
                        .say(&ctx.http, format!("Digest of <#{source_channel}>: nothing recent to summarize."))
                        .await?;
                    return Ok(());
                }
                // Summarized as untrusted data (T22).
                let summary = llm
                    .summarize_messages(&format!("<#{source_channel}>"), &lines)
                    .await
                    .map_err(|e| anyhow::anyhow!("summarize failed: {e}"))?;
                let body = format!("📰 **Digest of <#{source_channel}>**\n{}", truncate(&summary, 1800));
                ChannelId::new(*target_channel).say(&ctx.http, body).await?;
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

        // Anchor the decision (the concrete effect the owner approved, H-A12). Recorded
        // before execution so the audit record exists even if the effect later fails — a
        // denied action is recorded too. resolve() already guaranteed this fires once.
        self.decisions
            .record(ApprovalDecision::from_resolved(&action, dec, self.now_ms()));
        // The queue changed — persist so a restart doesn't resurrect a resolved action.
        self.persist().await;

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
        let mut ev = self.normalize(&msg);
        // Research-room UX (S2.5): inside a private research surface (the research channel
        // or an agenda thread Hermes opened), an owner message is a command without needing
        // an @mention. This never widens authority — the guard still authorizes by owner id
        // — it only relaxes the *addressed* requirement on surfaces that are private by
        // construction (so it cannot create a public oracle, H-A16).
        let in_private_room = self.room.research_channel == Some(ev.channel)
            || self.is_agenda_thread(ev.channel).await;
        if in_private_room && !ev.addressed.is_addressed() {
            ev.addressed = Addressed::Direct;
        }
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
