//! Transport-agnostic event types. The serenity adapter populates these from gateway
//! events; the guard reasons only over these, so it never depends on Discord types.

/// A Discord snowflake (user/channel/message id). We keep it a plain `u64` — the
/// guard only ever compares ids for equality, never parses semantics out of them.
pub type UserId = u64;
/// A channel snowflake.
pub type ChannelId = u64;
/// A message snowflake — the unit a command-plane action binds to (ADR-H9).
pub type MessageId = u64;

/// Who authored an event. Only a real `User` can possibly be the owner; webhooks,
/// system messages, and integrations are never the owner (T2 — they are a common
/// impersonation vector because they can carry an arbitrary display name).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorKind {
    /// A real user account, identified by its immutable id.
    User(UserId),
    /// A webhook post (display name is attacker-controlled).
    Webhook,
    /// A Discord system message (joins, pins, …).
    System,
    /// A bot/integration post.
    Integration,
}

/// The channel surface an event arrived on. The command plane is allowed only on
/// enumerated types; anything else default-denies (H-A17 / M9 — forums, ephemeral,
/// and unknown surfaces have principal-attribution quirks we do not yet model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKind {
    /// A direct message to the bot.
    Dm,
    /// A standard guild text channel.
    GuildText,
    /// A thread under a text channel.
    Thread,
    /// A forum channel (not yet modeled for the command plane).
    Forum,
    /// Any other / unknown surface.
    Other,
}

impl ChannelKind {
    /// Whether the command plane may operate here. Default-deny for anything not
    /// explicitly enumerated (H-A17).
    pub fn command_allowed(self) -> bool {
        matches!(self, ChannelKind::Dm | ChannelKind::GuildText | ChannelKind::Thread)
    }
}

/// How (if at all) the message addressed the bot. The command plane responds only
/// when **directly addressed** (T12) — ambient channel chatter is never a command and
/// never draws a response, so the bot cannot be baited into flooding a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addressed {
    /// A DM to the bot (inherently direct).
    Direct,
    /// An @mention of the bot.
    Mention,
    /// A reply to one of the bot's messages.
    Reply,
    /// Not addressed to the bot.
    None,
}

impl Addressed {
    /// Whether the bot was addressed at all.
    pub fn is_addressed(self) -> bool {
        !matches!(self, Addressed::None)
    }
}

/// A message event, normalized from the gateway. `content` is **data, never
/// instructions** (ADR-H4) — the guard never interprets it; it only routes.
#[derive(Debug, Clone)]
pub struct MessageEvent {
    /// Who authored it.
    pub author: AuthorKind,
    /// True iff the author is Hermes itself — dropped before any plane (T17).
    pub is_bot_self: bool,
    /// The channel it arrived on.
    pub channel: ChannelId,
    /// The channel surface kind.
    pub channel_kind: ChannelKind,
    /// The message id — a command binds to exactly this (ADR-H9).
    pub message_id: MessageId,
    /// The raw content (treated strictly as data).
    pub content: String,
    /// How it addressed the bot.
    pub addressed: Addressed,
    /// True if this is an edit (`MESSAGE_UPDATE`) rather than a create — moderation
    /// must re-classify edits (T16); the command plane treats them the same.
    pub edited: bool,
}

/// A component / application-command interaction (button, slash, context menu).
/// Interactions are a **separate auth surface** from messages and must be guarded on
/// `user` independently (T15) — seeing a channel never implies authority to act in it.
#[derive(Debug, Clone)]
pub struct InteractionEvent {
    /// The interacting user's immutable id (`interaction.member.user.id`).
    pub user: UserId,
    /// Where the interaction happened.
    pub channel: ChannelId,
    /// What kind of interaction.
    pub kind: InteractionKind,
}

/// The kind of interaction (for routing/labels; the guard only needs `user`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteractionKind {
    /// A button press, e.g. an approval-queue approve/deny (`custom_id`).
    Button { custom_id: String },
    /// A slash command invocation.
    Slash { name: String },
    /// Any other message-component interaction.
    Component { custom_id: String },
}
