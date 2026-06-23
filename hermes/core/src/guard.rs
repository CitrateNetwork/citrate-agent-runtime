//! The ingress guard: the single chokepoint every event passes before any plane,
//! tool, LLM, or capsule. All authorization is here, and it is fail-closed.

use crate::event::{AuthorKind, InteractionEvent, MessageEvent, MessageId, UserId};
use crate::principal::Principal;

/// The one response a non-owner ever gets on the command plane. A fixed constant with
/// no LLM round-trip, so it cannot be prompt-injected (T1) and cannot vary.
pub const REFUSAL: &str =
    "I don't work for you respectfully, I work for the company and Saul specifically.";

/// Owner authorization. Holds the single configured owner id (or none). Construction
/// from raw config is **fail-closed**: an unset, empty, malformed, or zero value
/// yields an authority that recognizes *no one* as the owner — including the real
/// owner — so a misconfiguration can never silently open the command plane to all.
#[derive(Debug, Clone)]
pub struct OwnerAuth {
    owner_id: Option<UserId>,
}

impl OwnerAuth {
    /// Construct with a known owner id.
    pub fn new(owner_id: UserId) -> Self {
        Self { owner_id: Some(owner_id) }
    }

    /// Construct from a raw config value (e.g. `OWNER_DISCORD_ID`). Trims whitespace;
    /// rejects non-numeric and zero. `None`/unparseable ⇒ serves no one (fail-closed).
    pub fn from_config(value: Option<&str>) -> Self {
        let owner_id = value
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|&id| id != 0);
        Self { owner_id }
    }

    /// Whether a valid owner id is configured. The daemon's `doctor` preflight refuses
    /// to accept traffic if this is false (a fail-closed guard that recognizes no one
    /// is safe, but it is also useless — better to refuse to start and say why).
    pub fn is_configured(&self) -> bool {
        self.owner_id.is_some()
    }

    /// Authorize a user id. Fail-closed: with no owner configured, nobody is the owner.
    pub fn authorize_user(&self, id: UserId) -> Principal {
        match self.owner_id {
            Some(owner) if owner == id => Principal::Owner,
            _ => Principal::Other,
        }
    }

    /// Authorize an author. Only a real `User` can be the owner; webhooks, system
    /// messages, and integrations are always `Other` (T2 — they carry attacker-chosen
    /// display names but no authentic owner identity).
    pub fn authorize_author(&self, author: AuthorKind) -> Principal {
        match author {
            AuthorKind::User(id) => self.authorize_user(id),
            AuthorKind::Webhook | AuthorKind::System | AuthorKind::Integration => Principal::Other,
        }
    }
}

/// Why an event was dropped before reaching any plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropReason {
    /// The author is Hermes itself — never ingest our own posts (T17): prevents loops
    /// and stops a summarized injection from re-entering as data.
    SelfEvent,
}

/// The guard's decision for a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageRouting {
    /// Owner, addressed, on an allowed channel: a command **bound to one message id**
    /// (ADR-H9). This id is the action's sole provenance.
    Command { message_id: MessageId },
    /// A non-owner addressed the bot on the command plane: refuse. The caller applies
    /// the per-user cooldown ([`crate::cooldown::RefusalCooldown`]) before sending (T12).
    Refuse,
    /// Seen but not a command — ambient chatter, or a non-command channel. Goes to the
    /// moderation plane as **data only**; in S1 moderation takes no action.
    Moderate,
    /// Dropped before any plane.
    Drop(DropReason),
}

/// Route a message through the ingress guard. This is the whole command/moderation
/// split in one function: self-events drop, owners addressing the bot get a bound
/// command, non-owners addressing it get refused, everything else is moderation data.
pub fn route_message(auth: &OwnerAuth, ev: &MessageEvent) -> MessageRouting {
    // T17 — never act on our own messages, before anything else looks at them.
    if ev.is_bot_self {
        return MessageRouting::Drop(DropReason::SelfEvent);
    }

    let principal = auth.authorize_author(ev.author);
    // The command plane requires the bot to be *directly addressed* (T12) on an
    // *allowed channel type* (H-A17). Both must hold, or it is moderation data.
    let command_eligible = ev.addressed.is_addressed() && ev.channel_kind.command_allowed();

    match (principal, command_eligible) {
        (Principal::Owner, true) => MessageRouting::Command { message_id: ev.message_id },
        // Ambient owner message, or owner on a non-command surface: not a command.
        (Principal::Owner, false) => MessageRouting::Moderate,
        // Non-owner addressing the bot: the refusal (cooldown applied by the caller).
        (Principal::Other, true) => MessageRouting::Refuse,
        // Non-owner ambient: moderation only — watched, never obeyed.
        (Principal::Other, false) => MessageRouting::Moderate,
    }
}

/// The guard's decision for an interaction (button/slash/component).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractionDecision {
    /// The interacting user is the owner — allow.
    Allow,
    /// Anyone else — deny. Visibility of the channel/component is *not* authority (T15).
    Deny,
}

/// Route an interaction. Re-runs the guard on the **interacting user's id** — the
/// approval-queue buttons live in an owner-only channel, but "can see it" must never
/// imply "can click it" (T15 / ADR-H9 / H-A2).
pub fn route_interaction(auth: &OwnerAuth, ev: &InteractionEvent) -> InteractionDecision {
    match auth.authorize_user(ev.user) {
        Principal::Owner => InteractionDecision::Allow,
        Principal::Other => InteractionDecision::Deny,
    }
}

/// The owner-authored context filter (ADR-H9): given the messages of a command-plane
/// thread, return only those authored by the owner (and never the bot itself). This is
/// what closes the back door where a non-owner message in a thread the bot reads could
/// become planner input — non-owner content is quotable *data*, never instruction.
pub fn owner_authored_context<'a>(
    auth: &OwnerAuth,
    msgs: &'a [MessageEvent],
) -> Vec<&'a MessageEvent> {
    msgs.iter()
        .filter(|m| !m.is_bot_self && auth.authorize_author(m.author) == Principal::Owner)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Addressed, ChannelKind, InteractionKind};

    const OWNER: UserId = 877642945996673126; // saulloveman
    const STRANGER: UserId = 111111111111111111;
    const BOT: UserId = 1518794917349031976; // citrate-hermes

    fn msg(author: AuthorKind, addressed: Addressed, kind: ChannelKind) -> MessageEvent {
        MessageEvent {
            author,
            is_bot_self: false,
            channel: 42,
            channel_kind: kind,
            message_id: 9001,
            content: "hello".into(),
            addressed,
            edited: false,
        }
    }

    fn owner_auth() -> OwnerAuth {
        OwnerAuth::new(OWNER)
    }

    // --- fail-closed configuration ------------------------------------------------

    #[test]
    fn unconfigured_owner_serves_no_one() {
        // Even the real owner id is Other when no owner is configured (fail-closed).
        let auth = OwnerAuth::from_config(None);
        assert!(!auth.is_configured());
        assert_eq!(auth.authorize_user(OWNER), Principal::Other);
    }

    #[test]
    fn malformed_owner_config_is_fail_closed() {
        for bad in ["", "   ", "not-a-number", "0", "12x34"] {
            let auth = OwnerAuth::from_config(Some(bad));
            assert!(!auth.is_configured(), "{bad:?} should not configure an owner");
            assert_eq!(auth.authorize_user(OWNER), Principal::Other);
        }
    }

    #[test]
    fn valid_owner_config_parses_and_trims() {
        let auth = OwnerAuth::from_config(Some("  877642945996673126  "));
        assert!(auth.is_configured());
        assert_eq!(auth.authorize_user(OWNER), Principal::Owner);
        assert_eq!(auth.authorize_user(STRANGER), Principal::Other);
    }

    // --- T2: impersonation --------------------------------------------------------

    #[test]
    fn only_the_owner_user_id_is_owner() {
        let auth = owner_auth();
        assert_eq!(auth.authorize_user(OWNER), Principal::Owner);
        assert_eq!(auth.authorize_user(STRANGER), Principal::Other);
    }

    #[test]
    fn webhook_system_integration_can_never_be_owner() {
        // The classic impersonation vector: a webhook/system post carrying the name
        // "Saul". No authentic user id ⇒ always Other.
        let auth = owner_auth();
        for a in [AuthorKind::Webhook, AuthorKind::System, AuthorKind::Integration] {
            assert_eq!(auth.authorize_author(a), Principal::Other);
            let r = route_message(&auth, &msg(a, Addressed::Mention, ChannelKind::GuildText));
            assert_eq!(r, MessageRouting::Refuse);
        }
    }

    // --- T17: self-event drop -----------------------------------------------------

    #[test]
    fn self_events_are_dropped_before_any_plane() {
        let auth = owner_auth();
        let mut e = msg(AuthorKind::User(BOT), Addressed::Mention, ChannelKind::GuildText);
        e.is_bot_self = true;
        assert_eq!(route_message(&auth, &e), MessageRouting::Drop(DropReason::SelfEvent));
    }

    // --- command vs moderation routing -------------------------------------------

    #[test]
    fn owner_addressed_gets_a_bound_command() {
        let auth = owner_auth();
        let e = msg(AuthorKind::User(OWNER), Addressed::Mention, ChannelKind::GuildText);
        assert_eq!(route_message(&auth, &e), MessageRouting::Command { message_id: 9001 });
    }

    #[test]
    fn owner_ambient_is_moderation_not_command() {
        // The owner just chatting (not addressing the bot) is not issuing a command.
        let auth = owner_auth();
        let e = msg(AuthorKind::User(OWNER), Addressed::None, ChannelKind::GuildText);
        assert_eq!(route_message(&auth, &e), MessageRouting::Moderate);
    }

    #[test]
    fn non_owner_addressed_is_refused() {
        let auth = owner_auth();
        let e = msg(AuthorKind::User(STRANGER), Addressed::Mention, ChannelKind::GuildText);
        assert_eq!(route_message(&auth, &e), MessageRouting::Refuse);
    }

    #[test]
    fn non_owner_ambient_is_moderation_only() {
        // A non-owner is watched (moderation) but never obeyed (no command, no refusal
        // spam): the two planes, exactly.
        let auth = owner_auth();
        let e = msg(AuthorKind::User(STRANGER), Addressed::None, ChannelKind::GuildText);
        assert_eq!(route_message(&auth, &e), MessageRouting::Moderate);
    }

    // --- H-A17: channel-type default-deny ----------------------------------------

    #[test]
    fn command_plane_default_denies_unmodeled_channels() {
        let auth = owner_auth();
        // Even the owner, addressing the bot, gets no command on a forum/unknown
        // surface — it falls back to moderation data.
        for kind in [ChannelKind::Forum, ChannelKind::Other] {
            let e = msg(AuthorKind::User(OWNER), Addressed::Mention, kind);
            assert_eq!(route_message(&auth, &e), MessageRouting::Moderate);
        }
        // DMs and threads are allowed command surfaces.
        for kind in [ChannelKind::Dm, ChannelKind::Thread, ChannelKind::GuildText] {
            let e = msg(AuthorKind::User(OWNER), Addressed::Mention, kind);
            assert_eq!(route_message(&auth, &e), MessageRouting::Command { message_id: 9001 });
        }
    }

    // --- T15: interaction auth ----------------------------------------------------

    #[test]
    fn interactions_are_authorized_by_interacting_user_not_visibility() {
        let auth = owner_auth();
        let approve = |user| InteractionEvent {
            user,
            channel: 7,
            kind: InteractionKind::Button { custom_id: "approve:42".into() },
        };
        assert_eq!(route_interaction(&auth, &approve(OWNER)), InteractionDecision::Allow);
        // A non-owner who can SEE the approval-queue channel still cannot click approve.
        assert_eq!(route_interaction(&auth, &approve(STRANGER)), InteractionDecision::Deny);
    }

    // --- ADR-H9: per-message binding + owner-authored context filter --------------

    #[test]
    fn context_window_is_filtered_to_owner_authored_messages() {
        // The back-door the adversarial review flagged: a non-owner (or self) message
        // in a thread the bot reads must NOT become planner input.
        let auth = owner_auth();
        let mut bot_msg = msg(AuthorKind::User(BOT), Addressed::None, ChannelKind::Thread);
        bot_msg.is_bot_self = true;
        let thread = vec![
            msg(AuthorKind::User(OWNER), Addressed::None, ChannelKind::Thread),
            msg(AuthorKind::User(STRANGER), Addressed::None, ChannelKind::Thread),
            msg(AuthorKind::Webhook, Addressed::None, ChannelKind::Thread),
            bot_msg,
            msg(AuthorKind::User(OWNER), Addressed::Mention, ChannelKind::Thread),
        ];
        let ctx = owner_authored_context(&auth, &thread);
        assert_eq!(ctx.len(), 2, "only the two owner-authored messages survive");
        assert!(ctx
            .iter()
            .all(|m| matches!(m.author, AuthorKind::User(OWNER) if true)));
    }

    // --- T1 (S1 scope): the refusal is a fixed, injection-proof constant ----------

    #[test]
    fn refusal_is_the_exact_fixed_string() {
        assert_eq!(
            REFUSAL,
            "I don't work for you respectfully, I work for the company and Saul specifically."
        );
    }
}
