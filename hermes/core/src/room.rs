//! Research-room scoping (WP-S2.5, H-A16). *Where* Hermes will hold a rich, multi-turn
//! conversation — as opposed to merely being addressed — is deliberately narrow: a
//! **private** surface only. This closes the "public owner-id oracle": if Hermes reasoned
//! richly with the owner in a public channel, any observer could identify the owner by who
//! draws a thoughtful reply (everyone else gets the fixed refusal). Confining rich command
//! handling to private surfaces removes that signal — in public, an owner command is
//! treated as ambient (no rich reply), indistinguishable from the bot ignoring chatter.
//!
//! Pure (ADR-H11). The adapter supplies the one fact it can't derive from a single event —
//! whether the channel is a known agenda thread — from the [`crate::agenda::AgendaStore`].

use crate::event::{ChannelId, ChannelKind, MessageEvent};

/// The owner-configured boundary of the research room: the private research channel (and
/// whether DMs count as private). Default-deny: with nothing configured, only DMs are
/// private and there is no research channel.
#[derive(Debug, Clone, Default)]
pub struct RoomScope {
    /// The private `#hermes-research` channel id, if configured.
    pub research_channel: Option<ChannelId>,
    /// Whether DMs to the bot are treated as a private command surface. Default `true` —
    /// a DM is inherently one-to-one, so it is not a public oracle.
    pub allow_dms: bool,
}

impl RoomScope {
    /// Build from the configured research channel. DMs private by default.
    pub fn new(research_channel: Option<ChannelId>) -> Self {
        Self { research_channel, allow_dms: true }
    }
}

/// Whether `ev` arrived on a **private** command surface, given the room scope and whether
/// the channel is a known agenda thread. Private ⇒ rich command handling is allowed.
///
/// Private iff any of:
///   - a DM (and `allow_dms`), or
///   - the configured research channel, or
///   - a known agenda thread (a thread Hermes itself opened for an agenda).
///
/// Everything else is public — including the owner @mentioning the bot in a normal guild
/// channel, which is downgraded to ambient so it cannot become an owner-id oracle.
pub fn is_private_surface(ev: &MessageEvent, scope: &RoomScope, is_agenda_thread: bool) -> bool {
    if matches!(ev.channel_kind, ChannelKind::Dm) {
        return scope.allow_dms;
    }
    if let Some(research) = scope.research_channel {
        if ev.channel == research {
            return true;
        }
    }
    is_agenda_thread
}

/// Whether the owner just opened an **agenda** — a top-level post in the research channel
/// (not in a thread, not a DM). The adapter responds by opening a thread for it. A message
/// already inside an agenda thread continues that agenda instead (see
/// [`crate::agenda::AgendaStore::append_turn`]).
pub fn is_new_agenda_post(ev: &MessageEvent, scope: &RoomScope, is_agenda_thread: bool) -> bool {
    if is_agenda_thread {
        return false;
    }
    match scope.research_channel {
        Some(research) => {
            ev.channel == research && matches!(ev.channel_kind, ChannelKind::GuildText)
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Addressed, AuthorKind};

    fn ev(channel: ChannelId, kind: ChannelKind) -> MessageEvent {
        MessageEvent {
            author: AuthorKind::User(1),
            is_bot_self: false,
            channel,
            channel_kind: kind,
            message_id: 9,
            content: "hi".into(),
            addressed: Addressed::Mention,
            edited: false,
        }
    }

    #[test]
    fn dm_is_private_by_default() {
        let scope = RoomScope::new(None);
        assert!(is_private_surface(&ev(1, ChannelKind::Dm), &scope, false));
    }

    #[test]
    fn dm_can_be_disallowed() {
        let scope = RoomScope { research_channel: None, allow_dms: false };
        assert!(!is_private_surface(&ev(1, ChannelKind::Dm), &scope, false));
    }

    #[test]
    fn research_channel_is_private_other_guild_channels_are_not() {
        let scope = RoomScope::new(Some(555));
        assert!(is_private_surface(&ev(555, ChannelKind::GuildText), &scope, false));
        // A different public guild channel is NOT private — no owner-id oracle here.
        assert!(!is_private_surface(&ev(777, ChannelKind::GuildText), &scope, false));
    }

    #[test]
    fn known_agenda_thread_is_private() {
        let scope = RoomScope::new(Some(555));
        assert!(is_private_surface(&ev(888, ChannelKind::Thread), &scope, true));
        // An unknown thread is not automatically private.
        assert!(!is_private_surface(&ev(888, ChannelKind::Thread), &scope, false));
    }

    #[test]
    fn new_agenda_post_only_at_research_channel_top_level() {
        let scope = RoomScope::new(Some(555));
        assert!(is_new_agenda_post(&ev(555, ChannelKind::GuildText), &scope, false));
        // In an agenda thread → continue, not open.
        assert!(!is_new_agenda_post(&ev(555, ChannelKind::Thread), &scope, true));
        // Not the research channel → not an agenda post.
        assert!(!is_new_agenda_post(&ev(777, ChannelKind::GuildText), &scope, false));
        // No research channel configured → never opens agendas from guild posts.
        assert!(!is_new_agenda_post(&ev(555, ChannelKind::GuildText), &RoomScope::new(None), false));
    }
}
