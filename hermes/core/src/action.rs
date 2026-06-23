//! The action-decision layer: turn a routed message into the concrete [`Action`] the
//! transport should carry out. This is the last pure step before Discord — the serenity
//! adapter maps `Action`s to API calls and decides nothing itself (ADR-H3).

use crate::cooldown::RefusalCooldown;
use crate::event::{AuthorKind, MessageEvent, MessageId};
use crate::guard::{route_message, MessageRouting, OwnerAuth};

/// What the transport should do about a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Reply with the fixed refusal string ([`crate::guard::REFUSAL`]).
    Refuse,
    /// Hand to the command plane, bound to this owner-authored message id (ADR-H9).
    /// In S1 the command plane just acknowledges; execution arrives in S2.
    Command { message_id: MessageId },
    /// Feed to the moderation plane as data. In S1 this is observe-only (no API effect).
    Moderate,
    /// Do nothing — a self-event, or a refusal suppressed by the per-user cooldown (T12).
    Ignore,
}

/// Decide the action for one message: route it through the guard, then apply the refusal
/// cooldown so a non-owner cannot turn the bot into a channel-flooding amplifier. The
/// cooldown is keyed on the author's user id when present; for webhook/system/integration
/// authors (no stable user id) it keys on the channel, so a webhook cannot flood either.
///
/// `now_ms` is a monotonic millisecond clock the daemon supplies (so the policy is
/// deterministic and testable).
pub fn decide(
    auth: &OwnerAuth,
    cooldown: &mut RefusalCooldown,
    ev: &MessageEvent,
    now_ms: u64,
) -> Action {
    match route_message(auth, ev) {
        MessageRouting::Drop(_) => Action::Ignore,
        MessageRouting::Command { message_id } => Action::Command { message_id },
        MessageRouting::Moderate => Action::Moderate,
        MessageRouting::Refuse => {
            let key = match ev.author {
                AuthorKind::User(id) => id,
                _ => ev.channel, // webhook/system/integration: rate-limit per channel
            };
            if cooldown.should_refuse(key, now_ms) {
                Action::Refuse
            } else {
                Action::Ignore
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Addressed, ChannelKind};

    const OWNER: u64 = 877642945996673126;
    const STRANGER: u64 = 222;

    fn ev(author: AuthorKind, addressed: Addressed) -> MessageEvent {
        MessageEvent {
            author,
            is_bot_self: false,
            channel: 7,
            channel_kind: ChannelKind::GuildText,
            message_id: 9001,
            content: "x".into(),
            addressed,
            edited: false,
        }
    }

    #[test]
    fn owner_addressed_becomes_a_bound_command() {
        let auth = OwnerAuth::new(OWNER);
        let mut cd = RefusalCooldown::new(10_000);
        let a = decide(&auth, &mut cd, &ev(AuthorKind::User(OWNER), Addressed::Mention), 0);
        assert_eq!(a, Action::Command { message_id: 9001 });
    }

    #[test]
    fn ambient_is_moderate_and_self_is_ignore() {
        let auth = OwnerAuth::new(OWNER);
        let mut cd = RefusalCooldown::new(10_000);
        assert_eq!(
            decide(&auth, &mut cd, &ev(AuthorKind::User(OWNER), Addressed::None), 0),
            Action::Moderate
        );
        let mut selfev = ev(AuthorKind::User(OWNER), Addressed::Mention);
        selfev.is_bot_self = true;
        assert_eq!(decide(&auth, &mut cd, &selfev, 0), Action::Ignore);
    }

    #[test]
    fn non_owner_refused_once_then_cooled_down() {
        let auth = OwnerAuth::new(OWNER);
        let mut cd = RefusalCooldown::new(10_000);
        let e = ev(AuthorKind::User(STRANGER), Addressed::Mention);
        assert_eq!(decide(&auth, &mut cd, &e, 0), Action::Refuse);
        assert_eq!(decide(&auth, &mut cd, &e, 1_000), Action::Ignore); // within window
        assert_eq!(decide(&auth, &mut cd, &e, 11_000), Action::Refuse); // window elapsed
    }

    #[test]
    fn webhook_refusal_is_rate_limited_per_channel() {
        // A webhook has no user id; the cooldown keys on the channel so it still can't
        // flood. Same channel within the window ⇒ suppressed.
        let auth = OwnerAuth::new(OWNER);
        let mut cd = RefusalCooldown::new(10_000);
        let w = ev(AuthorKind::Webhook, Addressed::Mention);
        assert_eq!(decide(&auth, &mut cd, &w, 0), Action::Refuse);
        assert_eq!(decide(&auth, &mut cd, &w, 500), Action::Ignore);
    }
}
