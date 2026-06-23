//! Pure classification helpers: extract the primitives the guard needs from a Discord
//! event. Kept free of serenity types so they are unit-testable — the serenity handler
//! pulls the primitives off the gateway structs and calls these.

use hermes_core::event::{Addressed, AuthorKind, ChannelKind};

/// Classify a message author. Returns the [`AuthorKind`] and whether the author is the
/// bot itself (which the guard drops, T17). A webhook is never a real user — it carries
/// an attacker-chosen display name but no authentic identity (T2).
pub fn classify_author(is_webhook: bool, author_id: u64, bot_id: u64) -> (AuthorKind, bool) {
    if is_webhook {
        (AuthorKind::Webhook, false)
    } else {
        (AuthorKind::User(author_id), author_id == bot_id)
    }
}

/// Classify the channel surface. No guild ⇒ DM; a thread is a thread; otherwise a guild
/// text channel. (Forums and other surfaces would map to [`ChannelKind::Other`] and
/// default-deny the command plane; serenity thread detection is refined as we wire it.)
pub fn classify_channel(in_guild: bool, is_thread: bool) -> ChannelKind {
    match (in_guild, is_thread) {
        (false, _) => ChannelKind::Dm,
        (true, true) => ChannelKind::Thread,
        (true, false) => ChannelKind::GuildText,
    }
}

/// Classify how the message addressed the bot. A DM is inherently direct; otherwise a
/// reply to the bot beats a mention beats nothing. Only an addressed message can be a
/// command or draw a refusal (T12).
pub fn classify_addressed(is_dm: bool, mentions_bot: bool, replies_to_bot: bool) -> Addressed {
    if is_dm {
        Addressed::Direct
    } else if replies_to_bot {
        Addressed::Reply
    } else if mentions_bot {
        Addressed::Mention
    } else {
        Addressed::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOT: u64 = 1518794917349031976;
    const OWNER: u64 = 877642945996673126;

    #[test]
    fn author_classification() {
        assert_eq!(classify_author(false, OWNER, BOT), (AuthorKind::User(OWNER), false));
        assert_eq!(classify_author(false, BOT, BOT), (AuthorKind::User(BOT), true)); // self
        assert_eq!(classify_author(true, OWNER, BOT), (AuthorKind::Webhook, false)); // webhook
    }

    #[test]
    fn channel_classification() {
        assert_eq!(classify_channel(false, false), ChannelKind::Dm);
        assert_eq!(classify_channel(true, false), ChannelKind::GuildText);
        assert_eq!(classify_channel(true, true), ChannelKind::Thread);
    }

    #[test]
    fn addressed_classification() {
        assert_eq!(classify_addressed(true, false, false), Addressed::Direct);
        assert_eq!(classify_addressed(false, false, true), Addressed::Reply);
        assert_eq!(classify_addressed(false, true, false), Addressed::Mention);
        assert_eq!(classify_addressed(false, false, false), Addressed::None);
        // reply outranks mention
        assert_eq!(classify_addressed(false, true, true), Addressed::Reply);
    }
}
