//! `hermes-core` — the transport-agnostic decision core for Hermes (HERMES-L-S1).
//!
//! This crate is the security heart of Hermes: the **ingress guard** and the
//! **two-plane** routing that make Hermes serve exactly one principal on the command
//! plane (the owner) while still moderating everyone. It is pure logic over typed
//! events — no Discord, no async, no I/O — so every boundary property is exhaustively
//! unit-testable. The serenity gateway adapter (`hermes-discord`, a later WP) maps
//! transport events onto these types and **makes no decisions of its own** (ADR-H3).
//!
//! The properties this crate guarantees, each tied to a threat row in
//! `.agentile/planset/hermes/06_THREAT_MODEL.md`:
//!
//! - **Owner-only command plane, fail-closed** — only `OWNER_DISCORD_ID` reaches the
//!   command plane; an unset/malformed owner id serves *no one* ([`guard::OwnerAuth`]).
//! - **T2** owner impersonation — authorization is by immutable user id; webhooks /
//!   system / integration authors can never be the owner.
//! - **T12** refusal-spam — the refusal is a fixed const, sent only when addressed,
//!   rate-limited per user ([`cooldown::RefusalCooldown`]).
//! - **T15** interaction auth — buttons/slash re-run the guard on the *interacting*
//!   user id, never channel visibility ([`guard::route_interaction`]).
//! - **T17** self-event loop — `is_bot_self` events are dropped before any plane.
//! - **ADR-H9** per-message binding — a command binds to one owner-authored message id;
//!   the planner context window is filtered to owner-authored messages
//!   ([`guard::owner_authored_context`]).

pub mod action;
pub mod cooldown;
pub mod event;
pub mod guard;
pub mod principal;

pub use action::{decide, Action};
pub use cooldown::RefusalCooldown;
pub use event::{
    Addressed, AuthorKind, ChannelId, ChannelKind, InteractionEvent, InteractionKind, MessageEvent,
    MessageId, UserId,
};
pub use guard::{
    owner_authored_context, route_interaction, route_message, DropReason, InteractionDecision,
    MessageRouting, OwnerAuth, REFUSAL,
};
pub use principal::Principal;
