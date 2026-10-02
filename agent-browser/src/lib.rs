//! # citrate-agent-browser: Hermes's browser worker (HUP-S5.1 + S5.6)
//!
//! Planset `2026-09-30-hermes-upskill`, epic E5 "Eyes on the web" (US-5.1 "Watch it browse").
//!
//! - [`chromium`]: find a Chromium (the managed one at `CITRATE_BROWSER_CHROMIUM`, else a system
//!   one), launch it headless with a throwaway profile, or locate the member's own Chrome on a
//!   loopback remote-debugging port. When none exists the status says "not installed"; installing
//!   the managed one is the component updater's job (HUP-S5.5).
//! - [`cdp`]: a small blocking Chrome DevTools Protocol client, loopback only.
//! - [`snapshot`]: ref-indexed accessibility snapshots (`[e3] button "Continue"`).
//! - [`service`]: the worker: navigate, snapshot, act by ref, screenshot, a screencast for the
//!   Browser pop-out ([`frames`]), Stop, and attach-to-Chrome.
//! - [`scope`]: attach-mode origin scoping: per-origin, per-session consent; banking, email and
//!   health origins excluded by default (`data/sensitive-origins.toml`).
//! - [`approvals`]: after taint, each effectful browser action waits for the member's decision.
//! - [`tools`]: the four `browser_*` tool specs and their host.
//!
//! Every page is untrusted: tool output is fenced as data and taints the session. The worker is
//! keyless and never signs; nothing here touches a wallet. Off unless the sidecar is started with
//! `CITRATE_HERMES_BROWSER=1`.

pub mod approvals;
pub mod cdp;
pub mod chromium;
pub mod frames;
pub mod scope;
pub mod service;
pub mod snapshot;
pub mod tools;

pub use service::{BrowserConfig, BrowserError, BrowserService, BrowserStatus};
