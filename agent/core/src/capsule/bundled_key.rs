//! Bundled-tier publisher public key — CIT-AGENT-3e.
//!
//! The runtime ships the PUBLIC key of the bundled-tier capsule publisher so it
//! can verify the in-tree `.cps` fleet through
//! [`crate::capsule::Capsule::from_archive_verified`] with no env override. The
//! matching PRIVATE key is held off-tree — `.capsule-signing-key.env` (gitignored)
//! for staging, an HSM-resident key for production — and is never embedded here.
//!
//! Rotating to the production key is a one-line change: replace the bytes below
//! with the HSM key's public half (and re-pack the fleet with `cit-capsule-pack`
//! pointed at that key). The verification wiring is identical.

use crate::capsule::tiers::StaticKeyRegistry;

/// Ed25519 public key (32 bytes) of the bundled-tier publisher. STAGING key,
/// generated 2026-06-06 by `cit-capsule-pack`; swap for the HSM key in prod.
pub const BUNDLED_PUBLISHER_KEY: [u8; 32] = [
    0x4a, 0x4a, 0x0c, 0x85, 0x78, 0x3c, 0xae, 0x8b, 0x5b, 0x75, 0x2a, 0x83, 0xd9, 0x03, 0x65, 0x95,
    0x8e, 0xd1, 0x9d, 0xc1, 0xa6, 0xe1, 0x1f, 0xf6, 0xd9, 0xe2, 0x16, 0x78, 0x7e, 0x6a, 0xa7, 0x0a,
];

/// The capsule-verification registry the dispatcher uses: the bundled-tier key
/// is trusted; the managed tier is not yet provisioned.
pub fn registry() -> StaticKeyRegistry {
    StaticKeyRegistry { bundled: Some(BUNDLED_PUBLISHER_KEY), managed: None }
}
