//! Confirming that one committer anchored a value, on either `AnchorRegistry` version.
//!
//! `isAnchored(root)` only says that *someone* anchored `root`. A client that wants to know its
//! own anchor landed must ask about its own address, or a stranger who sends the same value first
//! would make an unsent (or failed) anchor look confirmed.
//!
//! - The next registry version (HUP-S7.1 redeploy) keeps one record per `(committer, root)` and
//!   answers `isAnchoredBy(committer, root)` directly.
//! - The deployed version keeps only the first record of each root and has no `isAnchoredBy`: the
//!   call reverts (no such function). There the committer of the first record (`getAnchor(root)`)
//!   must be the client. A client whose identical value was sent second by someone else is told
//!   "not anchored by you", which is the truth on that version: its transaction reverted.
//!
//! [`OwnAnchorCheck`] is the read sequence as a small state machine with no I/O, so a client can
//! drive it over any transport (citrate-agent-core's `AnchorRegistryClient` drives it over
//! JSON-RPC `eth_call`, and the anvil test runs it against both registry versions):
//!
//! 1. `isAnchored(root)`: `false` ends the check with `false` on both versions.
//! 2. `isAnchoredBy(committer, root)`: a `bool` ends the check (next version); a revert means the
//!    deployed version.
//! 3. `getAnchor(root)` (deployed version only): the record must be for `root`, and the answer is
//!    whether its committer is `committer`.
//!
//! Any other answer (a revert where both versions return data, a return value of the wrong
//! shape) is an error, never a `true`.

use crate::error::{Error, Result};

/// `keccak256("isAnchoredBy(address,bytes32)")[..4]` (next registry version only).
pub const IS_ANCHORED_BY_SELECTOR: [u8; 4] = [0x09, 0x86, 0x64, 0x55];
/// `keccak256("getAnchor(bytes32)")[..4]`: the first record of a root (both versions).
pub const GET_ANCHOR_SELECTOR: [u8; 4] = [0x7f, 0xeb, 0x51, 0xd9];

/// `isAnchoredBy(committer, root)` calldata (68 bytes).
pub fn is_anchored_by_calldata(committer: &[u8; 20], root: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(68);
    out.extend_from_slice(&IS_ANCHORED_BY_SELECTOR);
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(committer);
    out.extend_from_slice(root);
    out
}

/// `getAnchor(root)` calldata (36 bytes).
pub fn get_anchor_calldata(root: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(&GET_ANCHOR_SELECTOR);
    out.extend_from_slice(root);
    out
}

/// Decode an ABI `bool` return: exactly one word, `0` or `1`.
pub fn decode_bool(ret: &[u8]) -> Result<bool> {
    if ret.len() != 32 || ret[..31].iter().any(|b| *b != 0) || ret[31] > 1 {
        return Err(Error::Registry(format!(
            "expected an ABI bool, got {} bytes",
            ret.len()
        )));
    }
    Ok(ret[31] == 1)
}

/// The committer of an `Anchor` struct returned by `getAnchor` / `getAnchorBy`
/// (`uint8 kind, bytes32 root, address committer, uint256 block_number, uint256 timestamp`),
/// after checking that the record is for `root`.
pub fn decode_anchor_committer(ret: &[u8], root: &[u8; 32]) -> Result<[u8; 20]> {
    if ret.len() != 5 * 32 {
        return Err(Error::Registry(format!(
            "expected an Anchor (160 bytes), got {} bytes",
            ret.len()
        )));
    }
    if ret[..31].iter().any(|b| *b != 0) || ret[31] > 2 {
        return Err(Error::Registry(
            "the anchor kind is not an AnchorKind".into(),
        ));
    }
    if &ret[32..64] != root {
        return Err(Error::Registry(
            "the registry returned the record of a different value".into(),
        ));
    }
    if ret[64..76].iter().any(|b| *b != 0) {
        return Err(Error::Registry("the committer is not an address".into()));
    }
    let mut c = [0u8; 20];
    c.copy_from_slice(&ret[76..96]);
    Ok(c)
}

/// What one `eth_call` to the registry came back with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryAnswer {
    /// The call returned these bytes.
    Returned(Vec<u8>),
    /// The call reverted (for example: no such function on this registry version).
    Reverted,
}

/// The next step of an [`OwnAnchorCheck`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckStep {
    /// Make this read-only call to the registry and pass the answer to [`OwnAnchorCheck::answer`].
    Call(Vec<u8>),
    /// The check is over: did `committer` anchor `root`?
    Done(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    AnyCommitter,
    ByCommitter,
    FirstRecord,
    Finished,
}

/// Did `committer` anchor `root`? See the module docs for the read sequence.
#[derive(Debug, Clone)]
pub struct OwnAnchorCheck {
    committer: [u8; 20],
    root: [u8; 32],
    stage: Stage,
}

impl OwnAnchorCheck {
    /// Start a check. The first call is `isAnchored(root)`.
    pub fn new(committer: [u8; 20], root: [u8; 32]) -> (Self, CheckStep) {
        let check = Self {
            committer,
            root,
            stage: Stage::AnyCommitter,
        };
        let first = CheckStep::Call(crate::calldata::is_anchored_calldata(&root));
        (check, first)
    }

    /// Feed the answer to the last [`CheckStep::Call`].
    pub fn answer(&mut self, a: RegistryAnswer) -> Result<CheckStep> {
        let step = match (self.stage, a) {
            (Stage::AnyCommitter, RegistryAnswer::Returned(r)) => {
                if decode_bool(&r)? {
                    self.stage = Stage::ByCommitter;
                    CheckStep::Call(is_anchored_by_calldata(&self.committer, &self.root))
                } else {
                    CheckStep::Done(false)
                }
            }
            (Stage::AnyCommitter, RegistryAnswer::Reverted) => {
                return Err(Error::Registry(
                    "isAnchored reverted: the address is not an AnchorRegistry".into(),
                ))
            }
            (Stage::ByCommitter, RegistryAnswer::Returned(r)) => CheckStep::Done(decode_bool(&r)?),
            (Stage::ByCommitter, RegistryAnswer::Reverted) => {
                // The deployed version: no isAnchoredBy. Its single record names the committer.
                self.stage = Stage::FirstRecord;
                CheckStep::Call(get_anchor_calldata(&self.root))
            }
            (Stage::FirstRecord, RegistryAnswer::Returned(r)) => {
                CheckStep::Done(decode_anchor_committer(&r, &self.root)? == self.committer)
            }
            (Stage::FirstRecord, RegistryAnswer::Reverted) => {
                return Err(Error::Registry(
                    "getAnchor reverted for a value isAnchored reported".into(),
                ))
            }
            (Stage::Finished, _) => {
                return Err(Error::Registry("the check is already over".into()))
            }
        };
        if matches!(step, CheckStep::Done(_)) {
            self.stage = Stage::Finished;
        }
        Ok(step)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Keccak256};

    const ME: [u8; 20] = [0xaa; 20];
    const STRANGER: [u8; 20] = [0xbb; 20];
    const ROOT: [u8; 32] = [0x11; 32];

    fn word_bool(b: bool) -> Vec<u8> {
        let mut w = vec![0u8; 32];
        w[31] = u8::from(b);
        w
    }

    fn anchor_struct(committer: &[u8; 20], root: &[u8; 32]) -> Vec<u8> {
        let mut out = vec![0u8; 160];
        out[31] = 2;
        out[32..64].copy_from_slice(root);
        out[76..96].copy_from_slice(committer);
        out[127] = 7; // block_number
        out[159] = 9; // timestamp
        out
    }

    fn run(committer: [u8; 20], answers: Vec<RegistryAnswer>) -> Result<(bool, Vec<Vec<u8>>)> {
        let (mut check, mut step) = OwnAnchorCheck::new(committer, ROOT);
        let mut calls = Vec::new();
        let mut answers = answers.into_iter();
        loop {
            match step {
                CheckStep::Done(v) => return Ok((v, calls)),
                CheckStep::Call(data) => {
                    calls.push(data);
                    let a = answers
                        .next()
                        .ok_or_else(|| Error::Registry("test ran out of answers".into()))?;
                    step = check.answer(a)?;
                }
            }
        }
    }

    #[test]
    fn selectors_are_keccak_of_the_signatures() {
        let k: [u8; 32] = Keccak256::digest(b"isAnchoredBy(address,bytes32)").into();
        assert_eq!(IS_ANCHORED_BY_SELECTOR, [k[0], k[1], k[2], k[3]]);
        let k: [u8; 32] = Keccak256::digest(b"getAnchor(bytes32)").into();
        assert_eq!(GET_ANCHOR_SELECTOR, [k[0], k[1], k[2], k[3]]);
        // `cast sig` (cast 1.5.1).
        assert_eq!(hex::encode(IS_ANCHORED_BY_SELECTOR), "09866455");
        assert_eq!(hex::encode(GET_ANCHOR_SELECTOR), "7feb51d9");
    }

    #[test]
    fn calldata_layout_matches_cast() {
        // `cast calldata "isAnchoredBy(address,bytes32)" 0xaaaa..aa 0x1111..11`.
        assert_eq!(
            hex::encode(is_anchored_by_calldata(&ME, &ROOT)),
            format!(
                "09866455{}{}{}",
                "00".repeat(12),
                "aa".repeat(20),
                "11".repeat(32)
            )
        );
        assert_eq!(
            hex::encode(get_anchor_calldata(&ROOT)),
            format!("7feb51d9{}", "11".repeat(32))
        );
    }

    #[test]
    fn unanchored_value_is_false_after_one_read() {
        let (v, calls) = run(ME, vec![RegistryAnswer::Returned(word_bool(false))]).unwrap();
        assert!(!v);
        assert_eq!(calls, vec![crate::calldata::is_anchored_calldata(&ROOT)]);
    }

    #[test]
    fn next_version_answers_by_committer() {
        let (v, calls) = run(
            ME,
            vec![
                RegistryAnswer::Returned(word_bool(true)),
                RegistryAnswer::Returned(word_bool(true)),
            ],
        )
        .unwrap();
        assert!(v);
        assert_eq!(calls[1], is_anchored_by_calldata(&ME, &ROOT));
        // Anchored by someone, but not by me: false, even though isAnchored is true.
        let (v, _) = run(
            ME,
            vec![
                RegistryAnswer::Returned(word_bool(true)),
                RegistryAnswer::Returned(word_bool(false)),
            ],
        )
        .unwrap();
        assert!(!v);
    }

    #[test]
    fn deployed_version_reads_the_first_committer() {
        let mine = vec![
            RegistryAnswer::Returned(word_bool(true)),
            RegistryAnswer::Reverted,
            RegistryAnswer::Returned(anchor_struct(&ME, &ROOT)),
        ];
        let (v, calls) = run(ME, mine).unwrap();
        assert!(v);
        assert_eq!(calls[2], get_anchor_calldata(&ROOT));
        // A stranger sent the same value first: not anchored by me.
        let theirs = vec![
            RegistryAnswer::Returned(word_bool(true)),
            RegistryAnswer::Reverted,
            RegistryAnswer::Returned(anchor_struct(&STRANGER, &ROOT)),
        ];
        assert!(!run(ME, theirs).unwrap().0);
    }

    #[test]
    fn odd_answers_are_errors_never_true() {
        // isAnchored reverting: not a registry.
        assert!(run(ME, vec![RegistryAnswer::Reverted]).is_err());
        // A malformed bool.
        assert!(run(ME, vec![RegistryAnswer::Returned(vec![1])]).is_err());
        let mut two = word_bool(true);
        two[31] = 2;
        assert!(run(ME, vec![RegistryAnswer::Returned(two)]).is_err());
        // getAnchor reverting after isAnchored said true.
        assert!(run(
            ME,
            vec![
                RegistryAnswer::Returned(word_bool(true)),
                RegistryAnswer::Reverted,
                RegistryAnswer::Reverted
            ]
        )
        .is_err());
        // The record of a different value, or a short answer.
        let other = anchor_struct(&ME, &[0x22; 32]);
        assert!(run(
            ME,
            vec![
                RegistryAnswer::Returned(word_bool(true)),
                RegistryAnswer::Reverted,
                RegistryAnswer::Returned(other)
            ]
        )
        .is_err());
        assert!(run(
            ME,
            vec![
                RegistryAnswer::Returned(word_bool(true)),
                RegistryAnswer::Reverted,
                RegistryAnswer::Returned(vec![0u8; 96])
            ]
        )
        .is_err());
    }

    #[test]
    fn dirty_committer_word_is_refused() {
        let mut a = anchor_struct(&ME, &ROOT);
        a[64] = 1;
        assert!(decode_anchor_committer(&a, &ROOT).is_err());
        let mut k = anchor_struct(&ME, &ROOT);
        k[31] = 3;
        assert!(decode_anchor_committer(&k, &ROOT).is_err());
        assert_eq!(
            decode_anchor_committer(&anchor_struct(&ME, &ROOT), &ROOT).unwrap(),
            ME
        );
    }

    #[test]
    fn answering_after_done_is_an_error() {
        let (mut check, _) = OwnAnchorCheck::new(ME, ROOT);
        assert_eq!(
            check
                .answer(RegistryAnswer::Returned(word_bool(false)))
                .unwrap(),
            CheckStep::Done(false)
        );
        assert!(check
            .answer(RegistryAnswer::Returned(word_bool(true)))
            .is_err());
    }
}
