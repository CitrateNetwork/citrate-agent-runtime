//! HUP-S7.3 nightly anchor batch: behaviour tests (tree, batch, proofs, calldata, ledger, plan).

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use citrate_agent_anchor::{
    anchor_calldata, build_day_batch, decode_anchor_calldata, is_anchored_calldata, pending_days,
    plan_day, prove, verify_proof, verify_record_proof, AnchorKind, AnchorLedger, BatchHeader,
    EntryStatus, Error, NightlyPlan, RecordOutcome, Tree, ANCHOR_SELECTOR, ANCHOR_SIGNATURE,
    CITRATE_CHAIN_ID, COMMITMENT_DOMAIN, IS_ANCHORED_SELECTOR,
};
use citrate_agent_records::merkle::{self, RetainedLeaf};
use citrate_agent_records::{
    read, Actor, Clock, Decision, DecisionEvent, DecisionLog, HicTier, LogConfig,
};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

const DAY: u64 = 86_400_000;

// ---------------------------------------------------------------------------------------------
// helpers

fn h(i: u64) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(b"leaf-data");
    s.update(i.to_be_bytes());
    s.finalize().into()
}

fn leaves(day: u64, first_seq: u64, n: u64) -> Vec<RetainedLeaf> {
    (0..n)
        .map(|i| RetainedLeaf {
            seq: first_seq + i,
            ts_ms: day * DAY + 1000 * i,
            hash: h(first_seq + i),
        })
        .collect()
}

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn ev(subject: &str) -> DecisionEvent {
    DecisionEvent {
        tier: HicTier::Hic1,
        kind: "tx".into(),
        subject: subject.into(),
        decision: Decision::Denied,
        reason: "test".into(),
        evidence: vec![],
    }
}

/// A log with `per_day[i]` records on day `base + i`.
fn log_with_days(dir: &Path, base: u64, per_day: &[u64], cfg: LogConfig) -> Arc<TestClock> {
    let c = Arc::new(TestClock(AtomicU64::new(base * DAY)));
    let (log, _) = DecisionLog::open_with_clock(dir, cfg, c.clone()).unwrap();
    for (i, n) in per_day.iter().enumerate() {
        c.0.store((base + i as u64) * DAY + 5, Ordering::SeqCst);
        for k in 0..*n {
            log.record_decision(Actor::member("m1"), ev(&format!("d{i}-r{k}")))
                .unwrap();
        }
    }
    c
}

// ---------------------------------------------------------------------------------------------
// tree

#[test]
fn tree_matches_the_rfc6962_reference_for_every_size_up_to_70() {
    for n in 1..=70u64 {
        let data: Vec<[u8; 32]> = (0..n).map(h).collect();
        let t = Tree::build(&data).expect("non-empty");
        assert_eq!(t.size(), n);
        assert_eq!(Some(t.root()), merkle::merkle_root(&data), "root n={n}");
        for i in 0..n as usize {
            let p = t.path(i).expect("in range");
            assert_eq!(p, merkle::audit_path(&data, i), "path n={n} i={i}");
            assert!(merkle::verify_path(&data[i], i as u64, n, &p, &t.root()));
        }
        assert!(t.path(n as usize).is_none());
    }
}

#[test]
fn tree_of_nothing_is_none_and_of_one_is_the_leaf_hash() {
    assert!(Tree::build(&[]).is_none());
    let t = Tree::build(&[h(7)]).expect("one");
    assert_eq!(t.root(), merkle::leaf_hash(&h(7)));
    assert_eq!(t.path(0), Some(vec![]));
}

#[test]
fn odd_sizes_promote_the_last_node_instead_of_duplicating_it() {
    // [a, b, c] must not equal [a, b, c, c] (the duplicated-leaf ambiguity).
    let three: Vec<[u8; 32]> = vec![h(1), h(2), h(3)];
    let four: Vec<[u8; 32]> = vec![h(1), h(2), h(3), h(3)];
    let (Some(t3), Some(t4)) = (Tree::build(&three), Tree::build(&four)) else {
        panic!("non-empty")
    };
    assert_ne!(t3.root(), t4.root());
    let ab = merkle::node_hash(&merkle::leaf_hash(&h(1)), &merkle::leaf_hash(&h(2)));
    assert_eq!(t3.root(), merkle::node_hash(&ab, &merkle::leaf_hash(&h(3))));
}

// ---------------------------------------------------------------------------------------------
// batch + proofs

#[test]
fn empty_day_builds_no_batch() {
    assert!(build_day_batch(5, &[]).unwrap().is_none());
    // Records of other days only.
    assert!(build_day_batch(5, &leaves(4, 0, 3)).unwrap().is_none());
}

#[test]
fn batch_covers_exactly_the_records_of_its_day() {
    let mut all = leaves(9, 0, 3);
    all.extend(leaves(10, 3, 5));
    all.extend(leaves(11, 8, 2));
    let b = build_day_batch(10, &all).unwrap().expect("batch");
    let hd = b.header();
    assert_eq!((hd.day, hd.first_seq, hd.last_seq, hd.count), (10, 3, 7, 5));
    let data: Vec<[u8; 32]> = (3..8).map(h).collect();
    assert_eq!(Some(hd.tree_root), merkle::merkle_root(&data));
    assert!(
        b.proof(2).is_none(),
        "day 9 record is not in the day 10 batch"
    );
    assert!(
        b.proof(8).is_none(),
        "day 11 record is not in the day 10 batch"
    );
}

#[test]
fn every_record_of_the_batch_has_a_valid_proof_for_0_1_odd_even_counts() {
    for n in [1u64, 2, 3, 4, 5, 7, 8, 9, 16, 17, 33] {
        let b = build_day_batch(3, &leaves(3, 100, n))
            .unwrap()
            .expect("batch");
        let root = b.commitment();
        let proofs = b.proofs();
        assert_eq!(proofs.len() as u64, n);
        for p in &proofs {
            assert!(verify_proof(p, &root), "n={n} seq={}", p.seq);
        }
    }
}

#[test]
fn batch_is_deterministic() {
    let a = build_day_batch(2, &leaves(2, 0, 13)).unwrap().expect("a");
    let b = build_day_batch(2, &leaves(2, 0, 13)).unwrap().expect("b");
    assert_eq!(a.header(), b.header());
    assert_eq!(a.commitment(), b.commitment());
    assert_eq!(a.proofs(), b.proofs());
}

#[test]
fn batch_refuses_out_of_order_or_gapped_seqs() {
    let mut gap = leaves(4, 0, 4);
    gap.remove(2);
    assert!(matches!(
        build_day_batch(4, &gap),
        Err(Error::SeqGap { day: 4, .. })
    ));
    let mut rev = leaves(4, 0, 4);
    rev.swap(0, 1);
    assert!(matches!(
        build_day_batch(4, &rev),
        Err(Error::SeqGap { day: 4, .. })
    ));
}

#[test]
fn commitment_binds_the_day_the_range_and_the_tree_root() {
    let b = build_day_batch(6, &leaves(6, 10, 4))
        .unwrap()
        .expect("batch");
    let hd = b.header().clone();
    // Documented formula.
    let mut s = Sha256::new();
    s.update(COMMITMENT_DOMAIN);
    s.update(hd.v.to_be_bytes());
    s.update(hd.day.to_be_bytes());
    s.update(hd.first_seq.to_be_bytes());
    s.update(hd.last_seq.to_be_bytes());
    s.update(hd.count.to_be_bytes());
    s.update(hd.tree_root);
    let want: [u8; 32] = s.finalize().into();
    assert_eq!(b.commitment(), want);
    assert_eq!(COMMITMENT_DOMAIN, b"citrate.agent-anchor.nightly.v1\n");
    // Changing any header field changes the commitment.
    for f in 0..5 {
        let mut x = hd.clone();
        match f {
            0 => x.day += 1,
            1 => x.first_seq += 1,
            2 => x.last_seq += 1,
            3 => x.count += 1,
            _ => x.tree_root[0] ^= 1,
        }
        assert_ne!(x.commitment(), want, "field {f}");
    }
    // The commitment is never the bare tree root.
    assert_ne!(b.commitment(), hd.tree_root);
}

#[test]
fn proof_fails_for_a_wrong_root_leaf_index_seq_or_path() {
    let b = build_day_batch(1, &leaves(1, 0, 6))
        .unwrap()
        .expect("batch");
    let root = b.commitment();
    let p = b.proof(3).expect("proof");
    assert!(verify_proof(&p, &root));

    let mut wrong_root = root;
    wrong_root[31] ^= 1;
    assert!(!verify_proof(&p, &wrong_root));
    // The bare tree root is not an anchored value.
    assert!(!verify_proof(&p, &b.header().tree_root));

    let mut x = p.clone();
    x.record_hash[0] ^= 1;
    assert!(!verify_proof(&x, &root), "edited record hash");

    let mut x = p.clone();
    x.seq += 1;
    assert!(!verify_proof(&x, &root), "seq not bound to its position");

    let mut x = p.clone();
    x.leaf_index += 1;
    x.seq += 1;
    assert!(!verify_proof(&x, &root), "moved leaf");

    let mut x = p.clone();
    x.path.pop();
    assert!(!verify_proof(&x, &root), "short path");

    let mut x = p.clone();
    x.path.push([0u8; 32]);
    assert!(!verify_proof(&x, &root), "long path");

    let mut x = p.clone();
    x.header.count = 99;
    assert!(!verify_proof(&x, &root), "header changed");

    let mut x = p.clone();
    x.leaf_index = 6;
    x.seq = 6;
    assert!(!verify_proof(&x, &root), "index out of range");
}

#[test]
fn proof_round_trips_through_json() {
    let b = build_day_batch(1, &leaves(1, 0, 5))
        .unwrap()
        .expect("batch");
    let p = b.proof(4).expect("proof");
    let s = serde_json::to_string(&p).unwrap();
    assert!(
        s.contains(&hex::encode(p.record_hash)),
        "hashes are hex in JSON"
    );
    let back = serde_json::from_str(&s).unwrap();
    assert_eq!(p, back);
    let hd: BatchHeader =
        serde_json::from_str(&serde_json::to_string(b.header()).unwrap()).unwrap();
    assert_eq!(&hd, b.header());
}

// ---------------------------------------------------------------------------------------------
// calldata (AnchorRegistry, citrate-chain contracts/src/cit_agent/AnchorRegistry.sol)

#[test]
fn selector_is_keccak_of_the_solidity_signature_and_matches_forge() {
    assert_eq!(ANCHOR_SIGNATURE, "anchor(uint8,bytes32)");
    let k: [u8; 32] = Keccak256::digest(ANCHOR_SIGNATURE.as_bytes()).into();
    assert_eq!(ANCHOR_SELECTOR, [k[0], k[1], k[2], k[3]]);
    // Pinned from `forge inspect AnchorRegistry methodIdentifiers` (forge 1.5.1).
    assert_eq!(hex::encode(ANCHOR_SELECTOR), "9e621f4c");
    let k: [u8; 32] = Keccak256::digest(b"isAnchored(bytes32)").into();
    assert_eq!(IS_ANCHORED_SELECTOR, [k[0], k[1], k[2], k[3]]);
    assert_eq!(hex::encode(IS_ANCHORED_SELECTOR), "4f0b5801");
}

#[test]
fn anchor_kind_matches_the_solidity_enum_order() {
    // enum AnchorKind { PerCapsule, PerApproval, NightlyMerkle }
    assert_eq!(AnchorKind::PerCapsule as u8, 0);
    assert_eq!(AnchorKind::PerApproval as u8, 1);
    assert_eq!(AnchorKind::NightlyMerkle as u8, 2);
}

#[test]
fn nightly_calldata_matches_cast() {
    let root = [0x11u8; 32];
    let data = anchor_calldata(AnchorKind::NightlyMerkle, &root);
    // `cast calldata "anchor(uint8,bytes32)" 2 0x1111..11` (cast 1.5.1).
    assert_eq!(
        hex::encode(&data),
        "9e621f4c\
         0000000000000000000000000000000000000000000000000000000000000002\
         1111111111111111111111111111111111111111111111111111111111111111"
    );
    assert_eq!(data.len(), 68);
    assert_eq!(
        decode_anchor_calldata(&data).unwrap(),
        (AnchorKind::NightlyMerkle, root)
    );
    let q = is_anchored_calldata(&root);
    assert_eq!(&q[..4], &IS_ANCHORED_SELECTOR);
    assert_eq!(&q[4..], &root);
}

#[test]
fn decode_refuses_malformed_calldata() {
    let root = [0x22u8; 32];
    let good = anchor_calldata(AnchorKind::NightlyMerkle, &root);
    assert!(decode_anchor_calldata(&good[..67]).is_err(), "short");
    let mut x = good.clone();
    x[0] ^= 1;
    assert!(decode_anchor_calldata(&x).is_err(), "selector");
    let mut x = good.clone();
    x[4 + 31] = 3;
    assert!(decode_anchor_calldata(&x).is_err(), "enum out of range");
    let mut x = good.clone();
    x[4] = 1;
    assert!(decode_anchor_calldata(&x).is_err(), "dirty high bytes");
    let mut x = good;
    x.push(0);
    assert!(decode_anchor_calldata(&x).is_err(), "trailing bytes");
}

// ---------------------------------------------------------------------------------------------
// ledger

#[test]
fn ledger_records_a_day_once_and_refuses_a_different_root() {
    let d = tempfile::tempdir().unwrap();
    let ledger = AnchorLedger::open(d.path()).unwrap();
    let b = build_day_batch(3, &leaves(3, 0, 4))
        .unwrap()
        .expect("batch");
    assert_eq!(
        ledger.record_batched(b.header(), 1).unwrap(),
        RecordOutcome::New
    );
    assert_eq!(
        ledger.record_batched(b.header(), 2).unwrap(),
        RecordOutcome::Unchanged
    );
    let other = build_day_batch(3, &leaves(3, 0, 5))
        .unwrap()
        .expect("other");
    assert!(matches!(
        ledger.record_batched(other.header(), 3),
        Err(Error::Conflict { day: 3 })
    ));
    let e = ledger.get(3).unwrap().expect("entry");
    assert_eq!(e.status, EntryStatus::Batched);
    assert_eq!(e.commitment, Some(b.commitment()));
    // Survives reopen.
    drop(ledger);
    let again = AnchorLedger::open(d.path()).unwrap();
    assert_eq!(again.entries().unwrap().len(), 1);
}

#[test]
fn ledger_refuses_a_record_in_two_batches() {
    let d = tempfile::tempdir().unwrap();
    let ledger = AnchorLedger::open(d.path()).unwrap();
    let b = build_day_batch(3, &leaves(3, 0, 4))
        .unwrap()
        .expect("batch");
    ledger.record_batched(b.header(), 1).unwrap();
    // A different day claiming seq 3 again.
    let o = build_day_batch(4, &leaves(4, 3, 2))
        .unwrap()
        .expect("overlap");
    assert!(matches!(
        ledger.record_batched(o.header(), 2),
        Err(Error::Overlap { day: 4, other: 3 })
    ));
}

#[test]
fn ledger_is_single_writer() {
    let d = tempfile::tempdir().unwrap();
    let _a = AnchorLedger::open(d.path()).unwrap();
    assert!(matches!(
        AnchorLedger::open(d.path()),
        Err(Error::Locked(_))
    ));
}

#[test]
fn ledger_marks_confirmation_only_for_batched_days() {
    let d = tempfile::tempdir().unwrap();
    let ledger = AnchorLedger::open(d.path()).unwrap();
    assert!(matches!(
        ledger.mark_confirmed(3, "0xabc", 10, 1),
        Err(Error::NotBatched { day: 3 })
    ));
    let b = build_day_batch(3, &leaves(3, 0, 2))
        .unwrap()
        .expect("batch");
    ledger.record_batched(b.header(), 1).unwrap();
    ledger.mark_confirmed(3, "0xabc", 10, 2).unwrap();
    let e = ledger.get(3).unwrap().expect("entry");
    let c = e.confirmed.expect("confirmed");
    assert_eq!((c.tx_hash.as_str(), c.block_number), ("0xabc", 10));
}

// ---------------------------------------------------------------------------------------------
// nightly plan over a real decision log

#[test]
fn plan_refuses_a_day_that_is_not_over() {
    let rec = tempfile::tempdir().unwrap();
    let led = tempfile::tempdir().unwrap();
    log_with_days(rec.path(), 100, &[2], LogConfig::default());
    let ledger = AnchorLedger::open(led.path()).unwrap();
    assert!(matches!(
        plan_day(rec.path(), &ledger, 100, 100 * DAY + 10, None),
        Err(Error::DayNotClosed {
            day: 100,
            today: 100
        })
    ));
    assert!(matches!(
        plan_day(rec.path(), &ledger, 101, 100 * DAY + 10, None),
        Err(Error::DayNotClosed { .. })
    ));
}

#[test]
fn plan_builds_unsigned_calldata_for_a_closed_day_and_is_idempotent() {
    let rec = tempfile::tempdir().unwrap();
    let led = tempfile::tempdir().unwrap();
    log_with_days(rec.path(), 100, &[3, 4, 1], LogConfig::default());
    let ledger = AnchorLedger::open(led.path()).unwrap();
    let now = 103 * DAY;
    let to = "0x00000000000000000000000000000000000000aa";
    let NightlyPlan::Ready {
        header,
        commitment,
        call,
        newly_recorded,
    } = plan_day(rec.path(), &ledger, 101, now, Some(to)).unwrap()
    else {
        panic!("ready")
    };
    assert!(newly_recorded);
    assert_eq!((header.first_seq, header.last_seq, header.count), (3, 6, 4));
    // Same tree root as agent-records' own daily root.
    let dr = merkle::daily_root(rec.path(), 101)
        .unwrap()
        .expect("daily root");
    assert_eq!(hex::encode(header.tree_root), dr.root);
    assert_eq!(call.chain_id, CITRATE_CHAIN_ID);
    assert_eq!(call.to.as_deref(), Some(to));
    assert_eq!(call.value, 0);
    assert_eq!(call.kind, AnchorKind::NightlyMerkle);
    assert_eq!(call.root, commitment);
    assert_eq!(
        call.data,
        anchor_calldata(AnchorKind::NightlyMerkle, &commitment)
    );
    // Planning again changes nothing.
    let NightlyPlan::Ready {
        commitment: c2,
        newly_recorded: n2,
        ..
    } = plan_day(rec.path(), &ledger, 101, now, Some(to)).unwrap()
    else {
        panic!("ready again")
    };
    assert_eq!(c2, commitment);
    assert!(!n2);
    // After confirmation it reports already anchored.
    ledger.mark_confirmed(101, "0x01", 7, now).unwrap();
    assert!(matches!(
        plan_day(rec.path(), &ledger, 101, now, None).unwrap(),
        NightlyPlan::AlreadyAnchored { .. }
    ));
}

#[test]
fn plan_reports_an_empty_day_and_records_nothing() {
    let rec = tempfile::tempdir().unwrap();
    let led = tempfile::tempdir().unwrap();
    log_with_days(rec.path(), 100, &[1, 0, 1], LogConfig::default());
    let ledger = AnchorLedger::open(led.path()).unwrap();
    assert_eq!(
        plan_day(rec.path(), &ledger, 101, 103 * DAY, None).unwrap(),
        NightlyPlan::Empty { day: 101 }
    );
    assert!(ledger.get(101).unwrap().is_none());
}

#[test]
fn every_batched_record_of_a_real_log_has_a_proof_against_the_anchored_value() {
    let rec = tempfile::tempdir().unwrap();
    let led = tempfile::tempdir().unwrap();
    // Small segments so the days span rotation boundaries.
    let cfg = LogConfig {
        max_segment_bytes: 700,
        max_segments: None,
    };
    log_with_days(rec.path(), 200, &[5, 9, 2], cfg);
    let segs = fs::read_dir(rec.path())
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .is_ok_and(|e| e.file_name().to_string_lossy().starts_with("seg-"))
        })
        .count();
    assert!(segs > 3, "rotation happened ({segs} segments)");
    let ledger = AnchorLedger::open(led.path()).unwrap();
    for day in 200..203 {
        let NightlyPlan::Ready { commitment, .. } =
            plan_day(rec.path(), &ledger, day, 203 * DAY, None).unwrap()
        else {
            panic!("ready {day}")
        };
        let e = ledger.get(day).unwrap().expect("entry");
        for seq in e.first_seq..=e.last_seq {
            let p = prove(rec.path(), &ledger, seq).unwrap().expect("proof");
            assert!(verify_proof(&p, &commitment), "day {day} seq {seq}");
            let r = read::get(rec.path(), seq).unwrap().expect("record");
            assert!(verify_record_proof(&r, &p, &commitment).unwrap());
        }
    }
    assert!(pending_days(rec.path(), &ledger, 203 * DAY)
        .unwrap()
        .is_empty());
}

#[test]
fn verify_record_proof_refuses_a_record_that_is_not_the_leaf() {
    let rec = tempfile::tempdir().unwrap();
    let led = tempfile::tempdir().unwrap();
    log_with_days(rec.path(), 10, &[3], LogConfig::default());
    let ledger = AnchorLedger::open(led.path()).unwrap();
    let NightlyPlan::Ready { commitment, .. } =
        plan_day(rec.path(), &ledger, 10, 11 * DAY, None).unwrap()
    else {
        panic!("ready")
    };
    let p = prove(rec.path(), &ledger, 1).unwrap().expect("proof");
    let other = read::get(rec.path(), 2).unwrap().expect("record");
    assert!(!verify_record_proof(&other, &p, &commitment).unwrap());
    let mut edited = read::get(rec.path(), 1).unwrap().expect("record");
    edited.record.ts_ms += 1;
    assert!(!verify_record_proof(&edited, &p, &commitment).unwrap());
}

#[test]
fn prove_refuses_a_day_that_is_not_batched_and_a_rewritten_log() {
    let rec = tempfile::tempdir().unwrap();
    let led = tempfile::tempdir().unwrap();
    log_with_days(rec.path(), 10, &[2, 2], LogConfig::default());
    let ledger = AnchorLedger::open(led.path()).unwrap();
    assert!(matches!(
        prove(rec.path(), &ledger, 0),
        Err(Error::NotBatched { day: 10 })
    ));
    assert!(prove(rec.path(), &ledger, 99).unwrap().is_none());
    plan_day(rec.path(), &ledger, 10, 12 * DAY, None).unwrap();
    // Rewrite the whole log consistently with different content: the ledger notices.
    fs::remove_dir_all(rec.path()).unwrap();
    fs::create_dir_all(rec.path()).unwrap();
    log_with_days(rec.path(), 10, &[3, 1], LogConfig::default());
    assert!(matches!(
        prove(rec.path(), &ledger, 0),
        Err(Error::Conflict { day: 10 })
    ));
    assert!(matches!(
        plan_day(rec.path(), &ledger, 10, 12 * DAY, None),
        Err(Error::Conflict { day: 10 })
    ));
}

#[test]
fn pending_days_lists_closed_unbatched_days_with_records() {
    let rec = tempfile::tempdir().unwrap();
    let led = tempfile::tempdir().unwrap();
    log_with_days(rec.path(), 50, &[1, 0, 2, 3], LogConfig::default());
    let ledger = AnchorLedger::open(led.path()).unwrap();
    // Day 53 is today: not closed.
    assert_eq!(
        pending_days(rec.path(), &ledger, 53 * DAY + 1).unwrap(),
        vec![50, 52]
    );
    plan_day(rec.path(), &ledger, 50, 53 * DAY + 1, None).unwrap();
    assert_eq!(
        pending_days(rec.path(), &ledger, 53 * DAY + 1).unwrap(),
        vec![52]
    );
    // Day 53 closes at midnight. Batched day 50 waits for core's confirmation instead.
    assert_eq!(
        pending_days(rec.path(), &ledger, 54 * DAY).unwrap(),
        vec![52, 53]
    );
    assert_eq!(ledger.unconfirmed().unwrap(), vec![50]);
    ledger.mark_confirmed(50, "0x02", 9, 54 * DAY).unwrap();
    assert!(ledger.unconfirmed().unwrap().is_empty());
}

#[test]
fn a_day_partly_pruned_before_batching_is_reported_incomplete_not_anchored() {
    let rec = tempfile::tempdir().unwrap();
    let led = tempfile::tempdir().unwrap();
    let cfg = LogConfig {
        max_segment_bytes: 700,
        max_segments: Some(2),
    };
    log_with_days(rec.path(), 300, &[12, 1], cfg);
    let ret = merkle::retained_leaves(rec.path()).unwrap();
    let cp = ret.pruned_through_ms.expect("pruned");
    assert_eq!(merkle::utc_day(cp), 300, "the prune cut into day 300");
    let ledger = AnchorLedger::open(led.path()).unwrap();
    let plan = plan_day(rec.path(), &ledger, 300, 302 * DAY, None).unwrap();
    let NightlyPlan::Incomplete { day, retained } = plan else {
        panic!("incomplete, got {plan:?}")
    };
    assert_eq!(day, 300);
    assert!(retained > 0 && retained < 12);
    let e = ledger.get(300).unwrap().expect("reported");
    assert_eq!(e.status, EntryStatus::Incomplete);
    assert!(e.commitment.is_none());
    // Reported days are not pending; the untouched day 301 is.
    assert_eq!(
        pending_days(rec.path(), &ledger, 302 * DAY).unwrap(),
        vec![301]
    );
}

#[test]
fn prove_says_so_when_a_batched_day_was_pruned_afterwards() {
    let rec = tempfile::tempdir().unwrap();
    let led = tempfile::tempdir().unwrap();
    let cfg = LogConfig {
        max_segment_bytes: 700,
        max_segments: Some(2),
    };
    let c = Arc::new(TestClock(AtomicU64::new(400 * DAY + 5)));
    let (log, _) = DecisionLog::open_with_clock(rec.path(), cfg, c.clone()).unwrap();
    for k in 0..3 {
        log.record_decision(Actor::member("m1"), ev(&format!("a{k}")))
            .unwrap();
    }
    let ledger = AnchorLedger::open(led.path()).unwrap();
    let NightlyPlan::Ready { commitment, .. } =
        plan_day(rec.path(), &ledger, 400, 401 * DAY, None).unwrap()
    else {
        panic!("ready")
    };
    assert!(verify_proof(
        &prove(rec.path(), &ledger, 2).unwrap().expect("proof"),
        &commitment
    ));
    // Day 401 records until the first prune, which cuts into day 400.
    c.0.store(401 * DAY + 5, Ordering::SeqCst);
    let mut k = 0;
    let ret = loop {
        log.record_decision(Actor::member("m1"), ev(&format!("b{k}")))
            .unwrap();
        k += 1;
        let ret = merkle::retained_leaves(rec.path()).unwrap();
        if ret.pruned_through_ms.is_some() {
            break ret;
        }
        assert!(k < 20, "no prune happened");
    };
    assert_eq!(merkle::utc_day(ret.pruned_through_ms.unwrap_or(0)), 400);
    let survivor = ret
        .leaves
        .iter()
        .find(|l| merkle::utc_day(l.ts_ms) == 400)
        .expect("part of day 400 is still retained")
        .seq;
    assert!(matches!(
        prove(rec.path(), &ledger, survivor),
        Err(Error::PrunedDay { day: 400 })
    ));
    // The batched day stays planned from the ledger: same call, no conflict.
    let NightlyPlan::Ready {
        commitment: again, ..
    } = plan_day(rec.path(), &ledger, 400, 402 * DAY, None).unwrap()
    else {
        panic!("ready from the ledger")
    };
    assert_eq!(again, commitment);
}
