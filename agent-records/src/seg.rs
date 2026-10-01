//! On-disk layout and the chain walk shared by the writer, the verifier, the reader, and the
//! Merkle functions.
//!
//! Directory contents:
//! - `seg-NNNNNNNN.jsonl`: segments, one [`StoredRecord`] per line, in `seq` order.
//! - `HEAD`: `{seq, hash}` of the last durable record, replaced atomically after each append.
//! - `CHECKPOINT` (only after pruning): where the retained chain starts.
//! - `LOCK`: held with an exclusive OS file lock by the single writer.
//! - `torn-*.bin`: bytes of an incomplete final line quarantined by crash recovery.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{io_err, Error, IntegrityError, Result};
use crate::record::{
    validate_actor, validate_decision, validate_outcome, Entry, StoredRecord, GENESIS_PREV,
    SCHEMA_VERSION,
};

pub(crate) const HEAD: &str = "HEAD";
pub(crate) const CHECKPOINT: &str = "CHECKPOINT";
pub(crate) const LOCK: &str = "LOCK";

pub(crate) fn seg_name(index: u32) -> String {
    format!("seg-{index:08}.jsonl")
}

fn parse_seg_name(name: &str) -> Option<u32> {
    name.strip_prefix("seg-")?
        .strip_suffix(".jsonl")
        .filter(|n| n.len() == 8 && n.bytes().all(|b| b.is_ascii_digit()))?
        .parse()
        .ok()
}

/// Segments sorted by index.
pub(crate) fn list_segments(dir: &Path) -> Result<Vec<(u32, PathBuf)>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).map_err(io_err(dir))? {
        let entry = entry.map_err(io_err(dir))?;
        let name = entry.file_name();
        if let Some(i) = name.to_str().and_then(parse_seg_name) {
            out.push((i, entry.path()));
        }
    }
    out.sort_by_key(|(i, _)| *i);
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Head {
    pub seq: u64,
    pub hash: String,
}

/// Where the retained chain starts after older segments were pruned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Checkpoint {
    /// The first retained `seq`.
    pub next_seq: u64,
    /// Hash of the last pruned record (the `prev` of record `next_seq`).
    pub prev: String,
    /// Timestamp of the last pruned record.
    pub ts_ms: u64,
    /// Allowing decisions at or before the checkpoint that still had no outcome.
    pub open: Vec<u64>,
}

fn read_json_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(Error::Json),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err(path)(e)),
    }
}

pub(crate) fn read_head(dir: &Path) -> Result<Option<Head>> {
    read_json_file(&dir.join(HEAD))
}

pub(crate) fn read_checkpoint(dir: &Path) -> Result<Option<Checkpoint>> {
    read_json_file(&dir.join(CHECKPOINT))
}

/// Flush a directory entry change (create, rename, delete) to disk. Directories cannot be opened
/// as files on Windows; there NTFS metadata journaling covers it.
pub(crate) fn sync_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(io_err(dir))?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Write `bytes` to `dir/name` atomically: temp file, fsync, rename, fsync the directory.
pub(crate) fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    let dst = dir.join(name);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(io_err(&tmp))?;
        f.write_all(bytes).map_err(io_err(&tmp))?;
        f.sync_all().map_err(io_err(&tmp))?;
    }
    fs::rename(&tmp, &dst).map_err(io_err(&dst))?;
    sync_dir(dir)
}

/// A segment as read from disk: its complete records, and an incomplete final line if any.
pub(crate) struct SegmentRead {
    pub records: Vec<StoredRecord>,
    /// Byte offset and length of an incomplete final line (no trailing newline).
    pub torn: Option<(u64, u64)>,
}

pub(crate) fn read_segment(path: &Path) -> Result<SegmentRead> {
    let bytes = fs::read(path).map_err(io_err(path))?;
    let seg = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut records = Vec::new();
    let mut start = 0usize;
    let mut line_no = 0usize;
    while start < bytes.len() {
        let Some(rel) = bytes[start..].iter().position(|b| *b == b'\n') else {
            return Ok(SegmentRead {
                records,
                torn: Some((start as u64, (bytes.len() - start) as u64)),
            });
        };
        line_no += 1;
        let line = &bytes[start..start + rel];
        let rec: StoredRecord =
            serde_json::from_slice(line).map_err(|_| IntegrityError::Malformed {
                segment: seg.clone(),
                line: line_no,
            })?;
        records.push(rec);
        start += rel + 1;
    }
    Ok(SegmentRead {
        records,
        torn: None,
    })
}

/// How strictly the walk treats states a live writer can produce mid-read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// The log is quiescent (or the caller holds the writer lock): a torn tail is an error and
    /// the tip may be at most one record past `HEAD`.
    Strict,
    /// Crash recovery: like `Strict`, but an incomplete final line is reported, not an error.
    Recover,
    /// A concurrent reader: an incomplete final line is an in-flight write and is skipped, and
    /// the tip may be any distance past the `HEAD` read before the segments.
    Live,
}

#[derive(Debug, Default)]
pub(crate) struct Walked {
    pub count: u64,
    pub first_seq: Option<u64>,
    /// `(seq, hash, ts_ms)` of the last record.
    pub tip: Option<(u64, String, u64)>,
    pub segments: usize,
    pub open: BTreeSet<u64>,
    pub head_lag: bool,
    /// Last segment with an incomplete final line: `(path, offset, len)`.
    pub torn: Option<(PathBuf, u64, u64)>,
    /// Segments whose records all precede the checkpoint (left behind by a crash mid-prune).
    pub stale_segments: Vec<PathBuf>,
    pub checkpoint: Option<Checkpoint>,
}

/// Walk the whole retained chain, checking every link, and call `visit` on each verified
/// record in order.
pub(crate) fn walk(dir: &Path, mode: Mode, mut visit: impl FnMut(&StoredRecord)) -> Result<Walked> {
    // HEAD first: a live writer only moves it forward after the segment write, so the segments
    // read afterwards are never behind it.
    let head = read_head(dir)?;
    let checkpoint = read_checkpoint(dir)?;
    let segs = list_segments(dir)?;

    let mut w = Walked {
        segments: segs.len(),
        ..Walked::default()
    };
    let (mut expect_seq, mut prev, mut last_ts) = match &checkpoint {
        Some(cp) => (cp.next_seq, cp.prev.clone(), cp.ts_ms),
        None => (0, GENESIS_PREV.to_string(), 0),
    };
    let floor = expect_seq;
    if let Some(cp) = &checkpoint {
        w.open.extend(cp.open.iter().copied());
    }
    let mut head_hash_at_seq: Option<String> = None;

    for (pos, (_, path)) in segs.iter().enumerate() {
        let is_last = pos + 1 == segs.len();
        let seg = read_segment(path)?;
        if let Some((off, len)) = seg.torn {
            let segname = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            match mode {
                Mode::Live if is_last => {}
                Mode::Recover if is_last => w.torn = Some((path.clone(), off, len)),
                _ => return Err(IntegrityError::TornTail { segment: segname }.into()),
            }
        }
        let mut all_stale = !seg.records.is_empty();
        for r in &seg.records {
            let b = &r.record;
            if b.seq < floor {
                // Left behind by a crash between writing CHECKPOINT and deleting the segment.
                if b.seq + 1 == floor && checkpoint.as_ref().is_some_and(|cp| cp.prev != r.hash) {
                    return Err(IntegrityError::CheckpointMismatch.into());
                }
                continue;
            }
            all_stale = false;
            if b.v != SCHEMA_VERSION {
                return Err(IntegrityError::UnknownVersion { seq: b.seq, v: b.v }.into());
            }
            if !r.hash_matches()? {
                return Err(IntegrityError::HashMismatch { seq: b.seq }.into());
            }
            if b.seq != expect_seq {
                return Err(IntegrityError::SeqGap {
                    expected: expect_seq,
                    found: b.seq,
                }
                .into());
            }
            if b.prev != prev {
                if checkpoint.is_some() && b.seq == floor {
                    return Err(IntegrityError::CheckpointMismatch.into());
                }
                return Err(IntegrityError::PrevMismatch { seq: b.seq }.into());
            }
            if b.ts_ms < last_ts {
                return Err(IntegrityError::TimeReversed { seq: b.seq }.into());
            }
            let policy = |e: Error| IntegrityError::Policy {
                seq: b.seq,
                why: e.to_string(),
            };
            validate_actor(&b.actor).map_err(policy)?;
            match &b.entry {
                Entry::Decision(d) => {
                    validate_decision(d).map_err(policy)?;
                    if d.decision.expects_outcome() {
                        w.open.insert(b.seq);
                    }
                }
                Entry::Outcome(o) => {
                    validate_outcome(o).map_err(policy)?;
                    if !w.open.remove(&o.decision_seq) {
                        return Err(IntegrityError::BadOutcomeRef {
                            seq: b.seq,
                            decision_seq: o.decision_seq,
                        }
                        .into());
                    }
                }
            }
            if head.as_ref().is_some_and(|h| h.seq == b.seq) {
                head_hash_at_seq = Some(r.hash.clone());
            }
            visit(r);
            w.count += 1;
            w.first_seq.get_or_insert(b.seq);
            expect_seq = b.seq + 1;
            prev = r.hash.clone();
            last_ts = b.ts_ms;
            w.tip = Some((b.seq, r.hash.clone(), b.ts_ms));
        }
        if all_stale {
            w.stale_segments.push(path.clone());
        }
    }

    match (&head, &w.tip) {
        (None, None) if checkpoint.is_none() => {}
        (None, _) => return Err(IntegrityError::HeadMissing.into()),
        (Some(h), None) => {
            return Err(IntegrityError::Truncated {
                head_seq: h.seq,
                tip: None,
            }
            .into())
        }
        (Some(h), Some((tip, tip_hash, _))) => {
            if h.seq > *tip {
                return Err(IntegrityError::Truncated {
                    head_seq: h.seq,
                    tip: Some(*tip),
                }
                .into());
            }
            if h.seq < floor {
                // HEAD points into the pruned range; only a lagging live read can see that.
                if mode != Mode::Live {
                    return Err(IntegrityError::HeadBehind {
                        head_seq: h.seq,
                        tip: *tip,
                    }
                    .into());
                }
            } else if head_hash_at_seq.as_deref() != Some(h.hash.as_str()) {
                return Err(IntegrityError::HeadHashMismatch { seq: h.seq }.into());
            }
            if h.seq == *tip && *tip_hash != h.hash {
                return Err(IntegrityError::HeadHashMismatch { seq: h.seq }.into());
            }
            let lag = tip - h.seq;
            if lag > 1 && mode != Mode::Live {
                return Err(IntegrityError::HeadBehind {
                    head_seq: h.seq,
                    tip: *tip,
                }
                .into());
            }
            w.head_lag = lag > 0;
        }
    }
    w.checkpoint = checkpoint;
    Ok(w)
}
