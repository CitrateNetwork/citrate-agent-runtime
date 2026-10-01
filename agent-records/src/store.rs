//! The single writer.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{io_err, Error, Result};
use crate::record::{
    validate_actor, validate_decision, validate_outcome, Actor, DecisionEvent, Entry, Outcome,
    OutcomeEvent, RecordBody, StoredRecord, SCHEMA_VERSION,
};
use crate::seg::{
    list_segments, read_checkpoint, read_segment, seg_name, sync_dir, walk, write_atomic,
    Checkpoint, Head, Mode, CHECKPOINT, HEAD, LOCK,
};
use crate::verify::VerifyReport;

/// Source of record timestamps (Unix milliseconds).
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// The system wall clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}

/// Rotation and retention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogConfig {
    /// A new segment starts when the next record would push the current one past this size. A
    /// single record larger than this still gets a segment of its own.
    pub max_segment_bytes: u64,
    /// Keep at most this many segments; older ones are dropped behind a `CHECKPOINT` that keeps
    /// the rest verifiable. `None` (the default) keeps everything. Callers should only enable
    /// pruning once the days in old segments are anchored (HUP-S7.3), because a dropped record
    /// can no longer be proven.
    pub max_segments: Option<usize>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            max_segment_bytes: 8 * 1024 * 1024,
            max_segments: None,
        }
    }
}

/// Returned once a record is durable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub seq: u64,
    pub hash: String,
    pub ts_ms: u64,
    /// The decision allows an effect, so [`DecisionLog::record_outcome`] is owed.
    pub awaiting_outcome: bool,
}

/// What [`DecisionLog::open`] had to repair.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Bytes of an incomplete final line moved to a `torn-*.bin` file.
    pub torn_tail_bytes: u64,
    /// `HEAD` was one record behind the tip and was moved forward.
    pub head_repaired: bool,
    /// Allowing decisions with no outcome, now closed as `outcome_unknown`.
    pub marked_unknown: Vec<u64>,
    /// Segments left behind by a crash during pruning, now deleted.
    pub stale_segments_removed: usize,
}

const RECOVERY_ACTOR: &str = "agent-records.recovery";

struct Inner {
    seg_index: u32,
    seg: File,
    seg_len: u64,
    seg_count: usize,
    next_seq: u64,
    prev: String,
    last_ts: u64,
    open: BTreeSet<u64>,
    /// Set after a write failed in a way that may leave the files inconsistent with this state.
    /// Every later append is refused until the log is reopened (and recovered).
    failed: bool,
}

/// The append-only decision log. One writer per directory, enforced with an OS file lock;
/// in-process callers share it behind an `Arc`.
pub struct DecisionLog {
    dir: PathBuf,
    cfg: LogConfig,
    clock: Arc<dyn Clock>,
    inner: Mutex<Inner>,
    _lock: File,
}

impl DecisionLog {
    /// Open (or create) the log in `dir` with the system clock, recovering from a crash.
    pub fn open(dir: &Path, cfg: LogConfig) -> Result<(Self, RecoveryReport)> {
        Self::open_with_clock(dir, cfg, Arc::new(SystemClock))
    }

    /// Open with an explicit clock.
    ///
    /// Recovery: an incomplete final line is moved to a `torn-*.bin` file, a `HEAD` one record
    /// behind is moved forward, segments left by an interrupted prune are deleted, and every
    /// allowing decision without an outcome is closed as `outcome_unknown`. Any other integrity
    /// failure refuses to open (fail closed: no record, no effect).
    pub fn open_with_clock(
        dir: &Path,
        mut cfg: LogConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<(Self, RecoveryReport)> {
        cfg.max_segment_bytes = cfg.max_segment_bytes.max(1);
        cfg.max_segments = cfg.max_segments.map(|n| n.max(1));
        fs::create_dir_all(dir).map_err(io_err(dir))?;
        let lock_path = dir.join(LOCK);
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(io_err(&lock_path))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(Error::Locked(dir.to_path_buf())),
            Err(TryLockError::Error(e)) => return Err(io_err(&lock_path)(e)),
        }

        let mut report = RecoveryReport::default();
        let mut w = walk(dir, Mode::Recover, |_| {})?;

        if let Some((path, off, len)) = w.torn.take() {
            quarantine_torn(dir, &path, off, len)?;
            report.torn_tail_bytes = len;
        }
        for stale in &w.stale_segments {
            fs::remove_file(stale).map_err(io_err(stale))?;
            report.stale_segments_removed += 1;
        }
        if !w.stale_segments.is_empty() {
            sync_dir(dir)?;
        }
        if w.head_lag {
            if let Some((seq, hash, _)) = &w.tip {
                write_head(dir, *seq, hash)?;
                report.head_repaired = true;
            }
        }

        let segs = list_segments(dir)?;
        let (seg_index, seg_path) = match segs.last() {
            Some((i, p)) => (*i, p.clone()),
            None => {
                let p = dir.join(seg_name(1));
                (1, p)
            }
        };
        let seg = open_append(&seg_path)?;
        if segs.is_empty() {
            sync_dir(dir)?;
        }
        let seg_len = seg.metadata().map_err(io_err(&seg_path))?.len();
        let (next_seq, prev, last_ts) = match (&w.tip, &w.checkpoint) {
            (Some((seq, hash, ts)), _) => (seq + 1, hash.clone(), *ts),
            (None, Some(cp)) => (cp.next_seq, cp.prev.clone(), cp.ts_ms),
            (None, None) => (0, crate::record::GENESIS_PREV.to_string(), 0),
        };

        let log = DecisionLog {
            dir: dir.to_path_buf(),
            cfg,
            clock,
            inner: Mutex::new(Inner {
                seg_index,
                seg,
                seg_len,
                seg_count: segs.len().max(1),
                next_seq,
                prev,
                last_ts,
                open: w.open.clone(),
                failed: false,
            }),
            _lock: lock,
        };

        for seq in w.open {
            log.record_outcome(
                Actor::daemon(RECOVERY_ACTOR),
                OutcomeEvent {
                    decision_seq: seq,
                    outcome: Outcome::OutcomeUnknown,
                    detail: "closed on recovery: the process stopped after this decision was \
                             recorded and before its outcome was; the effect may or may not \
                             have happened"
                        .into(),
                },
            )?;
            report.marked_unknown.push(seq);
        }
        Ok((log, report))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Record an HIC decision. Write-ahead: returns only after the record is on disk, and the
    /// caller must not perform an allowed effect unless this returned `Ok`.
    pub fn record_decision(&self, actor: Actor, event: DecisionEvent) -> Result<Receipt> {
        validate_actor(&actor)?;
        validate_decision(&event)?;
        self.append(actor, Entry::Decision(event))
    }

    /// Close an allowing decision with what happened to its effect.
    pub fn record_outcome(&self, actor: Actor, event: OutcomeEvent) -> Result<Receipt> {
        validate_actor(&actor)?;
        validate_outcome(&event)?;
        self.append(actor, Entry::Outcome(event))
    }

    /// Allowing decisions still waiting for an outcome, ascending.
    pub fn open_decisions(&self) -> Result<Vec<u64>> {
        Ok(self.lock()?.open.iter().copied().collect())
    }

    /// Verify the directory while holding the writer lock, so no append is in flight.
    pub fn verify(&self) -> Result<VerifyReport> {
        let _g = self.lock()?;
        crate::verify::verify_dir(&self.dir)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>> {
        self.inner.lock().map_err(|_| Error::Poisoned)
    }

    fn append(&self, actor: Actor, entry: Entry) -> Result<Receipt> {
        let mut g = self.lock()?;
        if g.failed {
            return Err(Error::Invalid(
                "an earlier write failed; reopen the log to recover before recording more".into(),
            ));
        }
        if let Entry::Outcome(o) = &entry {
            if !g.open.contains(&o.decision_seq) {
                return Err(Error::Invalid(format!(
                    "decision {} is not an open allowing decision",
                    o.decision_seq
                )));
            }
        }
        let ts_ms = self.clock.now_ms().max(g.last_ts);
        let body = RecordBody {
            v: SCHEMA_VERSION,
            seq: g.next_seq,
            ts_ms,
            prev: g.prev.clone(),
            actor,
            entry,
        };
        let rec = StoredRecord::seal(body)?;
        let mut line = serde_json::to_vec(&rec).map_err(Error::Json)?;
        line.push(b'\n');
        let len = line.len() as u64;

        if g.seg_len > 0 && g.seg_len.saturating_add(len) > self.cfg.max_segment_bytes {
            self.rotate(&mut g)?;
        }

        let seg_path = self.dir.join(seg_name(g.seg_index));
        if let Err(e) = g.seg.write_all(&line).and_then(|()| g.seg.sync_data()) {
            // Roll back a partial line so the next append does not land after garbage. If even
            // that fails, refuse further writes; recovery on reopen quarantines the torn tail.
            let rolled_back = g.seg.set_len(g.seg_len).and_then(|()| g.seg.sync_data());
            if rolled_back.is_err() {
                g.failed = true;
            }
            return Err(io_err(&seg_path)(e));
        }
        if let Err(e) = write_head(&self.dir, rec.record.seq, &rec.hash) {
            // The record is durable but HEAD lags. One lagging record is a state recovery
            // repairs; a second would not be, so stop here.
            g.failed = true;
            return Err(e);
        }

        g.seg_len += len;
        g.next_seq += 1;
        g.prev = rec.hash.clone();
        g.last_ts = ts_ms;
        let awaiting_outcome = match &rec.record.entry {
            Entry::Decision(d) => {
                if d.decision.expects_outcome() {
                    g.open.insert(rec.record.seq);
                }
                d.decision.expects_outcome()
            }
            Entry::Outcome(o) => {
                g.open.remove(&o.decision_seq);
                false
            }
        };
        Ok(Receipt {
            seq: rec.record.seq,
            hash: rec.hash,
            ts_ms,
            awaiting_outcome,
        })
    }

    fn rotate(&self, g: &mut Inner) -> Result<()> {
        let next = g
            .seg_index
            .checked_add(1)
            .ok_or_else(|| Error::Invalid("segment index exhausted".into()))?;
        let path = self.dir.join(seg_name(next));
        let f = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&path)
            .map_err(io_err(&path))?;
        sync_dir(&self.dir)?;
        g.seg = f;
        g.seg_index = next;
        g.seg_len = 0;
        g.seg_count += 1;
        if let Some(max) = self.cfg.max_segments {
            while g.seg_count > max {
                if let Err(e) = self.prune_oldest() {
                    g.failed = true;
                    return Err(e);
                }
                g.seg_count -= 1;
            }
        }
        Ok(())
    }

    /// Drop the oldest segment behind a checkpoint. Order: write the new CHECKPOINT, then delete
    /// the segment; a crash in between leaves a stale segment that the walk skips and the next
    /// open deletes.
    fn prune_oldest(&self) -> Result<()> {
        let segs = list_segments(&self.dir)?;
        let Some((_, oldest)) = segs.first() else {
            return Ok(());
        };
        let prior = read_checkpoint(&self.dir)?;
        let mut open: BTreeSet<u64> = prior
            .as_ref()
            .map(|c| c.open.iter().copied().collect())
            .unwrap_or_default();
        let floor = prior.as_ref().map_or(0, |c| c.next_seq);
        let seg = read_segment(oldest)?;
        let mut last = None;
        for r in seg.records.iter().filter(|r| r.record.seq >= floor) {
            match &r.record.entry {
                Entry::Decision(d) if d.decision.expects_outcome() => {
                    open.insert(r.record.seq);
                }
                Entry::Outcome(o) => {
                    open.remove(&o.decision_seq);
                }
                Entry::Decision(_) => {}
            }
            last = Some(r);
        }
        if let Some(last) = last {
            let cp = Checkpoint {
                next_seq: last.record.seq + 1,
                prev: last.hash.clone(),
                ts_ms: last.record.ts_ms,
                open: open.into_iter().collect(),
            };
            let bytes = serde_json::to_vec(&cp).map_err(Error::Json)?;
            write_atomic(&self.dir, CHECKPOINT, &bytes)?;
        }
        fs::remove_file(oldest).map_err(io_err(oldest))?;
        sync_dir(&self.dir)
    }
}

fn open_append(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(io_err(path))
}

fn write_head(dir: &Path, seq: u64, hash: &str) -> Result<()> {
    let bytes = serde_json::to_vec(&Head {
        seq,
        hash: hash.to_string(),
    })
    .map_err(Error::Json)?;
    write_atomic(dir, HEAD, &bytes)
}

/// Move an incomplete final line out of the segment into `torn-<segment>-<offset>.bin`, then cut
/// the segment back to its last complete record.
fn quarantine_torn(dir: &Path, seg: &Path, off: u64, len: u64) -> Result<()> {
    let bytes = fs::read(seg).map_err(io_err(seg))?;
    let start = usize::try_from(off).map_err(|_| Error::Invalid("torn offset".into()))?;
    let tail = bytes.get(start..).unwrap_or_default();
    let stem = seg
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let qname = format!("torn-{stem}-{off}.bin");
    write_atomic(dir, &qname, tail)?;
    let f = OpenOptions::new()
        .write(true)
        .open(seg)
        .map_err(io_err(seg))?;
    f.set_len(off).map_err(io_err(seg))?;
    f.sync_all().map_err(io_err(seg))?;
    debug_assert_eq!(tail.len() as u64, len);
    Ok(())
}
