//! The local anchor ledger: which days were batched, under which commitment, and whether core
//! reported the anchor as confirmed on chain.
//!
//! One JSON file (`ANCHOR_LEDGER.json`), rewritten atomically (temp file, fsync, rename, fsync the
//! directory), next to a `ANCHOR_LEDGER.lock` held with an exclusive OS file lock by the single
//! writer. The ledger enforces the batch rules the TLA+ model `AnchorBatch` checks:
//!
//! - a day is batched at most once, and never re-recorded with a different commitment
//!   ([`Error::Conflict`]);
//! - a record belongs to at most one batch: `seq` ranges of different days never overlap
//!   ([`Error::Overlap`]);
//! - a day whose records were partly pruned before batching is recorded as
//!   [`EntryStatus::Incomplete`] (reported, never anchored).
//!
//! The ledger is a local note, not the source of truth for "anchored": `AnchorRegistry.isAnchored`
//! is. Confirmation is written by core after its ceremony sends the anchor transaction.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::batch::{BatchHeader, BATCH_VERSION};
use crate::error::{io_err, Error, Result};

const LEDGER: &str = "ANCHOR_LEDGER.json";
const LOCK: &str = "ANCHOR_LEDGER.lock";
const LEDGER_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryStatus {
    /// The day's batch is fixed and its anchor calldata was built.
    Batched,
    /// Some of the day's records were pruned before it was batched; reported, never anchored.
    Incomplete,
}

/// Recorded by core once the anchor transaction is mined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirmation {
    pub tx_hash: String,
    pub block_number: u64,
    pub confirmed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    pub day: u64,
    pub status: EntryStatus,
    pub first_seq: u64,
    pub last_seq: u64,
    pub count: u64,
    #[serde(with = "crate::hex32::opt")]
    pub tree_root: Option<[u8; 32]>,
    /// The anchored value, for a batched day.
    #[serde(with = "crate::hex32::opt")]
    pub commitment: Option<[u8; 32]>,
    pub recorded_at_ms: u64,
    pub confirmed: Option<Confirmation>,
}

impl LedgerEntry {
    /// The batch header of a batched day.
    pub fn header(&self) -> Option<BatchHeader> {
        match (self.status, self.tree_root) {
            (EntryStatus::Batched, Some(tree_root)) => Some(BatchHeader {
                v: BATCH_VERSION,
                day: self.day,
                first_seq: self.first_seq,
                last_seq: self.last_seq,
                count: self.count,
                tree_root,
            }),
            _ => None,
        }
    }

    fn overlaps(&self, first: u64, last: u64) -> bool {
        self.first_seq <= last && first <= self.last_seq
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerFile {
    v: u32,
    entries: Vec<LedgerEntry>,
}

/// What a `record_*` call changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    New,
    Unchanged,
}

pub struct AnchorLedger {
    dir: PathBuf,
    guard: Mutex<()>,
    _lock: File,
}

impl AnchorLedger {
    /// Open (or create) the ledger in `dir`. One writer per directory.
    pub fn open(dir: &Path) -> Result<Self> {
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
        let ledger = Self {
            dir: dir.to_path_buf(),
            guard: Mutex::new(()),
            _lock: lock,
        };
        // Refuse a corrupt ledger at open, not at the first write.
        ledger.load()?;
        Ok(ledger)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn load(&self) -> Result<LedgerFile> {
        let path = self.dir.join(LEDGER);
        let file: LedgerFile = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(Error::Json)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => LedgerFile {
                v: LEDGER_VERSION,
                entries: Vec::new(),
            },
            Err(e) => return Err(io_err(&path)(e)),
        };
        if file.v != LEDGER_VERSION {
            return Err(Error::Corrupt(format!("unsupported version {}", file.v)));
        }
        for w in file.entries.windows(2) {
            if w[0].day >= w[1].day {
                return Err(Error::Corrupt(
                    "entries are not in strictly increasing day order".into(),
                ));
            }
        }
        Ok(file)
    }

    fn store(&self, file: &LedgerFile) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(file).map_err(Error::Json)?;
        let tmp = self.dir.join(format!("{LEDGER}.tmp"));
        let dst = self.dir.join(LEDGER);
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .map_err(io_err(&tmp))?;
            f.write_all(&bytes).map_err(io_err(&tmp))?;
            f.sync_all().map_err(io_err(&tmp))?;
        }
        fs::rename(&tmp, &dst).map_err(io_err(&dst))?;
        #[cfg(unix)]
        File::open(&self.dir)
            .and_then(|d| d.sync_all())
            .map_err(io_err(&self.dir))?;
        Ok(())
    }

    /// Every entry, by day.
    pub fn entries(&self) -> Result<Vec<LedgerEntry>> {
        Ok(self.load()?.entries)
    }

    pub fn get(&self, day: u64) -> Result<Option<LedgerEntry>> {
        Ok(self.load()?.entries.into_iter().find(|e| e.day == day))
    }

    /// Batched days with no confirmation recorded yet.
    pub fn unconfirmed(&self) -> Result<Vec<u64>> {
        Ok(self
            .load()?
            .entries
            .into_iter()
            .filter(|e| e.status == EntryStatus::Batched && e.confirmed.is_none())
            .map(|e| e.day)
            .collect())
    }

    fn insert(
        &self,
        entry: LedgerEntry,
        same: impl Fn(&LedgerEntry) -> bool,
    ) -> Result<RecordOutcome> {
        let _g = self
            .guard
            .lock()
            .map_err(|_| Error::Corrupt("lock poisoned".into()))?;
        let mut file = self.load()?;
        if let Some(e) = file.entries.iter().find(|e| e.day == entry.day) {
            return if same(e) {
                Ok(RecordOutcome::Unchanged)
            } else {
                Err(Error::Conflict { day: entry.day })
            };
        }
        if let Some(o) = file
            .entries
            .iter()
            .find(|e| e.overlaps(entry.first_seq, entry.last_seq))
        {
            return Err(Error::Overlap {
                day: entry.day,
                other: o.day,
            });
        }
        file.entries.push(entry);
        file.entries.sort_by_key(|e| e.day);
        self.store(&file)?;
        Ok(RecordOutcome::New)
    }

    /// Record a day's batch. Idempotent for the same header; a different header for a recorded
    /// day is a [`Error::Conflict`], and a `seq` range that overlaps another day is an
    /// [`Error::Overlap`].
    pub fn record_batched(&self, header: &BatchHeader, now_ms: u64) -> Result<RecordOutcome> {
        if !header.well_formed() {
            return Err(Error::Corrupt(format!(
                "malformed batch header for day {}",
                header.day
            )));
        }
        let commitment = header.commitment();
        self.insert(
            LedgerEntry {
                day: header.day,
                status: EntryStatus::Batched,
                first_seq: header.first_seq,
                last_seq: header.last_seq,
                count: header.count,
                tree_root: Some(header.tree_root),
                commitment: Some(commitment),
                recorded_at_ms: now_ms,
                confirmed: None,
            },
            |e| e.status == EntryStatus::Batched && e.commitment == Some(commitment),
        )
    }

    /// Report a day that cannot be batched because some of its records were pruned first. The
    /// range is that of the retained records.
    pub fn record_incomplete(
        &self,
        day: u64,
        first_seq: u64,
        last_seq: u64,
        now_ms: u64,
    ) -> Result<RecordOutcome> {
        if last_seq < first_seq {
            return Err(Error::Corrupt(format!("empty range for day {day}")));
        }
        self.insert(
            LedgerEntry {
                day,
                status: EntryStatus::Incomplete,
                first_seq,
                last_seq,
                count: last_seq - first_seq + 1,
                tree_root: None,
                commitment: None,
                recorded_at_ms: now_ms,
                confirmed: None,
            },
            |e| e.status == EntryStatus::Incomplete,
        )
    }

    /// Record that core's ceremony landed the anchor for `day`. Only a batched day can be
    /// confirmed, and a confirmation is written once (a different one is a conflict).
    pub fn mark_confirmed(
        &self,
        day: u64,
        tx_hash: &str,
        block_number: u64,
        now_ms: u64,
    ) -> Result<RecordOutcome> {
        let _g = self
            .guard
            .lock()
            .map_err(|_| Error::Corrupt("lock poisoned".into()))?;
        let mut file = self.load()?;
        let Some(e) = file
            .entries
            .iter_mut()
            .find(|e| e.day == day && e.status == EntryStatus::Batched)
        else {
            return Err(Error::NotBatched { day });
        };
        match &e.confirmed {
            Some(c) if c.tx_hash == tx_hash && c.block_number == block_number => {
                return Ok(RecordOutcome::Unchanged)
            }
            Some(_) => return Err(Error::Conflict { day }),
            None => {}
        }
        e.confirmed = Some(Confirmation {
            tx_hash: tx_hash.to_owned(),
            block_number,
            confirmed_at_ms: now_ms,
        });
        self.store(&file)?;
        Ok(RecordOutcome::New)
    }
}
