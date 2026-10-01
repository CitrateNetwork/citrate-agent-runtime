//! The checkpoint store: begin a step (snapshot), let the tool write, commit; undo a step or a
//! whole session with conflict detection; prune least-recently-used sessions to stay under cap.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use crate::blobs::{self, Staged, BLOBS_DIR};
use crate::error::{io_err, Conflict, Error, Result};
use crate::fsutil::{atomic_write, sync_dir, unique, TempGuard};
use crate::manifest::{Entry, Manifest, SessionMeta, StepStatus, MANIFEST_VERSION};
use crate::paths::{canonical_root, resolve, Resolved};
use crate::session::SessionId;
use crate::state::{self, fingerprint_now, link_target_string, mode_of, Fingerprint, Prior};

/// The lock file that keeps one process per store directory.
pub const LOCK_FILE: &str = "LOCK";
pub(crate) const TMP_DIR: &str = "tmp";
const SESSIONS_DIR: &str = "sessions";
const STEPS_DIR: &str = "steps";
const SESSION_META: &str = "session.json";

/// Size limits. Both are hard: a file or step that does not fit is refused, never half-saved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Total bytes of snapshot blobs kept. Older steps are pruned (least recently used session
    /// first, oldest step first) to make room; a step that alone exceeds it is refused.
    pub max_store_bytes: u64,
    /// Largest single file that is snapshotted. A change to a bigger file is refused.
    pub max_file_bytes: u64,
}

impl Default for Config {
    /// 512 MiB store, 64 MiB per file. Conservative defaults; the app may lower them.
    fn default() -> Self {
        Self {
            max_store_bytes: 512 * 1024 * 1024,
            max_file_bytes: 64 * 1024 * 1024,
        }
    }
}

/// A change a tool is about to make inside the granted folder. Paths are relative to the folder
/// (an absolute path inside it is accepted too).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Create or overwrite a file with the given content (identified by its SHA-256).
    Write { path: PathBuf, sha256: String },
    /// Delete a file or a symbolic link.
    Delete { path: PathBuf },
    /// Rename a file or link, replacing whatever is at `to`.
    Rename { from: PathBuf, to: PathBuf },
}

impl Change {
    pub fn write(path: impl AsRef<Path>, new_content: &[u8]) -> Self {
        Change::Write {
            path: path.as_ref().to_path_buf(),
            sha256: state::sha256_hex(new_content),
        }
    }

    pub fn delete(path: impl AsRef<Path>) -> Self {
        Change::Delete {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Self {
        Change::Rename {
            from: from.as_ref().to_path_buf(),
            to: to.as_ref().to_path_buf(),
        }
    }
}

/// A step as the UI sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepSummary {
    pub session: String,
    pub seq: u64,
    pub status: StepStatus,
    /// Paths touched, relative to `root`, in the order the step lists them.
    pub paths: Vec<String>,
    pub root: PathBuf,
}

/// What an undo did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UndoReport {
    /// Steps undone, newest first.
    pub steps: Vec<u64>,
    /// Paths restored, in the order they were restored.
    pub restored: Vec<String>,
    /// For a session undo: steps at or below this seq were pruned earlier and could not be undone.
    pub pruned_through: Option<u64>,
}

/// Store usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    pub blob_bytes: u64,
    pub blob_count: u64,
    pub steps: u64,
}

struct Inner {
    manifests: BTreeMap<(String, u64), Manifest>,
    sessions: HashMap<String, SessionMeta>,
    blobs: HashMap<String, u64>,
    /// Absolute paths with a step in flight.
    busy: HashSet<PathBuf>,
    tick: u64,
}

/// Undo checkpoints for agent file writes, under one app-data directory. One process per
/// directory (OS file lock); within the process every operation is serialized.
pub struct CheckpointStore {
    dir: PathBuf,
    cfg: Config,
    inner: Mutex<Inner>,
    _lock: File,
}

/// A step that has been snapshotted. Perform the change, then [`Step::commit`] (or
/// [`Step::abort`] if the change did not happen). Dropping it uncommitted marks it
/// [`StepStatus::Interrupted`].
pub struct Step<'s> {
    store: &'s CheckpointStore,
    session: SessionId,
    seq: u64,
    finished: bool,
}

impl std::fmt::Debug for Step<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Step")
            .field("session", &self.session)
            .field("seq", &self.seq)
            .finish()
    }
}

impl Step<'_> {
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Record the post-change state and release the paths.
    pub fn commit(mut self) -> Result<StepSummary> {
        let r = self.store.finish(&self.session, self.seq, true);
        if r.is_ok() {
            self.finished = true;
        }
        r
    }

    /// The change did not happen (or failed): mark the step interrupted and release the paths.
    /// Undo stays possible and accepts either the prior or the intended state.
    pub fn abort(mut self) -> Result<StepSummary> {
        let r = self.store.finish(&self.session, self.seq, false);
        if r.is_ok() {
            self.finished = true;
        }
        r
    }
}

impl Drop for Step<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.store.finish(&self.session, self.seq, false);
        }
    }
}

enum Kind {
    Write(String),
    Delete,
    RenameFrom,
    RenameTo(usize),
}

struct Plan {
    res: Resolved,
    kind: Kind,
}

impl CheckpointStore {
    /// Open (or create) the store in `dir`, recovering from a crash: temp files are removed, steps
    /// that were in flight become [`StepStatus::Interrupted`], unreferenced blobs are collected.
    pub fn open(dir: &Path, cfg: Config) -> Result<Self> {
        for sub in ["", TMP_DIR, BLOBS_DIR, SESSIONS_DIR] {
            let d = dir.join(sub);
            fs::create_dir_all(&d).map_err(io_err(&d))?;
        }
        // Snapshots are copies of the member's files: keep the store private to the member.
        state::set_mode(dir, Some(0o700))?;
        let lock_path = dir.join(LOCK_FILE);
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
        let store_dir = dir.to_path_buf();
        let tmp = dir.join(TMP_DIR);
        for e in fs::read_dir(&tmp).map_err(io_err(&tmp))? {
            let p = e.map_err(io_err(&tmp))?.path();
            let r = if p.is_dir() {
                fs::remove_dir_all(&p)
            } else {
                fs::remove_file(&p)
            };
            r.map_err(io_err(&p))?;
        }
        let store = Self {
            dir: store_dir,
            cfg,
            inner: Mutex::new(Inner {
                manifests: BTreeMap::new(),
                sessions: HashMap::new(),
                blobs: HashMap::new(),
                busy: HashSet::new(),
                tick: 0,
            }),
            _lock: lock,
        };
        store.load()?;
        Ok(store)
    }

    fn load(&self) -> Result<()> {
        let mut g = self.lock()?;
        let sessions = self.dir.join(SESSIONS_DIR);
        for e in fs::read_dir(&sessions).map_err(io_err(&sessions))? {
            let sdir = e.map_err(io_err(&sessions))?.path();
            let name = sdir
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if !sdir.is_dir() || SessionId::new(&name).is_err() {
                continue;
            }
            let meta_path = sdir.join(SESSION_META);
            let mut meta: SessionMeta = match fs::read(&meta_path) {
                Ok(b) => serde_json::from_slice(&b).map_err(|_| Error::Corrupt {
                    what: format!("{} is not valid session metadata", meta_path.display()),
                })?,
                Err(e) if e.kind() == ErrorKind::NotFound => SessionMeta::default(),
                Err(e) => return Err(io_err(&meta_path)(e)),
            };
            let steps = sdir.join(STEPS_DIR);
            let rd = match fs::read_dir(&steps) {
                Ok(rd) => rd,
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    g.sessions.insert(name, meta);
                    continue;
                }
                Err(e) => return Err(io_err(&steps)(e)),
            };
            for e in rd {
                let p = e.map_err(io_err(&steps))?.path();
                if p.extension().and_then(|x| x.to_str()) != Some("json") {
                    continue;
                }
                let bytes = fs::read(&p).map_err(io_err(&p))?;
                let mut m: Manifest =
                    serde_json::from_slice(&bytes).map_err(|_| Error::Corrupt {
                        what: format!("{} is not a valid step manifest", p.display()),
                    })?;
                if m.version != MANIFEST_VERSION || m.session != name {
                    return Err(Error::Corrupt {
                        what: format!("{} has an unexpected version or session", p.display()),
                    });
                }
                if m.status == StepStatus::Prepared {
                    m.status = StepStatus::Interrupted;
                    self.write_manifest(&m)?;
                }
                meta.last_seq = meta.last_seq.max(m.seq);
                g.manifests.insert((name.clone(), m.seq), m);
            }
            g.tick = g.tick.max(meta.last_used);
            g.sessions.insert(name, meta);
        }
        for (hex, len) in blobs::scan(&self.dir)? {
            g.blobs.insert(hex, len);
        }
        self.gc(&mut g)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>> {
        self.inner.lock().map_err(|_| Error::Poisoned)
    }

    fn tmp_dir(&self) -> PathBuf {
        self.dir.join(TMP_DIR)
    }

    fn steps_dir(&self, session: &str) -> PathBuf {
        self.dir.join(SESSIONS_DIR).join(session).join(STEPS_DIR)
    }

    fn manifest_path(&self, session: &str, seq: u64) -> PathBuf {
        self.steps_dir(session).join(format!("{seq:016}.json"))
    }

    fn write_manifest(&self, m: &Manifest) -> Result<()> {
        let d = self.steps_dir(&m.session);
        fs::create_dir_all(&d).map_err(io_err(&d))?;
        let bytes = serde_json::to_vec(m).map_err(Error::Json)?;
        atomic_write(
            &self.tmp_dir(),
            &self.manifest_path(&m.session, m.seq),
            &bytes,
        )
    }

    fn write_meta(&self, session: &str, meta: &SessionMeta) -> Result<()> {
        let d = self.dir.join(SESSIONS_DIR).join(session);
        fs::create_dir_all(&d).map_err(io_err(&d))?;
        let bytes = serde_json::to_vec(meta).map_err(Error::Json)?;
        atomic_write(&self.tmp_dir(), &d.join(SESSION_META), &bytes)
    }

    fn touch(&self, g: &mut Inner, session: &str) -> Result<()> {
        g.tick += 1;
        let tick = g.tick;
        let meta = g.sessions.entry(session.to_string()).or_default();
        meta.last_used = tick;
        let meta = meta.clone();
        self.write_meta(session, &meta)
    }

    /// Remove every blob no manifest refers to.
    fn gc(&self, g: &mut Inner) -> Result<()> {
        let referenced: HashSet<&str> = g
            .manifests
            .values()
            .flat_map(|m| m.entries.iter())
            .filter_map(|e| match &e.before {
                Prior::File { blob, .. } => Some(blob.as_str()),
                _ => None,
            })
            .collect();
        let dead: Vec<String> = g
            .blobs
            .keys()
            .filter(|h| !referenced.contains(h.as_str()))
            .cloned()
            .collect();
        for hex in dead {
            let p = blobs::blob_path(&self.dir, &hex);
            match fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(io_err(&p)(e)),
            }
            g.blobs.remove(&hex);
        }
        Ok(())
    }

    /// Evict the oldest step of the least recently used session until `needed` more bytes fit.
    /// Steps in flight are never evicted. Within a session eviction is oldest first, so "pruned
    /// through seq N" is exact.
    fn prune_to_fit(&self, g: &mut Inner, needed: u64) -> Result<()> {
        let cap = self.cfg.max_store_bytes;
        loop {
            let total: u64 = g.blobs.values().sum();
            if total.saturating_add(needed) <= cap {
                return Ok(());
            }
            let victim = g
                .sessions
                .iter()
                .filter_map(|(sid, meta)| {
                    let (key, m) = g
                        .manifests
                        .range((sid.clone(), 0)..=(sid.clone(), u64::MAX))
                        .next()?;
                    (m.status != StepStatus::Prepared).then(|| (meta.last_used, key.clone()))
                })
                .min();
            let Some((_, (sid, seq))) = victim else {
                return Err(Error::StoreFull { needed, cap });
            };
            let p = self.manifest_path(&sid, seq);
            match fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(io_err(&p)(e)),
            }
            g.manifests.remove(&(sid.clone(), seq));
            let meta = g.sessions.entry(sid.clone()).or_default();
            meta.pruned_through = meta.pruned_through.max(seq);
            let meta = meta.clone();
            self.write_meta(&sid, &meta)?;
            self.gc(g)?;
        }
    }

    /// Snapshot the prior state of every path `changes` will touch, under the granted folder
    /// `root`, and record a prepared step. Returns only after the snapshot and the manifest are
    /// durable, so the tool may write as soon as this returns.
    ///
    /// Refuses (and records nothing) when a path is outside `root`, goes through a symlinked
    /// directory, is a directory, would write through a symbolic link, is over the per-file cap,
    /// has another step in flight, or when the step would not fit in the store.
    pub fn begin_step(
        &self,
        session: &SessionId,
        root: &Path,
        changes: &[Change],
    ) -> Result<Step<'_>> {
        let root_canon = canonical_root(root)?;
        let mut plans: Vec<Plan> = Vec::new();
        for c in changes {
            match c {
                Change::Write { path, sha256 } => plans.push(Plan {
                    res: resolve(&root_canon, root, path)?,
                    kind: Kind::Write(sha256.clone()),
                }),
                Change::Delete { path } => plans.push(Plan {
                    res: resolve(&root_canon, root, path)?,
                    kind: Kind::Delete,
                }),
                Change::Rename { from, to } => {
                    let from_idx = plans.len();
                    plans.push(Plan {
                        res: resolve(&root_canon, root, from)?,
                        kind: Kind::RenameFrom,
                    });
                    plans.push(Plan {
                        res: resolve(&root_canon, root, to)?,
                        kind: Kind::RenameTo(from_idx),
                    });
                }
            }
        }
        let mut seen = HashSet::new();
        for p in &plans {
            if !seen.insert(p.res.rel.clone()) {
                return Err(Error::Path {
                    path: p.res.rel.clone(),
                    reason: "listed more than once in one step".into(),
                });
            }
        }

        let mut g = self.lock()?;
        for p in &plans {
            if g.busy.contains(&p.res.abs) {
                return Err(Error::Busy {
                    path: p.res.rel.clone(),
                });
            }
        }

        let tmp = self.tmp_dir();
        let mut staged: Vec<Staged> = Vec::new();
        let mut entries: Vec<Entry> = Vec::new();
        for p in &plans {
            let before = self.capture(&tmp, p, &mut staged)?;
            let expected_after = match &p.kind {
                Kind::Write(sha) => Fingerprint::File {
                    sha256: sha.clone(),
                },
                Kind::Delete | Kind::RenameFrom => Fingerprint::Absent,
                Kind::RenameTo(i) => entries
                    .get(*i)
                    .map(|e| e.before.fingerprint())
                    .unwrap_or(Fingerprint::Absent),
            };
            entries.push(Entry {
                path: p.res.rel.clone(),
                before,
                expected_after,
                after: None,
            });
        }

        let mut new_hexes = HashSet::new();
        let mut needed = 0u64;
        for s in &staged {
            if !g.blobs.contains_key(&s.hex) && new_hexes.insert(s.hex.clone()) {
                needed += s.size;
            }
        }
        if needed > self.cfg.max_store_bytes {
            return Err(Error::StepTooLarge {
                size: needed,
                cap: self.cfg.max_store_bytes,
            });
        }
        self.prune_to_fit(&mut g, needed)?;
        for s in staged {
            let (hex, size) = (s.hex.clone(), s.size);
            blobs::install(&self.dir, s)?;
            g.blobs.insert(hex, size);
        }

        let mut created_dirs: Vec<String> = Vec::new();
        for p in &plans {
            if matches!(p.kind, Kind::Write(_) | Kind::RenameTo(_)) {
                for d in &p.res.missing_dirs {
                    if !created_dirs.contains(d) {
                        created_dirs.push(d.clone());
                    }
                }
            }
        }
        created_dirs.sort_by_key(|d| d.matches('/').count());

        let sid = session.as_str().to_string();
        let seq = {
            let meta = g.sessions.entry(sid.clone()).or_default();
            meta.last_seq += 1;
            meta.last_seq
        };
        let m = Manifest {
            version: MANIFEST_VERSION,
            session: sid.clone(),
            seq,
            root: root_canon,
            status: StepStatus::Prepared,
            entries,
            created_dirs,
        };
        self.write_manifest(&m)?;
        for p in &plans {
            g.busy.insert(p.res.abs.clone());
        }
        g.manifests.insert((sid.clone(), seq), m);
        self.touch(&mut g, &sid)?;
        Ok(Step {
            store: self,
            session: session.clone(),
            seq,
            finished: false,
        })
    }

    fn capture(&self, tmp: &Path, p: &Plan, staged: &mut Vec<Staged>) -> Result<Prior> {
        let rel = &p.res.rel;
        let abs = &p.res.abs;
        let unsupported = |reason: &str| Error::Unsupported {
            path: rel.clone(),
            reason: reason.to_string(),
        };
        let meta = match fs::symlink_metadata(abs) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return match p.kind {
                    Kind::RenameFrom => Err(unsupported("the rename source does not exist")),
                    _ => Ok(Prior::Absent),
                };
            }
            Err(e) => return Err(io_err(abs)(e)),
        };
        let ft = meta.file_type();
        if ft.is_symlink() {
            if matches!(p.kind, Kind::Write(_)) {
                return Err(unsupported(
                    "is a symbolic link; writing through it is refused (the link itself may be deleted or renamed)",
                ));
            }
            return match link_target_string(abs)? {
                Some(target) => Ok(Prior::Symlink { target }),
                None => Err(unsupported("is a symbolic link with a non-UTF-8 target")),
            };
        }
        if ft.is_dir() {
            return Err(unsupported(
                "is a directory; only files and symbolic links are checkpointed",
            ));
        }
        if !ft.is_file() {
            return Err(unsupported("is a special file"));
        }
        let cap = self.cfg.max_file_bytes;
        if meta.len() > cap {
            return Err(Error::TooLarge {
                path: rel.clone(),
                size: meta.len(),
                cap,
            });
        }
        let s = blobs::stage(tmp, abs, rel, cap)?;
        let prior = Prior::File {
            blob: s.hex.clone(),
            size: s.size,
            mode: mode_of(&meta),
        };
        staged.push(s);
        Ok(prior)
    }

    fn finish(&self, session: &SessionId, seq: u64, commit: bool) -> Result<StepSummary> {
        let mut g = self.lock()?;
        let key = (session.as_str().to_string(), seq);
        let Some(m) = g.manifests.get(&key).cloned() else {
            return Err(Error::NotFound {
                session: key.0,
                seq,
            });
        };
        if m.status != StepStatus::Prepared {
            return Ok(summary(&m));
        }
        let mut done = m.clone();
        let res = (|| {
            if commit {
                for e in &mut done.entries {
                    e.after = Some(fingerprint_now(&done.root.join(&e.path))?);
                }
                done.status = StepStatus::Committed;
            } else {
                done.status = StepStatus::Interrupted;
            }
            self.write_manifest(&done)
        })();
        for e in &m.entries {
            g.busy.remove(&m.root.join(&e.path));
        }
        res?;
        g.manifests.insert(key.clone(), done.clone());
        self.touch(&mut g, &key.0)?;
        Ok(summary(&done))
    }

    /// Every step still on record for `session`, oldest first.
    pub fn steps(&self, session: &SessionId) -> Result<Vec<StepSummary>> {
        let g = self.lock()?;
        let s = session.as_str().to_string();
        Ok(g.manifests
            .range((s.clone(), 0)..=(s, u64::MAX))
            .map(|(_, m)| summary(m))
            .collect())
    }

    /// Store usage.
    pub fn usage(&self) -> Result<Usage> {
        let g = self.lock()?;
        Ok(Usage {
            blob_bytes: g.blobs.values().sum(),
            blob_count: g.blobs.len() as u64,
            steps: g.manifests.len() as u64,
        })
    }

    /// Undo one step: restore every path it touched to its prior state. Refused, with nothing
    /// changed, if any path is neither in the step's post state nor already in its prior state.
    pub fn undo_step(&self, session: &SessionId, seq: u64) -> Result<UndoReport> {
        let mut g = self.lock()?;
        let sid = session.as_str().to_string();
        let Some(m) = g.manifests.get(&(sid.clone(), seq)).cloned() else {
            let pruned = g
                .sessions
                .get(&sid)
                .is_some_and(|meta| seq > 0 && seq <= meta.pruned_through);
            return Err(if pruned {
                Error::Pruned { session: sid, seq }
            } else {
                Error::NotFound { session: sid, seq }
            });
        };
        match m.status {
            StepStatus::Undone => return Err(Error::AlreadyUndone { session: sid, seq }),
            StepStatus::Prepared => {
                return Err(Error::Busy {
                    path: m
                        .entries
                        .first()
                        .map(|e| e.path.clone())
                        .unwrap_or_default(),
                })
            }
            StepStatus::Committed | StepStatus::Interrupted => {}
        }
        self.undo_many(&mut g, &sid, vec![m])
    }

    /// Undo every step of `session` that is not undone yet, newest first. All or nothing on
    /// conflicts: the whole sequence is checked before anything is restored.
    pub fn undo_session(&self, session: &SessionId) -> Result<UndoReport> {
        let mut g = self.lock()?;
        let sid = session.as_str().to_string();
        let mut steps: Vec<Manifest> = g
            .manifests
            .range((sid.clone(), 0)..=(sid.clone(), u64::MAX))
            .map(|(_, m)| m.clone())
            .filter(|m| m.status != StepStatus::Undone)
            .collect();
        steps.reverse();
        if let Some(m) = steps.iter().find(|m| m.status == StepStatus::Prepared) {
            return Err(Error::Busy {
                path: m
                    .entries
                    .first()
                    .map(|e| e.path.clone())
                    .unwrap_or_default(),
            });
        }
        let pruned = g
            .sessions
            .get(&sid)
            .map(|meta| meta.pruned_through)
            .filter(|n| *n > 0);
        let mut report = if steps.is_empty() {
            UndoReport::default()
        } else {
            self.undo_many(&mut g, &sid, steps)?
        };
        report.pruned_through = pruned;
        Ok(report)
    }

    fn undo_many(&self, g: &mut Inner, sid: &str, steps: Vec<Manifest>) -> Result<UndoReport> {
        for m in &steps {
            for e in &m.entries {
                if g.busy.contains(&m.root.join(&e.path)) {
                    return Err(Error::Busy {
                        path: e.path.clone(),
                    });
                }
            }
        }
        // Preflight against a virtual view, so a multi-step undo is checked as a whole.
        let mut virt: HashMap<PathBuf, Fingerprint> = HashMap::new();
        let mut conflicts = Vec::new();
        for m in &steps {
            for e in &m.entries {
                let abs = m.root.join(&e.path);
                let cur = match virt.get(&abs) {
                    Some(f) => f.clone(),
                    None => fingerprint_now(&abs)?,
                };
                let before = e.before.fingerprint();
                if cur != before && &cur != e.post() {
                    conflicts.push(Conflict {
                        seq: m.seq,
                        path: e.path.clone(),
                        found: cur.to_string(),
                    });
                }
                virt.insert(abs, before);
            }
        }
        if !conflicts.is_empty() {
            return Err(Error::Conflict(conflicts));
        }
        for m in &steps {
            for e in &m.entries {
                if let Prior::File { blob, .. } = &e.before {
                    blobs::verify(&self.dir, blob)?;
                }
            }
        }
        let mut report = UndoReport::default();
        for m in steps {
            for e in &m.entries {
                self.restore(&m.root.join(&e.path), &e.before)?;
                report.restored.push(e.path.clone());
            }
            for d in m.created_dirs.iter().rev() {
                // Only removed when empty: anything the member put there since stays.
                let _ = fs::remove_dir(m.root.join(d));
            }
            let mut done = m.clone();
            done.status = StepStatus::Undone;
            self.write_manifest(&done)?;
            report.steps.push(m.seq);
            g.manifests.insert((sid.to_string(), m.seq), done);
        }
        self.touch(g, sid)?;
        Ok(report)
    }

    /// Put `prior` back at `abs`, atomically per path (temp sibling, then rename over).
    fn restore(&self, abs: &Path, prior: &Prior) -> Result<()> {
        let parent = abs
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| Error::Path {
                path: abs.display().to_string(),
                reason: "has no parent directory".into(),
            })?;
        match prior {
            Prior::Absent => match fs::symlink_metadata(abs) {
                Ok(m) if m.is_dir() => Err(Error::Unsupported {
                    path: abs.display().to_string(),
                    reason: "is now a directory; not removed".into(),
                }),
                Ok(_) => fs::remove_file(abs).map_err(io_err(abs)),
                Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
                Err(e) => Err(io_err(abs)(e)),
            },
            Prior::File { blob, mode, .. } => {
                fs::create_dir_all(&parent).map_err(io_err(&parent))?;
                let tmp = parent.join(unique(".citrate-undo-", ".part"));
                blobs::copy_verified(&self.dir, blob, &tmp)?;
                let mut guard = TempGuard::new(tmp.clone());
                state::set_mode(&tmp, *mode)?;
                fs::rename(&tmp, abs).map_err(io_err(abs))?;
                guard.disarm();
                sync_dir(&parent)
            }
            Prior::Symlink { target } => restore_symlink(&parent, abs, target),
        }
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(unix)]
fn restore_symlink(parent: &Path, abs: &Path, target: &str) -> Result<()> {
    fs::create_dir_all(parent).map_err(io_err(parent))?;
    let tmp = parent.join(unique(".citrate-undo-", ".link"));
    std::os::unix::fs::symlink(target, &tmp).map_err(io_err(&tmp))?;
    let mut guard = TempGuard::new(tmp.clone());
    fs::rename(&tmp, abs).map_err(io_err(abs))?;
    guard.disarm();
    sync_dir(parent)
}

#[cfg(not(unix))]
fn restore_symlink(_parent: &Path, abs: &Path, _target: &str) -> Result<()> {
    Err(Error::Unsupported {
        path: abs.display().to_string(),
        reason: "restoring symbolic links is only supported on Unix".into(),
    })
}

fn summary(m: &Manifest) -> StepSummary {
    StepSummary {
        session: m.session.clone(),
        seq: m.seq,
        status: m.status,
        paths: m.entries.iter().map(|e| e.path.clone()).collect(),
        root: m.root.clone(),
    }
}
