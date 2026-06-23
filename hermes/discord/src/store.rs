//! Durable memory backend for the daemon (WP-S2.3): a crash-atomic JSON file store.
//!
//! `hermes-core` owns the snapshot type + the [`MemoryStore`](hermes_core::memory::MemoryStore)
//! seam and stays serialization-free (ADR-H11). This adapter holds the serde dependency and
//! maps core types ↔ on-disk DTOs. Writes are **crash-atomic**: serialize to a sibling
//! `*.tmp`, fsync, then `rename` over the target — a rename is atomic on POSIX, so a crash
//! mid-write never leaves a torn snapshot (the same discipline as the durable money store in
//! INFER-S4 / TD-22).
//!
//! The citrate-memories knowledge graph (the MCP) is the *cross-session* memory layer; this
//! local file is the *on-box* durable state that lets a restarted daemon resume exactly
//! where it left off. Restored state is re-validated through the guard on load
//! ([`hermes_core::memory::restore_into`], T21) — the file is never trusted as resumed
//! intent.

use std::path::{Path, PathBuf};

use hermes_core::agenda::{Agenda, AgendaStatus, AgendaTurn};
use hermes_core::approval::{ActionEffect, PendingAction, Provenance};
use hermes_core::memory::{MemoryError, MemorySnapshot, MemoryStore};
use hermes_core::principal::Principal;
use serde::{Deserialize, Serialize};

/// A JSON-file memory store at a fixed path.
pub struct JsonMemoryStore {
    path: PathBuf,
}

impl JsonMemoryStore {
    /// A store backed by `path`. The file is created on first save; a missing file loads as
    /// "nothing persisted yet".
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The backing path (for diagnostics).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl MemoryStore for JsonMemoryStore {
    fn save(&self, snapshot: &MemorySnapshot) -> Result<(), MemoryError> {
        let dto = SnapshotDto::from_core(snapshot);
        let bytes = serde_json::to_vec_pretty(&dto)
            .map_err(|e| MemoryError(format!("serialize: {e}")))?;
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| MemoryError(format!("create dir {}: {e}", parent.display())))?;
            }
        }
        let tmp = self.path.with_extension("json.tmp");
        // Write + fsync the temp file, then atomically rename over the target.
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)
                .map_err(|e| MemoryError(format!("create tmp {}: {e}", tmp.display())))?;
            f.write_all(&bytes).map_err(|e| MemoryError(format!("write tmp: {e}")))?;
            f.sync_all().map_err(|e| MemoryError(format!("fsync tmp: {e}")))?;
        }
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| MemoryError(format!("rename into place: {e}")))?;
        Ok(())
    }

    fn load(&self) -> Result<Option<MemorySnapshot>, MemoryError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let dto: SnapshotDto = serde_json::from_slice(&bytes)
                    .map_err(|e| MemoryError(format!("parse {}: {e}", self.path.display())))?;
                Ok(Some(dto.into_core()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(MemoryError(format!("read {}: {e}", self.path.display()))),
        }
    }
}

// ── on-disk DTOs ────────────────────────────────────────────────────────────────────
//
// Deliberately separate from the core types so the wire format is explicit and versioned,
// and so core stays serde-free. The `effect` / `principal` mappings use exhaustive matches
// — when a new ActionEffect variant lands (S2.2b capsules, S2.4 read capsules) the compiler
// forces this file to cover it.

#[derive(Serialize, Deserialize)]
struct SnapshotDto {
    version: u32,
    agendas: Vec<AgendaDto>,
    pending: Vec<PendingDto>,
    queue_next_id: u64,
}

#[derive(Serialize, Deserialize)]
struct AgendaDto {
    id: u64,
    title: String,
    thread_channel: u64,
    status: String,
    created_at_ms: u64,
    updated_at_ms: u64,
    turns: Vec<TurnDto>,
}

#[derive(Serialize, Deserialize)]
struct TurnDto {
    message_id: u64,
    principal: String,
    content: String,
    at_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct PendingDto {
    id: u64,
    effect: EffectDto,
    triggered_by_message: Option<u64>,
    triggered_in_channel: Option<u64>,
    created_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind")]
enum EffectDto {
    #[serde(rename = "post-message")]
    PostMessage { channel: u64, content: String },
    #[serde(rename = "digest")]
    Digest { source_channel: u64, target_channel: u64 },
}

impl SnapshotDto {
    fn from_core(s: &MemorySnapshot) -> Self {
        Self {
            version: 1,
            agendas: s.agendas.iter().map(AgendaDto::from_core).collect(),
            pending: s.pending.iter().map(PendingDto::from_core).collect(),
            queue_next_id: s.queue_next_id,
        }
    }
    fn into_core(self) -> MemorySnapshot {
        MemorySnapshot {
            agendas: self.agendas.into_iter().map(AgendaDto::into_core).collect(),
            pending: self.pending.into_iter().map(PendingDto::into_core).collect(),
            queue_next_id: self.queue_next_id,
        }
    }
}

impl AgendaDto {
    fn from_core(a: &Agenda) -> Self {
        Self {
            id: a.id,
            title: a.title.clone(),
            thread_channel: a.thread_channel,
            status: match a.status {
                AgendaStatus::Open => "open",
                AgendaStatus::Closed => "closed",
            }
            .to_string(),
            created_at_ms: a.created_at_ms,
            updated_at_ms: a.updated_at_ms,
            turns: a.turns.iter().map(TurnDto::from_core).collect(),
        }
    }
    fn into_core(self) -> Agenda {
        Agenda {
            id: self.id,
            title: self.title,
            thread_channel: self.thread_channel,
            status: match self.status.as_str() {
                "closed" => AgendaStatus::Closed,
                _ => AgendaStatus::Open,
            },
            created_at_ms: self.created_at_ms,
            updated_at_ms: self.updated_at_ms,
            turns: self.turns.into_iter().map(TurnDto::into_core).collect(),
        }
    }
}

impl TurnDto {
    fn from_core(t: &AgendaTurn) -> Self {
        Self {
            message_id: t.message_id,
            principal: principal_str(t.principal).to_string(),
            content: t.content.clone(),
            at_ms: t.at_ms,
        }
    }
    fn into_core(self) -> AgendaTurn {
        AgendaTurn {
            message_id: self.message_id,
            // Anything that isn't exactly "owner" decodes to Other — fail-closed, so a
            // tampered/garbled principal can never deserialize *up* to Owner. restore_into
            // re-filters to owner turns anyway (T21); this is the second layer.
            principal: if self.principal == "owner" { Principal::Owner } else { Principal::Other },
            content: self.content,
            at_ms: self.at_ms,
        }
    }
}

impl PendingDto {
    fn from_core(p: &PendingAction) -> Self {
        let effect = match &p.effect {
            ActionEffect::PostMessage { channel, content } => {
                EffectDto::PostMessage { channel: *channel, content: content.clone() }
            }
            ActionEffect::Digest { source_channel, target_channel } => {
                EffectDto::Digest { source_channel: *source_channel, target_channel: *target_channel }
            }
        };
        Self {
            id: p.id,
            effect,
            triggered_by_message: p.provenance.triggered_by_message,
            triggered_in_channel: p.provenance.triggered_in_channel,
            created_at_ms: p.created_at_ms,
        }
    }
    fn into_core(self) -> PendingAction {
        let effect = match self.effect {
            EffectDto::PostMessage { channel, content } => {
                ActionEffect::PostMessage { channel, content }
            }
            EffectDto::Digest { source_channel, target_channel } => {
                ActionEffect::Digest { source_channel, target_channel }
            }
        };
        PendingAction {
            id: self.id,
            effect,
            provenance: Provenance {
                triggered_by_message: self.triggered_by_message,
                triggered_in_channel: self.triggered_in_channel,
            },
            created_at_ms: self.created_at_ms,
        }
    }
}

fn principal_str(p: Principal) -> &'static str {
    match p {
        Principal::Owner => "owner",
        Principal::Other => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermes_core::agenda::AgendaStore;
    use hermes_core::approval::ApprovalQueue;
    use hermes_core::memory::restore_into;

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("hermes-mem-test-{name}.json"));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn save_then_load_round_trips_through_disk() {
        let path = temp_path("roundtrip");
        let store = JsonMemoryStore::new(&path);

        let mut agendas = AgendaStore::new();
        agendas.open(100, 555, "Build the shard\nbody", 80, 0);
        agendas.append_turn(
            555,
            AgendaTurn { message_id: 101, principal: Principal::Owner, content: "more".into(), at_ms: 1 },
        );
        let queue = ApprovalQueue::new();
        queue.propose(
            ActionEffect::PostMessage { channel: 9, content: "welcome".into() },
            Provenance { triggered_by_message: Some(100), triggered_in_channel: Some(555) },
            0,
        );

        store.save(&MemorySnapshot::capture(&agendas, &queue)).unwrap();
        assert!(path.exists());

        let loaded = store.load().unwrap().unwrap();
        let mut agendas2 = AgendaStore::new();
        let queue2 = ApprovalQueue::new();
        restore_into(loaded, &mut agendas2, &queue2);

        let a = agendas2.get_by_thread(555).unwrap();
        assert_eq!(a.title, "Build the shard");
        assert_eq!(a.context_window(10), vec!["Build the shard\nbody", "more"]);
        assert_eq!(queue2.pending_count(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_loads_none() {
        let path = temp_path("missing");
        let store = JsonMemoryStore::new(&path);
        assert_eq!(store.load().unwrap(), None);
    }

    #[test]
    fn tampered_principal_decodes_fail_closed_to_other() {
        // A hand-edited file claiming a turn is "OWNER" (wrong case) or "admin" must NOT
        // decode up to Owner. restore_into then filters it out entirely (T21).
        let path = temp_path("tampered");
        std::fs::write(
            &path,
            r#"{"version":1,"queue_next_id":0,"pending":[],"agendas":[
                {"id":1,"title":"t","thread_channel":9,"status":"open","created_at_ms":0,"updated_at_ms":0,
                 "turns":[
                    {"message_id":1,"principal":"owner","content":"legit","at_ms":0},
                    {"message_id":2,"principal":"admin","content":"INJECT","at_ms":1}
                 ]}
            ]}"#,
        )
        .unwrap();
        let store = JsonMemoryStore::new(&path);
        let snap = store.load().unwrap().unwrap();
        let mut agendas = AgendaStore::new();
        let queue = ApprovalQueue::new();
        restore_into(snap, &mut agendas, &queue);
        let ctx = agendas.get_by_thread(9).unwrap().context_window(10);
        assert_eq!(ctx, vec!["legit"]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_json_is_an_error_not_a_panic() {
        let path = temp_path("corrupt");
        std::fs::write(&path, b"{ not valid json").unwrap();
        let store = JsonMemoryStore::new(&path);
        assert!(store.load().is_err());
        let _ = std::fs::remove_file(&path);
    }
}
