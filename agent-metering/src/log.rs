//! A local, append-only JSONL log of turn records.

use crate::record::TurnRecord;
use crate::MeteringError;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// One JSON record per line. The file stays on the member's machine.
#[derive(Debug, Clone)]
pub struct MeteringLog {
    path: PathBuf,
}

impl MeteringLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        MeteringLog { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record (creates the file and its parent directories on first use).
    pub fn append(&self, rec: &TurnRecord) -> Result<(), MeteringError> {
        let mut line =
            serde_json::to_string(rec).map_err(|e| MeteringError::Serialize(e.to_string()))?;
        line.push('\n');
        if let Some(dir) = self.path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(|e| MeteringError::Io(e.to_string()))?;
            }
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| MeteringError::Io(e.to_string()))?;
        f.write_all(line.as_bytes())
            .map_err(|e| MeteringError::Io(e.to_string()))
    }

    /// Every record in order. A missing file is an empty log; a bad line is an error naming it
    /// (1-based), never silently skipped.
    pub fn read_all(&self) -> Result<Vec<TurnRecord>, MeteringError> {
        let f = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(MeteringError::Io(e.to_string())),
        };
        let mut out = Vec::new();
        for (i, line) in BufReader::new(f).lines().enumerate() {
            let line = line.map_err(|e| MeteringError::Io(e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            let rec = serde_json::from_str(&line).map_err(|e| MeteringError::Parse {
                line: i + 1,
                msg: e.to_string(),
            })?;
            out.push(rec);
        }
        Ok(out)
    }
}
