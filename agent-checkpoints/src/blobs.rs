//! Content-addressed blob store: `blobs/<first two hex>/<sha256 hex>`. A blob is written to a temp
//! file while being hashed, fsynced, then renamed into place, so a crash leaves either a complete
//! blob or a temp file that the next open removes.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{io_err, Error, Result};
use crate::fsutil::{sync_dir, unique, TempGuard};

pub(crate) const BLOBS_DIR: &str = "blobs";

pub(crate) fn blob_path(store: &Path, hex: &str) -> PathBuf {
    let shard = hex.get(..2).unwrap_or("00");
    store.join(BLOBS_DIR).join(shard).join(hex)
}

pub(crate) fn is_blob_name(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// A snapshot copied into the store's temp dir, hashed, not yet installed.
pub(crate) struct Staged {
    pub hex: String,
    pub size: u64,
    guard: TempGuard,
}

/// Copy `src` into `tmp_dir`, hashing as it goes. Refuses (`TooLarge`) as soon as more than
/// `cap` bytes have been read, so a file that grows during the copy is still bounded.
pub(crate) fn stage(tmp_dir: &Path, src: &Path, rel: &str, cap: u64) -> Result<Staged> {
    let tmp = tmp_dir.join(unique("blob-", ".part"));
    let guard = TempGuard::new(tmp.clone());
    let mut input = File::open(src).map_err(io_err(src))?;
    let mut out = File::create(&tmp).map_err(io_err(&tmp))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = input.read(&mut buf).map_err(io_err(src))?;
        if n == 0 {
            break;
        }
        size += n as u64;
        if size > cap {
            let now = fs::metadata(src).map(|m| m.len()).unwrap_or(size);
            return Err(Error::TooLarge {
                path: rel.to_string(),
                size: now.max(size),
                cap,
            });
        }
        h.update(&buf[..n]);
        out.write_all(&buf[..n]).map_err(io_err(&tmp))?;
    }
    out.sync_all().map_err(io_err(&tmp))?;
    Ok(Staged {
        hex: hex::encode(h.finalize()),
        size,
        guard,
    })
}

/// Move a staged blob into place. If the blob already exists the staged copy is dropped.
pub(crate) fn install(store: &Path, mut s: Staged) -> Result<()> {
    let dest = blob_path(store, &s.hex);
    if dest.exists() {
        return Ok(());
    }
    let Some(tmp) = s.guard.0.clone() else {
        return Err(Error::Corrupt {
            what: "staged blob has no temp file".into(),
        });
    };
    let shard = dest.parent().map(Path::to_path_buf).unwrap_or_default();
    fs::create_dir_all(&shard).map_err(io_err(&shard))?;
    fs::rename(&tmp, &dest).map_err(io_err(&dest))?;
    s.guard.disarm();
    sync_dir(&shard)
}

/// Copy blob `hex` to `dest`, verifying its hash on the way. On a mismatch `dest` is removed and
/// `Corrupt` is returned.
pub(crate) fn copy_verified(store: &Path, hex: &str, dest: &Path) -> Result<()> {
    let src = blob_path(store, hex);
    let mut input = File::open(&src).map_err(|e| missing_or_io(&src, hex, e))?;
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest)
        .map_err(io_err(dest))?;
    let mut guard = TempGuard::new(dest.to_path_buf());
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = input.read(&mut buf).map_err(io_err(&src))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        out.write_all(&buf[..n]).map_err(io_err(dest))?;
    }
    if hex::encode(h.finalize()) != hex {
        return Err(corrupt(hex));
    }
    out.sync_all().map_err(io_err(dest))?;
    guard.disarm();
    Ok(())
}

/// Check that blob `hex` exists and hashes to its name.
pub(crate) fn verify(store: &Path, hex: &str) -> Result<()> {
    let src = blob_path(store, hex);
    match crate::state::hash_file(&src) {
        Ok((h, _)) if h == hex => Ok(()),
        Ok(_) => Err(corrupt(hex)),
        Err(Error::Io { source, .. }) => Err(missing_or_io(&src, hex, source)),
        Err(e) => Err(e),
    }
}

fn corrupt(hex: &str) -> Error {
    Error::Corrupt {
        what: format!("snapshot blob {hex} does not match its hash"),
    }
}

fn missing_or_io(src: &Path, hex: &str, e: std::io::Error) -> Error {
    if e.kind() == ErrorKind::NotFound {
        Error::Corrupt {
            what: format!("snapshot blob {hex} is missing"),
        }
    } else {
        io_err(src)(e)
    }
}

/// Every blob on disk with its size.
pub(crate) fn scan(store: &Path) -> Result<Vec<(String, u64)>> {
    let root = store.join(BLOBS_DIR);
    let mut out = Vec::new();
    let shards = match fs::read_dir(&root) {
        Ok(rd) => rd,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(io_err(&root)(e)),
    };
    for shard in shards {
        let shard = shard.map_err(io_err(&root))?.path();
        if !shard.is_dir() {
            continue;
        }
        for e in fs::read_dir(&shard).map_err(io_err(&shard))? {
            let e = e.map_err(io_err(&shard))?;
            let name = e.file_name().to_string_lossy().to_string();
            if is_blob_name(&name) {
                let len = e.metadata().map_err(io_err(e.path()))?.len();
                out.push((name, len));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_stops_at_the_cap_even_if_the_file_grew_after_the_size_check() {
        let d = tempfile::tempdir().expect("tempdir");
        let src = d.path().join("f");
        fs::write(&src, vec![0u8; 20]).expect("w");
        match stage(d.path(), &src, "f", 10) {
            Err(Error::TooLarge { size, cap, .. }) => assert_eq!((size, cap), (20, 10)),
            Err(e) => panic!("expected TooLarge, got {e:?}"),
            Ok(_) => panic!("expected TooLarge, got a staged blob"),
        }
        let left: Vec<_> = fs::read_dir(d.path())
            .expect("ls")
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(
            left,
            vec![std::ffi::OsString::from("f")],
            "temp copy removed"
        );
    }

    #[test]
    fn copy_verified_rejects_a_blob_that_changed_after_the_preflight() {
        let d = tempfile::tempdir().expect("tempdir");
        let hex = crate::state::sha256_hex(b"good");
        let p = blob_path(d.path(), &hex);
        fs::create_dir_all(p.parent().expect("shard")).expect("mkdir");
        fs::write(&p, b"evil").expect("w");
        let dest = d.path().join("out");
        assert!(matches!(
            copy_verified(d.path(), &hex, &dest),
            Err(Error::Corrupt { .. })
        ));
        assert!(!dest.exists(), "partial copy removed");
    }
}
