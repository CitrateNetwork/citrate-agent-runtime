//! Each managed browser gets a profile folder of its own. Two launches that share a folder become
//! one Chrome (Chrome hands the second launch to the first through its per-profile singleton), so
//! the second worker would drive the first worker's browser, behind the first worker's network
//! gate. The folder is created fresh, never reused, and private to the member.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};

use citrate_agent_browser::chromium::new_profile_dir;

fn scratch(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "citrate-profile-test-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("scratch folder");
    p
}

#[test]
fn launches_at_the_same_moment_get_different_fresh_folders() {
    let parent = scratch("burst");
    let threads = 32;
    let per = 16;
    let start = Arc::new(Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let parent = parent.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                (0..per)
                    .map(|_| new_profile_dir(&parent).expect("a profile folder"))
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut all = BTreeSet::new();
    for h in handles {
        for p in h.join().expect("thread") {
            assert!(p.starts_with(&parent), "{}", p.display());
            assert!(p.is_dir(), "{}", p.display());
            assert_eq!(
                std::fs::read_dir(&p).expect("readable").count(),
                0,
                "a fresh, empty folder"
            );
            assert!(all.insert(p.clone()), "{} was handed out twice", p.display());
        }
    }
    assert_eq!(all.len(), threads * per);
    let _ = std::fs::remove_dir_all(&parent);
}

#[cfg(unix)]
#[test]
fn the_profile_folder_is_private_to_the_member() {
    use std::os::unix::fs::PermissionsExt;
    let parent = scratch("mode");
    let p = new_profile_dir(&parent).expect("a profile folder");
    let mode = std::fs::metadata(&p).expect("stat").permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let _ = std::fs::remove_dir_all(&parent);
}
