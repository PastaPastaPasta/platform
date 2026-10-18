//! Everything backup and restore create is owner-only from creation, whatever
//! the umask.
//!
//! The umask is process-wide, and the proof seam fires for every restore in
//! the process, so this file holds one test and runs as its own binary.
#![cfg(unix)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use common::{fresh_persister, wid};
use platform_wallet_storage::sqlite::backup::set_restore_proof_seam;
use platform_wallet_storage::SqlitePersister;

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Restore `from` over `live` with a pre-restore backup into `auto`, and
/// return what the proof's directory held, with modes, while its copy was open.
fn restore_recording_the_proof(live: &Path, from: &Path, auto: &Path) -> Vec<(String, u32)> {
    let seen: Arc<Mutex<Vec<(String, u32)>>> = Arc::default();
    let record = Arc::clone(&seen);
    set_restore_proof_seam(Some(Arc::new(move |dir: &Path| {
        let mut seen = record.lock().unwrap();
        seen.push((".".into(), mode(dir)));
        for name in names(dir) {
            let path = dir.join(&name);
            seen.push((name.clone(), mode(&path)));
            if path.is_dir() {
                for inner in names(&path) {
                    seen.push((format!("{name}/{inner}"), mode(&path.join(&inner))));
                }
            }
        }
    })));
    let restored = SqlitePersister::restore_from(live, from, Some(auto));
    set_restore_proof_seam(None);
    restored.unwrap();
    let seen = seen.lock().unwrap().clone();
    seen
}

fn assert_owner_only_backups(auto: &Path) {
    let backups = names(auto);
    assert!(!backups.is_empty());
    for name in backups {
        assert_eq!(mode(&auto.join(&name)), 0o600, "{name}");
    }
}

#[test]
fn backup_and_restore_create_owner_only_under_umask_022() {
    // SAFETY: `umask` only swaps the process's file-mode mask; nothing else
    // in this binary runs concurrently.
    let previous = unsafe { libc::umask(0o022) };

    let (persister, tmp, live) = fresh_persister();
    common::ensure_wallet_meta(&persister, &wid(0x71));

    // A manual backup creates its missing parents.
    let nested = tmp.path().join("manual").join("nested");
    let backup = persister.backup_to(&nested.join("backup.db")).unwrap();
    drop(persister);
    assert_eq!(mode(&tmp.path().join("manual")), 0o700);
    assert_eq!(mode(&nested), 0o700);
    assert_eq!(mode(&backup), 0o600);

    // A current-schema restore: the proof holds only its copy.
    let auto = tmp.path().join("auto").join("nested");
    let seen = restore_recording_the_proof(&live, &backup, &auto);
    assert_eq!(seen, [(".".into(), 0o700), ("wallet.db".into(), 0o600)]);
    assert_eq!(mode(&tmp.path().join("auto")), 0o700);
    assert_eq!(mode(&auto), 0o700);
    assert_owner_only_backups(&auto);

    // An older-schema restore: the proof's open migrates its copy and takes
    // a pre-migration backup into `backups`.
    let old: PathBuf = tmp.path().join("old.db");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v4_2_dev_migrated.db"),
        &old,
    )
    .unwrap();
    std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o600)).unwrap();
    let auto2 = tmp.path().join("auto2");
    let seen = restore_recording_the_proof(&live, &old, &auto2);
    assert_eq!(seen[0], (".".into(), 0o700));
    assert!(seen.contains(&("backups".into(), 0o700)), "{seen:?}");
    let backup_files: Vec<_> = seen
        .iter()
        .filter(|(name, _)| name.starts_with("backups/"))
        .collect();
    assert!(!backup_files.is_empty(), "{seen:?}");
    for (name, m) in seen.iter().skip(1) {
        let want = if name == "backups" { 0o700 } else { 0o600 };
        assert_eq!(*m, want, "{name}");
    }
    assert_owner_only_backups(&auto2);
    assert_eq!(mode(&live), 0o600);

    // Neither restore left its proof or its staged file behind.
    let leftovers: Vec<_> = names(tmp.path())
        .into_iter()
        .filter(|name| name.starts_with(".restore-proof-") || name.starts_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    unsafe { libc::umask(previous) };
}
