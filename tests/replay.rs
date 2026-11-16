use std::error::Error as _;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

use identity_keyfile::KeyfileError;
use message_attestation::{
    AttestationError, FileReplayStore, MemoryReplayStore, ReplayStore, REPLAY_STATE_MAX_BYTES,
};

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

fn test_path(name: &str) -> (PathBuf, PathBuf) {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "message-attestation-{name}-{}-{id}",
        std::process::id()
    ));
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)
        .expect("create test directory");
    let path = directory.join("replay.json");
    (directory, path)
}

#[test]
fn memory_store_accepts_only_increasing_sequences() {
    let store = MemoryReplayStore::default();
    assert_eq!(store.last_seen("scope", "key").expect("read"), None);
    assert!(store
        .record("scope", "key", 1, 0, None)
        .expect("record first"));
    assert!(!store
        .record("scope", "key", 1, 0, None)
        .expect("reject duplicate"));
    assert!(!store
        .record("scope", "key", 0, 0, None)
        .expect("reject lower"));
    assert!(store
        .record("scope", "key", 2, 0, None)
        .expect("record higher"));
    assert_eq!(store.last_seen("scope", "key").expect("read"), Some(2));
}

#[test]
fn scopes_are_independent() {
    let store = MemoryReplayStore::default();
    assert!(store
        .record("first", "key", 3, 0, None)
        .expect("record first scope"));
    assert!(store
        .record("second", "key", 1, 0, None)
        .expect("record second scope"));
    assert_eq!(
        store.last_seen("first", "key").expect("read first"),
        Some(3)
    );
    assert_eq!(
        store.last_seen("second", "key").expect("read second"),
        Some(1)
    );
}

#[test]
fn file_store_survives_a_reopen() {
    let (directory, path) = test_path("reopen");
    {
        let store = FileReplayStore::open(&path).expect("open empty store");
        assert!(store.record("scope", "key", 5, 0, None).expect("record"));
    }
    let store = FileReplayStore::open(&path).expect("reopen store");
    assert_eq!(store.last_seen("scope", "key").expect("read"), Some(5));
    assert!(!store
        .record("scope", "key", 4, 0, None)
        .expect("reject lower"));
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn a_missing_file_is_an_empty_store() {
    let (directory, path) = test_path("missing");
    let store = FileReplayStore::open(&path).expect("open missing file");
    assert_eq!(store.last_seen("scope", "key").expect("read"), None);
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn a_corrupt_file_fails_closed() {
    let (directory, path) = test_path("corrupt");
    fs::write(&path, b"not json").expect("write corrupt state");
    let error = FileReplayStore::open(&path).expect_err("corrupt state must fail");
    assert_eq!(error.to_string(), "store failed");
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn two_stores_on_one_file_do_not_both_accept_the_same_sequence() {
    let (directory, path) = test_path("race");
    let first = Arc::new(FileReplayStore::open(&path).expect("open first store"));
    let second = Arc::new(FileReplayStore::open(&path).expect("open second store"));
    for sequence in 1..=50 {
        let left = Arc::clone(&first);
        let right = Arc::clone(&second);
        let left_thread = thread::spawn(move || {
            left.record("scope", "key", sequence, 0, None)
                .expect("left record")
        });
        let right_thread = thread::spawn(move || {
            right
                .record("scope", "key", sequence, 0, None)
                .expect("right record")
        });
        let accepted = [
            left_thread.join().expect("left thread"),
            right_thread.join().expect("right thread"),
        ];
        assert_eq!(accepted.iter().filter(|value| **value).count(), 1);
    }
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn a_stale_temp_file_does_not_wedge_the_store() {
    let (directory, path) = test_path("stale-temp");
    let store = FileReplayStore::open(&path).expect("open");
    let stale = directory.join(format!(".replay.json.{}.tmp", std::process::id()));
    fs::write(&stale, b"leftover from a crash").expect("write stale temp");
    assert!(store
        .record("scope", "key", 1, 0, None)
        .expect("record despite stale temp"));
    assert_eq!(store.last_seen("scope", "key").expect("read"), Some(1));
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

fn keyfile_error(error: &AttestationError) -> &KeyfileError {
    assert!(
        matches!(error, AttestationError::Store(_)),
        "not Store: {error:?}"
    );
    assert_eq!(error.to_string(), "store failed");
    error
        .source()
        .and_then(|source| source.downcast_ref::<KeyfileError>())
        .unwrap_or_else(|| panic!("Store source is not a KeyfileError: {error:?}"))
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

#[test]
fn state_and_lock_files_are_0600_and_the_parent_0700() {
    let (directory, path) = test_path("modes");
    let store = FileReplayStore::open(&path).expect("open");
    assert!(store.record("scope", "key", 1, 0, None).expect("record"));
    assert_eq!(mode_of(&path), 0o600);
    assert_eq!(mode_of(&lock_path(&path)), 0o600);
    assert_eq!(mode_of(&directory), 0o700);
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn a_missing_parent_is_created_0700() {
    let (directory, _) = test_path("new-parent");
    let nested = directory.join("a").join("b");
    let path = nested.join("replay.json");
    let store = FileReplayStore::open(&path).expect("open creates the parent");
    assert!(store.record("scope", "key", 1, 0, None).expect("record"));
    assert_eq!(mode_of(&nested), 0o700);
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn a_group_writable_parent_is_refused() {
    let (directory, path) = test_path("loose-parent");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o775)).expect("loosen");
    let error = FileReplayStore::open(&path).expect_err("loose parent must be refused");
    assert!(
        matches!(keyfile_error(&error), KeyfileError::InsecureDir(_)),
        "{error:?}"
    );
    assert_eq!(mode_of(&directory), 0o775, "the library must never tighten");
    assert!(!path.exists());
    assert!(!lock_path(&path).exists());
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn a_loose_state_file_is_refused_not_tightened() {
    let (directory, path) = test_path("loose-state");
    fs::write(&path, b"{}").expect("write state");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loosen");
    let error = FileReplayStore::open(&path).expect_err("loose state must be refused");
    assert!(
        matches!(keyfile_error(&error), KeyfileError::InsecureFile(_)),
        "{error:?}"
    );
    assert_eq!(mode_of(&path), 0o644, "the library must never tighten");
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn a_loose_lock_file_is_refused_not_tightened() {
    let (directory, path) = test_path("loose-lock");
    let lock = lock_path(&path);
    fs::write(&lock, b"").expect("write lock");
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).expect("loosen");
    let error = FileReplayStore::open(&path).expect_err("loose lock must be refused");
    assert!(
        matches!(keyfile_error(&error), KeyfileError::InsecureFile(_)),
        "{error:?}"
    );
    assert_eq!(mode_of(&lock), 0o644, "the library must never tighten");
    assert!(!path.exists());
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn a_loose_lock_file_is_refused_on_every_operation() {
    let (directory, path) = test_path("loosened-lock");
    let store = FileReplayStore::open(&path).expect("open");
    let lock = lock_path(&path);
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o666)).expect("loosen");
    assert!(store.last_seen("scope", "key").is_err());
    assert!(store.record("scope", "key", 1, 0, None).is_err());
    assert_eq!(mode_of(&lock), 0o666);
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn a_symlinked_lock_or_state_file_is_refused() {
    let (directory, path) = test_path("symlinks");
    let target = directory.join("target");
    fs::write(&target, b"{}").expect("write target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("tighten");
    std::os::unix::fs::symlink(&target, lock_path(&path)).expect("symlink lock");
    assert!(
        FileReplayStore::open(&path).is_err(),
        "symlinked lock must be refused"
    );
    fs::remove_file(lock_path(&path)).expect("remove lock link");
    std::os::unix::fs::symlink(&target, &path).expect("symlink state");
    let error = FileReplayStore::open(&path).expect_err("symlinked state must be refused");
    assert!(
        matches!(keyfile_error(&error), KeyfileError::InsecureFile(_)),
        "{error:?}"
    );
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn a_missing_state_file_is_the_empty_store() {
    let (directory, path) = test_path("missing-state");
    let store = FileReplayStore::open(&path).expect("open");
    assert_eq!(store.last_seen("scope", "key").expect("read"), None);
    assert!(!path.exists(), "reading a missing state must not create it");
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn a_fifo_at_the_state_path_is_refused_without_hanging() {
    let (directory, path) = test_path("fifo");
    let c_path = CString::new(path.as_os_str().as_bytes()).expect("c path");
    // SAFETY: c_path is a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    let (sender, receiver) = std::sync::mpsc::channel();
    let open_path = path.clone();
    thread::spawn(move || {
        let _ = sender.send(FileReplayStore::open(&open_path).map(|_| ()));
    });
    let result = receiver
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("open on a FIFO must not hang");
    let error = result.expect_err("a FIFO must be refused");
    assert!(
        matches!(keyfile_error(&error), KeyfileError::NotAFile(_)),
        "{error:?}"
    );
    fs::remove_dir_all(directory).expect("clean up");
}

fn padded_state(len: usize) -> Vec<u8> {
    let mut bytes = b"{}".to_vec();
    bytes.resize(len, b' ');
    bytes
}

#[test]
fn an_oversize_state_file_is_refused_and_one_at_the_cap_is_read() {
    let (directory, path) = test_path("oversize");
    fs::write(&path, padded_state(REPLAY_STATE_MAX_BYTES + 1)).expect("write state");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("tighten");
    let error = FileReplayStore::open(&path).expect_err("oversize must be refused");
    assert!(
        matches!(
            keyfile_error(&error),
            KeyfileError::TooLarge { cap: 1_048_576, .. }
        ),
        "{error:?}"
    );
    fs::write(&path, padded_state(REPLAY_STATE_MAX_BYTES)).expect("write state at the cap");
    FileReplayStore::open(&path).expect("a state exactly at the cap is read");
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn the_temp_file_is_removed_when_the_write_fails() {
    let (directory, path) = test_path("temp-removed");
    let store = FileReplayStore::open(&path).expect("open");
    fs::create_dir(&path).expect("make the state path a directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("mode");
    assert!(store.record("scope", "key", 1, 0, None).is_err());
    let leftovers: Vec<_> = fs::read_dir(&directory)
        .expect("list")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.ends_with(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temp files left behind: {leftovers:?}"
    );
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn a_write_that_cannot_create_its_temp_fails_and_leaves_none() {
    let (directory, path) = test_path("temp-readonly");
    let store = FileReplayStore::open(&path).expect("open");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).expect("read-only parent");
    assert!(store.record("scope", "key", 1, 0, None).is_err());
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("restore");
    assert!(!path.exists());
    assert!(fs::read_dir(&directory).expect("list").all(|entry| !entry
        .expect("entry")
        .file_name()
        .to_string_lossy()
        .ends_with(".tmp")));
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn a_fifo_or_directory_at_the_lock_path_is_refused() {
    let (directory, path) = test_path("lock-fifo");
    let lock = lock_path(&path);
    let c_path = CString::new(lock.as_os_str().as_bytes()).expect("c path");
    // SAFETY: c_path is a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    let error = FileReplayStore::open(&path).expect_err("a FIFO lock must be refused");
    assert!(
        matches!(keyfile_error(&error), KeyfileError::InsecureFile(_)),
        "{error:?}"
    );
    fs::remove_file(&lock).expect("remove fifo");
    fs::create_dir(&lock).expect("directory lock");
    assert!(FileReplayStore::open(&path).is_err());
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn memory_store_is_debug() {
    let store = MemoryReplayStore::default();
    assert!(format!("{store:?}").contains("MemoryReplayStore"));
}

// --- Task 8: entries carry their time; safe forgetting ---

fn stores() -> Vec<(Box<dyn ReplayStore>, Option<PathBuf>)> {
    let (directory, path) = test_path("both");
    let file = FileReplayStore::open(&path).expect("open file store");
    vec![
        (Box::new(MemoryReplayStore::default()), None),
        (Box::new(file), Some(directory)),
    ]
}

fn finish(directory: Option<PathBuf>) {
    if let Some(directory) = directory {
        fs::remove_dir_all(directory).expect("clean up");
    }
}

#[test]
fn record_stores_the_time_and_an_older_time_never_lowers_it() {
    for (store, dir) in stores() {
        assert!(store.record("s", "k", 1, 100, None).unwrap());
        assert!(store.record("s", "k", 2, 50, None).unwrap());
        // Another key's record forgets entries older than 75; "k" kept time 100.
        assert!(store.record("s", "other", 1, 200, Some(75)).unwrap());
        assert_eq!(store.last_seen("s", "k").unwrap(), Some(2));
        finish(dir);
    }
}

#[test]
fn forgetting_is_strict_and_per_scope() {
    for (store, dir) in stores() {
        assert!(store.record("A", "old", 4, 10, None).unwrap());
        assert!(store.record("A", "edge", 5, 20, None).unwrap());
        assert!(store.record("B", "old", 6, 10, None).unwrap());
        assert!(store.record("A", "new", 7, 5, Some(20)).unwrap());
        assert_eq!(store.last_seen("A", "old").unwrap(), None);
        assert_eq!(store.last_seen("A", "edge").unwrap(), Some(5));
        assert_eq!(store.last_seen("B", "old").unwrap(), Some(6));
        assert_eq!(
            store.last_seen("A", "new").unwrap(),
            Some(7),
            "the entry just written is never forgotten by its own call"
        );
        finish(dir);
    }
}

#[test]
fn no_forget_when_none() {
    for (store, dir) in stores() {
        assert!(store.record("A", "old", 4, 1, None).unwrap());
        assert!(store.record("A", "new", 1, 1_000_000, None).unwrap());
        assert_eq!(store.last_seen("A", "old").unwrap(), Some(4));
        finish(dir);
    }
}

#[test]
fn a_rejected_record_forgets_nothing() {
    for (store, dir) in stores() {
        assert!(store.record("A", "old", 4, 1, None).unwrap());
        assert!(store.record("A", "k", 5, 100, None).unwrap());
        assert!(!store.record("A", "k", 5, 100, Some(50)).unwrap());
        assert_eq!(store.last_seen("A", "old").unwrap(), Some(4));
        finish(dir);
    }
}

#[test]
fn a_forgotten_key_can_record_again_from_sequence_one() {
    for (store, dir) in stores() {
        assert!(store.record("A", "old", 9, 10, None).unwrap());
        assert!(store.record("A", "new", 1, 100, Some(50)).unwrap());
        assert_eq!(store.last_seen("A", "old").unwrap(), None);
        assert!(store.record("A", "old", 1, 100, None).unwrap());
        finish(dir);
    }
}

#[test]
fn the_file_layout_is_sequence_and_attested_at() {
    let (directory, path) = test_path("layout");
    let store = FileReplayStore::open(&path).expect("open");
    assert!(store.record("s", "k", 3, 77, None).unwrap());
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read")).expect("json");
    assert_eq!(
        value,
        serde_json::json!({"s": {"k": {"sequence": 3, "attested_at": 77}}})
    );
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn the_old_bare_number_layout_fails_closed() {
    let (directory, path) = test_path("bare-number");
    fs::write(&path, br#"{"s":{"k":5}}"#).expect("write old layout");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
    let error = FileReplayStore::open(&path).expect_err("old layout must fail closed");
    assert!(matches!(error, AttestationError::Store(_)), "{error:?}");
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn forgetting_persists_across_a_reopen() {
    let (directory, path) = test_path("forget-reopen");
    {
        let store = FileReplayStore::open(&path).expect("open");
        assert!(store.record("s", "old", 3, 10, None).unwrap());
        assert!(store.record("s", "new", 1, 100, Some(50)).unwrap());
    }
    let store = FileReplayStore::open(&path).expect("reopen");
    assert_eq!(store.last_seen("s", "old").unwrap(), None);
    assert_eq!(store.last_seen("s", "new").unwrap(), Some(1));
    fs::remove_dir_all(directory).expect("clean up");
}

#[test]
fn malformed_entries_fail_closed() {
    for body in [
        r#"{"s":{"k":{"sequence":1}}}"#,
        r#"{"s":{"k":{"attested_at":1}}}"#,
        r#"{"s":{"k":{"sequence":-1,"attested_at":1}}}"#,
        r#"{"s":{"k":{"sequence":1,"attested_at":1.5}}}"#,
        r#"{"s":5}"#,
    ] {
        let (directory, path) = test_path("malformed");
        fs::write(&path, body).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        let error = FileReplayStore::open(&path).expect_err(body);
        assert!(
            matches!(error, AttestationError::Store(_)),
            "{body}: {error:?}"
        );
        fs::remove_dir_all(directory).expect("clean up");
    }
}

// --- Task 9 extra: the write path honours the read cap ---

#[test]
fn record_refuses_a_state_that_would_exceed_the_read_cap() {
    let (directory, path) = test_path("write-cap");
    let store = FileReplayStore::open(&path).expect("open");
    let mut accepted = Vec::new();
    let mut refusal = None;
    // Long keys fill the cap in a handful of records.
    for i in 0..64usize {
        let key = format!("{i:03}{}", "k".repeat(60_000));
        let before = fs::read(&path).ok();
        match store.record("s", &key, 1, 0, None) {
            Ok(true) => accepted.push(key),
            Ok(false) => panic!("a fresh key was reported as a replay"),
            Err(error) => {
                refusal = Some((error, before));
                break;
            }
        }
    }
    let (error, before) = refusal.expect("the record that crosses the cap must be refused");
    assert!(!accepted.is_empty(), "the cap was hit before any record was written");
    assert!(
        matches!(
            keyfile_error(&error),
            KeyfileError::TooLarge { cap: 1_048_576, .. }
        ),
        "{error:?}"
    );
    // The previously written file is intact, within the cap, and readable.
    let after = fs::read(&path).expect("state file still exists");
    assert_eq!(Some(after.clone()), before, "the refused record must not touch the file");
    assert!(after.len() <= REPLAY_STATE_MAX_BYTES);
    assert_eq!(mode_of(&path), 0o600);
    let reopened = FileReplayStore::open(&path).expect("the store is not bricked");
    for key in &accepted {
        assert_eq!(reopened.last_seen("s", key).unwrap(), Some(1));
    }
    // The refused key was not recorded.
    let refused_key = format!("{:03}{}", accepted.len(), "k".repeat(60_000));
    assert_eq!(reopened.last_seen("s", &refused_key).unwrap(), None);
    fs::remove_dir_all(directory).expect("clean up");
}
