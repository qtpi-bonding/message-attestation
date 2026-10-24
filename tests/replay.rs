use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

use message_attestation::replay::{FileReplayStore, MemoryReplayStore, ReplayStore};

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

fn test_path(name: &str) -> (PathBuf, PathBuf) {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!("message-attestation-{name}-{}-{id}", std::process::id()));
    fs::create_dir_all(&directory).expect("create test directory");
    let path = directory.join("replay.json");
    (directory, path)
}

#[test]
fn memory_store_accepts_only_increasing_sequences() {
    let store = MemoryReplayStore::default();
    assert_eq!(store.last_seen("scope", "key").expect("read"), None);
    assert!(store.record("scope", "key", 1).expect("record first"));
    assert!(!store.record("scope", "key", 1).expect("reject duplicate"));
    assert!(!store.record("scope", "key", 0).expect("reject lower"));
    assert!(store.record("scope", "key", 2).expect("record higher"));
    assert_eq!(store.last_seen("scope", "key").expect("read"), Some(2));
}

#[test]
fn scopes_are_independent() {
    let store = MemoryReplayStore::default();
    assert!(store.record("first", "key", 3).expect("record first scope"));
    assert!(store.record("second", "key", 1).expect("record second scope"));
    assert_eq!(store.last_seen("first", "key").expect("read first"), Some(3));
    assert_eq!(store.last_seen("second", "key").expect("read second"), Some(1));
}

#[test]
fn file_store_survives_a_reopen() {
    let (directory, path) = test_path("reopen");
    {
        let store = FileReplayStore::open(&path).expect("open empty store");
        assert!(store.record("scope", "key", 5).expect("record"));
    }
    let store = FileReplayStore::open(&path).expect("reopen store");
    assert_eq!(store.last_seen("scope", "key").expect("read"), Some(5));
    assert!(!store.record("scope", "key", 4).expect("reject lower"));
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
    assert!(error.to_string().starts_with("store:"));
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
        let left_thread = thread::spawn(move || left.record("scope", "key", sequence).expect("left record"));
        let right_thread = thread::spawn(move || right.record("scope", "key", sequence).expect("right record"));
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
    assert!(store.record("scope", "key", 1).expect("record despite stale temp"));
    assert_eq!(store.last_seen("scope", "key").expect("read"), Some(1));
}
