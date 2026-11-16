use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use identity_keyfile::private_fs::{create_private_dir, read_private_file, write_private_atomic};
use identity_keyfile::KeyfileError;
use serde_json::{Map, Value};

use crate::AttestationError;

/// Maximum accepted size of a replay state file.
pub const REPLAY_STATE_MAX_BYTES: usize = 1_048_576;

pub trait ReplayStore: Send + Sync {
    fn last_seen(&self, scope: &str, key_id: &str) -> Result<Option<u64>, AttestationError>;

    fn record(&self, scope: &str, key_id: &str, seq: u64) -> Result<bool, AttestationError>;
}

#[derive(Debug, Default)]
pub struct MemoryReplayStore {
    entries: Mutex<HashMap<(String, String), u64>>,
}

impl ReplayStore for MemoryReplayStore {
    fn last_seen(&self, scope: &str, key_id: &str) -> Result<Option<u64>, AttestationError> {
        let entries = self
            .entries
            .lock()
            .map_err(|error| AttestationError::Store(error.to_string().into()))?;
        Ok(entries.get(&(scope.to_owned(), key_id.to_owned())).copied())
    }

    fn record(&self, scope: &str, key_id: &str, seq: u64) -> Result<bool, AttestationError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|error| AttestationError::Store(error.to_string().into()))?;
        let key = (scope.to_owned(), key_id.to_owned());
        if let Some(last) = entries.get(&key) {
            if seq <= *last {
                return Ok(false);
            }
        }
        entries.insert(key, seq);
        Ok(true)
    }
}

#[derive(Debug)]
pub struct FileReplayStore {
    path: PathBuf,
    lock_path: PathBuf,
}

impl FileReplayStore {
    pub fn open(path: &Path) -> Result<Self, AttestationError> {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        create_private_dir(parent).map_err(store_error)?;
        let mut lock_name = path.as_os_str().to_owned();
        lock_name.push(".lock");
        let lock_path = PathBuf::from(lock_name);
        let store = Self {
            path: path.to_owned(),
            lock_path,
        };
        store.with_lock(|store| store.read_state()).map(|_| store)
    }

    fn with_lock<T>(
        &self,
        operation: impl FnOnce(&Self) -> Result<T, AttestationError>,
    ) -> Result<T, AttestationError> {
        // A fresh handle per operation: flock on one shared handle would not
        // exclude other threads using the same store.
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.lock_path)
            .map_err(|error| {
                // ELOOP: the lock path is a symlink (O_NOFOLLOW refused it).
                if error.raw_os_error() == Some(libc::ELOOP) {
                    KeyfileError::InsecureFile(self.lock_path.clone())
                } else {
                    keyfile_io(&self.lock_path, error)
                }
            })
            .map_err(store_error)?;
        // The handle checks run before flock so an insecure lock is never used.
        check_lock_handle(&lock, &self.lock_path, euid()).map_err(store_error)?;
        lock.lock().map_err(store_error)?;
        let result = operation(self);
        let unlock_result = lock.unlock().map_err(store_error);
        match (result, unlock_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn read_state(&self) -> Result<Map<String, Value>, AttestationError> {
        let bytes = match read_private_file(&self.path, REPLAY_STATE_MAX_BYTES) {
            Ok(bytes) => bytes,
            // A missing file is an empty store.
            Err(KeyfileError::Missing(_)) => return Ok(Map::new()),
            Err(error) => return Err(store_error(error)),
        };
        let value: Value = serde_json::from_slice(&bytes).map_err(store_error)?;
        value
            .as_object()
            .cloned()
            .ok_or_else(|| store_message("replay state is not an object"))
    }

    fn write_state(&self, state: &Map<String, Value>) -> Result<(), AttestationError> {
        let contents = serde_json::to_vec(state).map_err(store_error)?;
        write_private_atomic(&self.path, &contents, 0o600).map_err(store_error)
    }
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn keyfile_io(path: &Path, error: io::Error) -> KeyfileError {
    KeyfileError::Io {
        path: path.to_path_buf(),
        source: error,
    }
}

/// Checks an already-opened lock file handle: a regular file with no group or
/// other access, owned by `uid`. Checking the handle, not the path, cannot be
/// raced. Never chmods: an unsuitable lock file is only refused.
fn check_lock_handle(file: &File, path: &Path, uid: u32) -> Result<(), KeyfileError> {
    let meta = file.metadata().map_err(|error| keyfile_io(path, error))?;
    if !meta.is_file() || meta.mode() & 0o077 != 0 {
        return Err(KeyfileError::InsecureFile(path.to_path_buf()));
    }
    if meta.uid() != uid {
        return Err(KeyfileError::WrongOwner(path.to_path_buf()));
    }
    Ok(())
}

impl ReplayStore for FileReplayStore {
    fn last_seen(&self, scope: &str, key_id: &str) -> Result<Option<u64>, AttestationError> {
        self.with_lock(|store| {
            let state = store.read_state()?;
            lookup(&state, scope, key_id)
        })
    }

    fn record(&self, scope: &str, key_id: &str, seq: u64) -> Result<bool, AttestationError> {
        self.with_lock(|store| {
            let mut state = store.read_state()?;
            if let Some(last) = lookup(&state, scope, key_id)? {
                if seq <= last {
                    return Ok(false);
                }
            }
            let scopes = state
                .entry(scope.to_owned())
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .ok_or_else(|| store_message("scope state is not an object"))?;
            scopes.insert(key_id.to_owned(), Value::from(seq));
            store.write_state(&state)?;
            Ok(true)
        })
    }
}

fn lookup(
    state: &Map<String, Value>,
    scope: &str,
    key_id: &str,
) -> Result<Option<u64>, AttestationError> {
    let Some(scope_value) = state.get(scope) else {
        return Ok(None);
    };
    let scope_map = scope_value
        .as_object()
        .ok_or_else(|| store_message("scope state is not an object"))?;
    let Some(value) = scope_map.get(key_id) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| store_message("sequence is not an unsigned integer"))
}

fn store_error(error: impl std::error::Error + Send + Sync + 'static) -> AttestationError {
    AttestationError::Store(Box::new(error))
}

fn store_message(message: &str) -> AttestationError {
    AttestationError::Store(message.to_owned().into())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_lock_handle_owned_by_another_user_is_refused() {
        let path = std::env::temp_dir().join(format!("replay-lock-owner-{}", std::process::id()));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .expect("create lock");
        let me = euid();
        check_lock_handle(&file, &path, me).expect("own file passes");
        let error = check_lock_handle(&file, &path, me + 1).expect_err("foreign owner refused");
        assert!(
            matches!(&error, KeyfileError::WrongOwner(p) if p == &path),
            "{error:?}"
        );
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "never chmod");
        std::fs::remove_file(&path).expect("clean up");
    }
}
