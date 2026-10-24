use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{Map, Value};

use crate::AttestationError;

pub trait ReplayStore: Send + Sync {
    fn last_seen(&self, scope: &str, key_id: &str) -> Result<Option<u64>, AttestationError>;

    fn record(&self, scope: &str, key_id: &str, seq: u64) -> Result<bool, AttestationError>;
}

#[derive(Default)]
pub struct MemoryReplayStore {
    entries: Mutex<HashMap<(String, String), u64>>,
}

impl ReplayStore for MemoryReplayStore {
    fn last_seen(&self, scope: &str, key_id: &str) -> Result<Option<u64>, AttestationError> {
        let entries = self
            .entries
            .lock()
            .map_err(|error| AttestationError::Store(error.to_string()))?;
        Ok(entries
            .get(&(scope.to_owned(), key_id.to_owned()))
            .copied())
    }

    fn record(&self, scope: &str, key_id: &str, seq: u64) -> Result<bool, AttestationError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|error| AttestationError::Store(error.to_string()))?;
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
            .open(&self.lock_path)
            .map_err(store_error)?;
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
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Map::new()),
            Err(error) => return Err(store_error(error)),
        };
        let mut contents = String::new();
        file.read_to_string(&mut contents).map_err(store_error)?;
        let value: Value = serde_json::from_str(&contents).map_err(store_error)?;
        value
            .as_object()
            .cloned()
            .ok_or_else(|| store_message("replay state is not an object"))
    }

    fn write_state(&self, state: &Map<String, Value>) -> Result<(), AttestationError> {
        let parent = match self.path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let name = self
            .path
            .file_name()
            .ok_or_else(|| store_message("replay path has no file name"))?
            .to_string_lossy();
        let temp_path = parent.join(format!(".{name}.{}.tmp", std::process::id()));
        let contents = serde_json::to_vec(state).map_err(store_error)?;
        let mut temp = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp_path)
            .map_err(store_error)?;
        let write_result = (|| {
            temp.write_all(&contents).map_err(store_error)?;
            temp.sync_all().map_err(store_error)?;
            fs::rename(&temp_path, &self.path).map_err(store_error)?;
            let directory = File::open(parent).map_err(store_error)?;
            directory.sync_all().map_err(store_error)
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        write_result
    }
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

fn store_error(error: impl std::fmt::Display) -> AttestationError {
    AttestationError::Store(error.to_string())
}

fn store_message(message: &str) -> AttestationError {
    AttestationError::Store(message.to_owned())
}
