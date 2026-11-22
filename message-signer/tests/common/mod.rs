//! Shared fixtures for the message signer's integration tests.
//!
//! Keys are always generated in temporary directories through
//! `identity_keyfile::testkit`; nothing here reads real key files, identity
//! directories or the real home.

#![allow(dead_code)]

use identity_crypto::Timestamp;
use identity_request_auth::Clock;
use std::sync::{Arc, Mutex};

pub const T0: i64 = 1_800_000_000;
pub const SERVER: &str = "server-1";
pub const PATH: &str = "/acme.v1.Inventory/AddItem";
pub const BODY_TYPE: &str = "type.googleapis.com/acme.v1.AddItemRequest";
pub const BODY: &[u8] = b"\x0a\x05apple";
pub const ROOM: &str = "room:r1";

/// A clock the test moves by hand (mirrors the auth testkit so the signer
/// tests do not depend on its internals for time control).
#[derive(Debug)]
pub struct TestClock(Mutex<i64>);

impl TestClock {
    pub fn new(now: i64) -> Arc<Self> {
        Arc::new(Self(Mutex::new(now)))
    }

    pub fn advance(&self, seconds: i64) {
        *self.0.lock().unwrap_or_else(|p| p.into_inner()) += seconds;
    }

    pub fn now(&self) -> i64 {
        *self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            seconds: self.now(),
            nanos: 0,
        }
    }
}

/// A log sink that records every line for later inspection.
#[derive(Clone, Default)]
pub struct LogSink(Arc<Mutex<Vec<String>>>);

impl LogSink {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn sink(&self) -> Arc<dyn Fn(&str) + Send + Sync> {
        let inner = self.0.clone();
        Arc::new(move |line: &str| {
            inner
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(line.to_string());
        })
    }

    pub fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn contains(&self, needle: &str) -> bool {
        self.lines().iter().any(|l| l.contains(needle))
    }
}

pub fn encode_b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn decode_b64(text: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .expect("valid base64")
}

/// The principal id string of the temp dir's identity.
pub fn principal_string(dir: &std::path::Path) -> String {
    identity_keyfile::DeviceKeys::load(dir)
        .expect("device keys")
        .principal_id
        .to_string()
}

/// A private temp directory holding an initialised identity with its root
/// file removed (device-only, as the signer requires).
pub struct DeviceOnlyDir {
    dir: tempfile::TempDir,
}

impl DeviceOnlyDir {
    pub fn new(now: i64, ttl_seconds: i64) -> Self {
        let dir = tempfile::TempDir::new().expect("temp identity dir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("make temp dir private");
        identity_keyfile::IdentityKeys::init(dir.path(), now, ttl_seconds)
            .expect("initialize temp identity");
        std::fs::remove_file(dir.path().join(identity_keyfile::ROOT_FILE))
            .expect("remove the root file for a device-only dir");
        Self { dir }
    }

    pub fn path(&self) -> &std::path::Path {
        self.dir.path()
    }
}

use std::os::unix::fs::PermissionsExt;

/// The identity-request-signer part of a combined config, for a temp identity
/// dir and socket, with no `[message]` section appended yet.
pub fn config_text(dir: &std::path::Path, socket: &std::path::Path) -> String {
    format!(
        "identity_dir = {:?}\nexpected_principal = {:?}\nsocket = {:?}\n",
        dir,
        principal_string(dir),
        socket
    )
}

/// The `[message]` table for a temp dir, using its own device principal as the
/// deliverer string (any canonical principal works for parsing).
pub fn message_table(deliverer: &str) -> String {
    format!("[message]\ndeliverer = {deliverer:?}\n")
}
