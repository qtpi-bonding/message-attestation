//! The `sign_message` op: parses the tool input, mints/refreshes the message
//! session and signs with `compose_reply`.

use crate::config::MessageConfig;
use crate::error::MessageSignerError;
use identity_request_auth::Clock;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// A minted message session lasts this long.
pub const SESSION_TTL_SECONDS: i64 = 3600;
/// A session is re-minted once this much of its life has passed (60%).
pub const SESSION_REMINT_AFTER_SECONDS: i64 = 2160;

struct Inner {
    identity_dir: PathBuf,
    message: MessageConfig,
    clock: Arc<dyn Clock>,
    keys: identity_keyfile::DeviceKeys,
    /// How many sessions were minted; for tests.
    minted: AtomicUsize,
}

/// The registered op. Cheap to clone; clones share the mint counter.
#[derive(Clone)]
pub struct MessageOp {
    inner: Arc<Inner>,
}

impl MessageOp {
    /// Validates the message config, then loads the device-only keys from
    /// `identity_dir` (`identity_keyfile::DeviceKeys::load`; a fixed error on
    /// failure). Starts with an empty session cache.
    pub fn new(
        identity_dir: &Path,
        message: &MessageConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<MessageOp, MessageSignerError> {
        unimplemented!("MessageOp::new")
    }

    /// How many sessions were minted so far; for tests.
    pub fn mint_count(&self) -> usize {
        self.inner.minted.load(Ordering::SeqCst)
    }
}

impl identity_request_signer::Op for MessageOp {
    fn name(&self) -> &str {
        "sign_message"
    }

    fn run(
        &self,
        ctx: &identity_request_signer::OpContext,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, identity_request_signer::SignerError> {
        unimplemented!("MessageOp::run")
    }
}
