//! The `[message]` section of the config, and the whole-file loader.

use crate::error::MessageSignerError;
use serde::Deserialize;
use std::path::Path;

/// The config file may be at most this many bytes.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

fn default_max_targets() -> usize {
    64
}

/// The `[message]` table: the deliverer (the audience) and the target cap.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageConfig {
    /// The deliverer's canonical principal id; also the message audience.
    pub deliverer: String,
    /// At most this many unique targets per message.
    #[serde(default = "default_max_targets")]
    max_targets: usize,
}

impl MessageConfig {
    /// Empty deliverer -> `service_principal_missing`; a deliverer that is not
    /// a canonical principal id, or `max_targets` of 0 or over
    /// `message_attestation::MAX_TARGETS`, -> `config_invalid`.
    pub fn validate(&self) -> Result<(), MessageSignerError> {
        unimplemented!("MessageConfig::validate")
    }

    pub fn max_targets(&self) -> usize {
        self.max_targets
    }
}

/// Parses the whole config from text. Requires a `[message]` table; every
/// other top-level key is passed to `identity_request_signer::Config::parse`,
/// so an unknown top-level key is still refused. Refusal text is fixed and
/// never echoes file content.
pub fn parse_config(
    text: &str,
) -> Result<(identity_request_signer::Config, MessageConfig), MessageSignerError> {
    unimplemented!("parse_config")
}

/// Loads the config from a file. Refuses a symlink, any group/other mode bit
/// and a file over 1 MiB, all with fixed messages, then calls
/// [`parse_config`].
pub fn load_config(
    path: &Path,
) -> Result<(identity_request_signer::Config, MessageConfig), MessageSignerError> {
    unimplemented!("load_config")
}
