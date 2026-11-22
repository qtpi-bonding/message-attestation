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
        if self.deliverer.is_empty() {
            return Err(MessageSignerError::ServicePrincipalMissing);
        }
        if identity_crypto::PrincipalId::parse_canonical(&self.deliverer).is_err()
            || self.max_targets == 0
            || self.max_targets > message_attestation::MAX_TARGETS
        {
            return Err(MessageSignerError::ConfigInvalid(String::from(
                "the [message] section is invalid",
            )));
        }
        Ok(())
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
    const BAD: &str = "the configuration is invalid";
    let table: toml::Table = toml::from_str(text).map_err(|_| {
        MessageSignerError::ConfigInvalid(String::from("the configuration is not valid TOML"))
    })?;
    let message = table
        .get("message")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| {
            MessageSignerError::ConfigInvalid(String::from("the [message] section is missing"))
        })?
        .clone();
    let message_text = toml::to_string(&message)
        .map_err(|_| MessageSignerError::ConfigInvalid(String::from(BAD)))?;
    let message: MessageConfig = toml::from_str(&message_text).map_err(|_| {
        MessageSignerError::ConfigInvalid(String::from("the [message] section is invalid"))
    })?;
    let rest = {
        let mut rest = table.clone();
        rest.remove("message");
        toml::to_string(&rest).map_err(|_| MessageSignerError::ConfigInvalid(String::from(BAD)))?
    };
    let config = identity_request_signer::Config::parse(&rest)
        .map_err(|_| MessageSignerError::ConfigInvalid(String::from(BAD)))?;
    config
        .validate()
        .map_err(|_| MessageSignerError::ConfigInvalid(String::from(BAD)))?;
    message.validate()?;
    Ok((config, message))
}

/// Loads the config from a file. Refuses a symlink, any group/other mode bit
/// and a file over 1 MiB, all with fixed messages, then calls
/// [`parse_config`].
pub fn load_config(
    path: &Path,
) -> Result<(identity_request_signer::Config, MessageConfig), MessageSignerError> {
    use std::io::Read;
    if std::fs::symlink_metadata(path)
        .map_err(|_| {
            MessageSignerError::ConfigInvalid(String::from("cannot read the config file"))
        })?
        .file_type()
        .is_symlink()
    {
        return Err(MessageSignerError::ConfigInvalid(String::from(
            "the config file must not be a symlink",
        )));
    }
    let mut file = std::fs::File::open(path).map_err(|_| {
        MessageSignerError::ConfigInvalid(String::from("cannot read the config file"))
    })?;
    let meta = file.metadata().map_err(|_| {
        MessageSignerError::ConfigInvalid(String::from("cannot read the config file"))
    })?;
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(MessageSignerError::ConfigInvalid(String::from(
            "the config file is too large",
        )));
    }
    use std::os::unix::fs::PermissionsExt;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(MessageSignerError::ConfigInvalid(String::from(
            "the config file must be readable only by its owner",
        )));
    }
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(|_| {
        MessageSignerError::ConfigInvalid(String::from("the config is not valid UTF-8"))
    })?;
    parse_config(&text)
}
