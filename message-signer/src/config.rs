//! The `[message]` section of the config, and the whole-file loader.

use crate::error::MessageSignerError;
use serde::Deserialize;
use std::path::Path;

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

/// Parses the whole config from a table. Requires a `[message]` table; the
/// rest is passed to `identity_request_signer::Config::from_table`, so an
/// unknown top-level key is still refused. Refusal text is fixed and never
/// echoes file content.
pub fn parse_table(
    table: toml::Table,
) -> Result<(identity_request_signer::Config, MessageConfig), MessageSignerError> {
    const BAD: &str = "the configuration is invalid";
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
        rest
    };
    let config = identity_request_signer::Config::from_table(rest)
        .map_err(|_| MessageSignerError::ConfigInvalid(String::from(BAD)))?;
    config
        .validate()
        .map_err(|_| MessageSignerError::ConfigInvalid(String::from(BAD)))?;
    message.validate()?;
    Ok((config, message))
}

/// Parses the whole config from text. Refusal text is fixed and never echoes
/// file content.
pub fn parse_config(
    text: &str,
) -> Result<(identity_request_signer::Config, MessageConfig), MessageSignerError> {
    let table: toml::Table = toml::from_str(text).map_err(|_| {
        MessageSignerError::ConfigInvalid(String::from("the configuration is not valid TOML"))
    })?;
    parse_table(table)
}

/// Loads the config from a file. The private-file checks (symlink, mode,
/// size, UTF-8) are `identity_request_signer::read_private_toml`'s; the
/// refusal is then the same fixed `config_invalid` this crate reports.
pub fn load_config(
    path: &Path,
) -> Result<(identity_request_signer::Config, MessageConfig), MessageSignerError> {
    let table = identity_request_signer::read_private_toml(path).map_err(|_| {
        MessageSignerError::ConfigInvalid(String::from("cannot read the config file"))
    })?;
    parse_table(table)
}
