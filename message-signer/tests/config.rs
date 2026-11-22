//! `[message]` config parsing and start-up refusals.

mod common;

use common::*;
use std::os::unix::fs::PermissionsExt;

fn parse_with(
    table: &str,
) -> Result<
    (
        identity_request_signer::Config,
        message_attestation_signer::MessageConfig,
    ),
    message_attestation_signer::MessageSignerError,
> {
    let dir = DeviceOnlyDir::new(T0, 91 * 86400);
    let text = format!(
        "{}{table}",
        config_text(dir.path(), &dir.path().join("s.sock"))
    );
    message_attestation_signer::parse_config(&text)
}

const DELIVERER: &str = "p256:02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn a_config_without_a_message_table_is_refused() {
    let err = parse_with("").expect_err("missing [message]");
    assert_eq!(
        coded_error::CodedError::code(&err),
        "message.signer.config_invalid"
    );
}

#[test]
fn an_empty_deliverer_is_service_principal_missing() {
    let err = parse_with("[message]\ndeliverer = \"\"\n").expect_err("empty deliverer");
    assert_eq!(
        coded_error::CodedError::code(&err),
        "message.signer.service_principal_missing"
    );
}

#[test]
fn a_non_canonical_deliverer_is_refused() {
    let err = parse_with("[message]\ndeliverer = \"not-a-principal\"\n")
        .expect_err("non-canonical deliverer");
    assert_eq!(
        coded_error::CodedError::code(&err),
        "message.signer.config_invalid"
    );
}

#[test]
fn an_unknown_key_inside_the_message_table_is_refused() {
    let err = parse_with(&format!(
        "[message]\ndeliverer = {DELIVERER:?}\nextra = 1\n"
    ))
    .expect_err("unknown key in [message]");
    assert_eq!(
        coded_error::CodedError::code(&err),
        "message.signer.config_invalid"
    );
}

#[test]
fn an_unknown_top_level_key_is_still_refused() {
    let err = parse_with(&format!(
        "mystery_key = 1\n[message]\ndeliverer = {DELIVERER:?}\n"
    ))
    .expect_err("unknown top-level key");
    assert_eq!(
        coded_error::CodedError::code(&err),
        "identity.request_signer.config_invalid"
    );
}

#[test]
fn max_targets_zero_is_refused() {
    let err = parse_with(&format!(
        "[message]\ndeliverer = {DELIVERER:?}\nmax_targets = 0\n"
    ))
    .expect_err("max_targets 0");
    assert_eq!(
        coded_error::CodedError::code(&err),
        "message.signer.config_invalid"
    );
}

#[test]
fn max_targets_over_the_cap_is_refused() {
    let err = parse_with(&format!(
        "[message]\ndeliverer = {DELIVERER:?}\nmax_targets = {}\n",
        message_attestation::MAX_TARGETS + 1
    ))
    .expect_err("max_targets over the cap");
    assert_eq!(
        coded_error::CodedError::code(&err),
        "message.signer.config_invalid"
    );
}

#[test]
fn max_targets_defaults_to_64() {
    let (config, message) =
        parse_with(&format!("[message]\ndeliverer = {DELIVERER:?}\n")).expect("valid config");
    assert_eq!(message.max_targets(), 64);
    assert_eq!(config.identity_dir, config.identity_dir);
}

#[test]
fn load_config_refuses_a_symlink() {
    let dir = DeviceOnlyDir::new(T0, 91 * 86400);
    let config_dir = tempfile::TempDir::new().expect("config temp dir");
    let real = config_dir.path().join("real.toml");
    let link = config_dir.path().join("link.toml");
    std::fs::write(&real, config_text(dir.path(), &dir.path().join("s.sock")))
        .expect("write config");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let err = message_attestation_signer::load_config(&link).expect_err("symlink");
    assert_eq!(
        coded_error::CodedError::code(&err),
        "message.signer.config_invalid"
    );
}

#[test]
fn load_config_refuses_a_group_or_other_readable_file() {
    let dir = DeviceOnlyDir::new(T0, 91 * 86400);
    let config_dir = tempfile::TempDir::new().expect("config temp dir");
    let path = config_dir.path().join("signer.toml");
    std::fs::write(&path, config_text(dir.path(), &dir.path().join("s.sock")))
        .expect("write config");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("make it 0644");
    let err = message_attestation_signer::load_config(&path).expect_err("0644");
    assert_eq!(
        coded_error::CodedError::code(&err),
        "message.signer.config_invalid"
    );
}

#[test]
fn load_config_refuses_an_over_large_file() {
    let dir = DeviceOnlyDir::new(T0, 91 * 86400);
    let config_dir = tempfile::TempDir::new().expect("config temp dir");
    let path = config_dir.path().join("signer.toml");
    let pad = "x".repeat(1024 * 1024 + 1);
    let text = format!(
        "{}[message]\ndeliverer = {DELIVERER:?}\npad = {pad:?}\n",
        config_text(dir.path(), &dir.path().join("s.sock"))
    );
    std::fs::write(&path, text).expect("write config");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("make it 0600");
    let err = message_attestation_signer::load_config(&path).expect_err("too large");
    assert_eq!(
        coded_error::CodedError::code(&err),
        "message.signer.config_invalid"
    );
}

#[test]
fn load_config_accepts_a_0600_file() {
    let dir = DeviceOnlyDir::new(T0, 91 * 86400);
    let config_dir = tempfile::TempDir::new().expect("config temp dir");
    let path = config_dir.path().join("signer.toml");
    let text = format!(
        "{}[message]\ndeliverer = {:?}\n",
        config_text(dir.path(), &dir.path().join("s.sock")),
        principal_string(dir.path())
    );
    std::fs::write(&path, text).expect("write config");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("make it 0600");
    let (_, message) =
        message_attestation_signer::load_config(&path).expect("a 0600 config is accepted");
    assert_eq!(message.deliverer, principal_string(dir.path()));
}

#[test]
fn no_error_text_echoes_file_content() {
    // A marker planted in a bad file must never come back in the error text.
    let marker = "planted-secret-marker-7f3a";
    let err =
        parse_with(&format!("[message]\ndeliverer = \"\"\n{marker} = 1\n")).expect_err("bad file");
    assert!(!err.to_string().contains(marker), "leak: {err}");
}
