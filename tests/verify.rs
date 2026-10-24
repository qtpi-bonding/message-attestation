use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use identity_crypto::pb::DeliveryAttestation;
use message_attestation::locate::locate;
use message_attestation::{AttestationError, DEFAULT_META_KEY};
use prost::Message;
use serde_json::json;

#[test]
fn absent_meta_key_is_none() {
    let meta = json!({});
    let result = locate(&meta, DEFAULT_META_KEY).expect("absent key should not fail");
    assert!(result.is_none());
}

#[test]
fn a_nested_meta_key_is_ignored() {
    let meta = json!({"nested": {DEFAULT_META_KEY: "not examined"}});
    let result = locate(&meta, DEFAULT_META_KEY).expect("nested key should be ignored");
    assert!(result.is_none());
}

#[test]
fn a_non_string_value_is_not_string() {
    let meta = json!({DEFAULT_META_KEY: 42});
    let error = locate(&meta, DEFAULT_META_KEY).expect_err("number should be rejected");
    assert!(matches!(error, AttestationError::NotString));
}

#[test]
fn bad_base64_is_an_error() {
    let meta = json!({DEFAULT_META_KEY: "%%%"});
    let error = locate(&meta, DEFAULT_META_KEY).expect_err("invalid base64 should fail");
    assert!(matches!(error, AttestationError::Base64(_)));
}

#[test]
fn bytes_that_are_not_an_attestation_are_a_decode_error() {
    let encoded = STANDARD.encode([0xff, 0xff]);
    let meta = json!({DEFAULT_META_KEY: encoded});
    let error = locate(&meta, DEFAULT_META_KEY).expect_err("invalid protobuf should fail");
    assert!(matches!(error, AttestationError::Decode(_)));
}

#[test]
fn locate_returns_the_original_bytes_unchanged() {
    let attestation = DeliveryAttestation::default();
    let bytes = attestation.encode_to_vec();
    let meta = json!({DEFAULT_META_KEY: STANDARD.encode(&bytes)});
    let (raw, decoded) = locate(&meta, DEFAULT_META_KEY)
        .expect("valid attestation should decode")
        .expect("key is present");
    assert_eq!(raw, bytes);
    assert_eq!(decoded, attestation);
}
