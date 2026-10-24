mod common;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use identity_crypto::pb::DeliveryAttestation;
use message_attestation::locate::locate;
use message_attestation::{
    confirm, verify_attestation, AttestationError, AttestationPolicy, MemoryReplayStore,
    ReplayStore, DEFAULT_META_KEY,
};
use prost::Message;
use serde_json::json;

fn verification_error(
    result: Result<Option<message_attestation::Verified>, AttestationError>,
) -> AttestationError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("verification unexpectedly succeeded"),
    }
}

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

#[test]
fn a_genuine_attestation_verifies_and_returns_the_signed_body() {
    let signed = common::signed(7, 1, 100);
    let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
    let policy = AttestationPolicy {
        meta_key: DEFAULT_META_KEY,
        trusted: &trusted,
        own_devices: Some(std::slice::from_ref(&signed.device)),
        max_age_secs: None,
        now_unix: None,
    };
    let replay = MemoryReplayStore::default();
    let verified = verify_attestation(&signed.meta, &policy, &replay, "room")
        .expect("valid attestation")
        .expect("attestation is present");
    assert_eq!(verified.delivery.key_id, "delivery-key");
    assert_eq!(verified.delivery.batch_sequence, 7);
    assert_eq!(verified.delivery.attested_at_unix, 100);
    assert_eq!(verified.delivery.messages.len(), 1);
    assert_eq!(verified.delivery.messages[0].message_id, "message-0");
    assert_eq!(verified.delivery.messages[0].room_id, "room-1");
    assert_eq!(verified.delivery.messages[0].body_text, "body-0");
    assert_eq!(verified.delivery.messages[0].author_genesis, Some(signed.key));
}

#[test]
fn the_original_bytes_are_returned_unchanged() {
    let signed = common::signed(1, 1, 100);
    let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
    let policy = AttestationPolicy {
        meta_key: DEFAULT_META_KEY,
        trusted: &trusted,
        own_devices: Some(std::slice::from_ref(&signed.device)),
        max_age_secs: None,
        now_unix: None,
    };
    let verified = verify_attestation(&signed.meta, &policy, &MemoryReplayStore::default(), "s")
        .expect("valid attestation")
        .expect("attestation is present");
    assert_eq!(verified.delivery.raw, signed.raw);
}

#[test]
fn an_unknown_key_id_is_refused() {
    let signed = common::signed(1, 1, 100);
    let trusted = Vec::new();
    let policy = AttestationPolicy {
        meta_key: DEFAULT_META_KEY,
        trusted: &trusted,
        own_devices: Some(std::slice::from_ref(&signed.device)),
        max_age_secs: None,
        now_unix: None,
    };
    let error = verification_error(verify_attestation(
        &signed.meta,
        &policy,
        &MemoryReplayStore::default(),
        "s",
    ));
    assert!(matches!(error, AttestationError::UnknownKeyId(ref id) if id == "delivery-key"));
}

#[test]
fn a_tampered_body_fails_the_signature() {
    let signed = common::signed(1, 1, 100);
    let mut tampered = signed.attestation.clone();
    tampered.messages[0].body_text = "changed".to_owned();
    let meta = common::meta_for(&tampered);
    let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
    let policy = AttestationPolicy {
        meta_key: DEFAULT_META_KEY,
        trusted: &trusted,
        own_devices: Some(std::slice::from_ref(&signed.device)),
        max_age_secs: None,
        now_unix: None,
    };
    let error = verification_error(verify_attestation(
        &meta,
        &policy,
        &MemoryReplayStore::default(),
        "s",
    ));
    assert!(matches!(error, AttestationError::BadSignature));
}

#[test]
fn a_device_not_in_recipients_is_refused() {
    let signed = common::signed(1, 1, 100);
    let other = common::signed(2, 1, 100);
    let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
    let policy = AttestationPolicy {
        meta_key: DEFAULT_META_KEY,
        trusted: &trusted,
        own_devices: Some(std::slice::from_ref(&other.device)),
        max_age_secs: None,
        now_unix: None,
    };
    let error = verification_error(verify_attestation(
        &signed.meta,
        &policy,
        &MemoryReplayStore::default(),
        "s",
    ));
    assert!(matches!(error, AttestationError::NotARecipient));
}

#[test]
fn no_own_device_with_an_attestation_present_is_an_error() {
    let signed = common::signed(1, 1, 100);
    let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
    let policy = AttestationPolicy {
        meta_key: DEFAULT_META_KEY,
        trusted: &trusted,
        own_devices: None,
        max_age_secs: None,
        now_unix: None,
    };
    let error = verification_error(verify_attestation(
        &signed.meta,
        &policy,
        &MemoryReplayStore::default(),
        "s",
    ));
    assert!(matches!(error, AttestationError::OwnDevicesMissing));
}

#[test]
fn an_empty_own_device_list_is_an_error_not_a_pass() {
    let signed = common::signed(1, 1, 100);
    let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
    let policy = AttestationPolicy {
        meta_key: DEFAULT_META_KEY,
        trusted: &trusted,
        own_devices: Some(&[]),
        max_age_secs: None,
        now_unix: None,
    };
    let error = verification_error(verify_attestation(
        &signed.meta,
        &policy,
        &MemoryReplayStore::default(),
        "s",
    ));
    assert!(matches!(error, AttestationError::OwnDevicesMissing));
}

#[test]
fn an_empty_message_list_is_refused() {
    let signed = common::signed(1, 0, 100);
    let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
    let policy = AttestationPolicy {
        meta_key: DEFAULT_META_KEY,
        trusted: &trusted,
        own_devices: Some(std::slice::from_ref(&signed.device)),
        max_age_secs: None,
        now_unix: None,
    };
    let error = verification_error(verify_attestation(
        &signed.meta,
        &policy,
        &MemoryReplayStore::default(),
        "s",
    ));
    assert!(matches!(error, AttestationError::EmptyMessages));
}

#[test]
fn a_stale_attestation_is_refused_only_when_a_window_is_set() {
    let signed = common::signed(1, 1, 100);
    let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
    let stale_policy = AttestationPolicy {
        meta_key: DEFAULT_META_KEY,
        trusted: &trusted,
        own_devices: Some(std::slice::from_ref(&signed.device)),
        max_age_secs: Some(50),
        now_unix: Some(200),
    };
    let error = verification_error(verify_attestation(
        &signed.meta,
        &stale_policy,
        &MemoryReplayStore::default(),
        "s",
    ));
    assert!(matches!(error, AttestationError::Stale { age_secs: 100, max: 50 }));
    let open_policy = AttestationPolicy {
        max_age_secs: None,
        now_unix: None,
        ..stale_policy
    };
    assert!(verify_attestation(&signed.meta, &open_policy, &MemoryReplayStore::default(), "s")
        .expect("freshness disabled")
        .is_some());
}

#[test]
fn verify_twice_before_confirm_succeeds_both_times() {
    let signed = common::signed(1, 1, 100);
    let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
    let policy = AttestationPolicy {
        meta_key: DEFAULT_META_KEY,
        trusted: &trusted,
        own_devices: Some(std::slice::from_ref(&signed.device)),
        max_age_secs: None,
        now_unix: None,
    };
    let replay = MemoryReplayStore::default();
    assert!(verify_attestation(&signed.meta, &policy, &replay, "s").expect("first verify").is_some());
    assert!(verify_attestation(&signed.meta, &policy, &replay, "s").expect("second verify").is_some());
}

#[test]
fn after_confirm_the_same_sequence_is_a_replay() {
    let signed = common::signed(1, 1, 100);
    let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
    let policy = AttestationPolicy {
        meta_key: DEFAULT_META_KEY,
        trusted: &trusted,
        own_devices: Some(std::slice::from_ref(&signed.device)),
        max_age_secs: None,
        now_unix: None,
    };
    let replay = MemoryReplayStore::default();
    let verified = verify_attestation(&signed.meta, &policy, &replay, "s")
        .expect("verify")
        .expect("present");
    confirm(&replay, verified.pending).expect("confirm");
    let error = verification_error(verify_attestation(&signed.meta, &policy, &replay, "s"));
    assert!(matches!(error, AttestationError::Replay { last: 1, got: 1, .. }));
}

#[test]
fn a_lower_sequence_after_a_higher_is_a_replay() {
    let signed = common::signed(1, 1, 100);
    let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
    let policy = AttestationPolicy {
        meta_key: DEFAULT_META_KEY,
        trusted: &trusted,
        own_devices: Some(std::slice::from_ref(&signed.device)),
        max_age_secs: None,
        now_unix: None,
    };
    let replay = MemoryReplayStore::default();
    assert!(replay.record("s", "delivery-key", 2).expect("record higher"));
    let error = verification_error(verify_attestation(&signed.meta, &policy, &replay, "s"));
    assert!(matches!(error, AttestationError::Replay { last: 2, got: 1, .. }));
}

#[test]
fn no_attestation_returns_none_even_without_own_devices() {
    let trusted: Vec<(String, identity_crypto::PublicKey)> = Vec::new();
    let policy = AttestationPolicy {
        meta_key: DEFAULT_META_KEY,
        trusted: &trusted,
        own_devices: None,
        max_age_secs: None,
        now_unix: None,
    };
    let result = verify_attestation(&json!({}), &policy, &MemoryReplayStore::default(), "s")
        .expect("absent attestation is not an error");
    assert!(result.is_none());
}
