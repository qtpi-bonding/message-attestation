mod common;

use identity_crypto::jwk_duo::SigningKeyPair;
use identity_crypto::pb;
use identity_crypto::transcripts::delivery_attestation_transcript;
use identity_crypto::Timestamp;
use message_attestation::locate::locate;
use message_attestation::{
    attach, confirm, verify_attestation, AttestationError, AttestationPolicy, MemoryReplayStore,
    ReplayStore, DEFAULT_META_KEY,
};
use serde_json::{json, Map, Value};

/// The generated proto3-JSON serde is the only encoder; tests mutate its output.
fn to_json(attestation: &pb::DeliveryAttestation) -> Value {
    serde_json::to_value(attestation).expect("generated serde encodes")
}

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

fn policy_for<'a>(
    trusted: &'a Vec<(String, identity_crypto::PublicKey)>,
    device: &'a identity_crypto::PublicKey,
    max_age_secs: Option<i64>,
    now_unix: Option<i64>,
) -> AttestationPolicy<'a> {
    AttestationPolicy {
        meta_key: DEFAULT_META_KEY,
        trusted,
        own_devices: Some(std::slice::from_ref(device)),
        max_age_secs,
        now_unix,
    }
}

#[test]
fn a_valid_attestation_under_a_nested_key_is_ignored_by_verify() {
    let signed = common::signed(1, 1, 100);
    let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
    let policy = policy_for(&trusted, &signed.device, None, None);
    let nested = json!({"outer": signed.meta});
    let result = verify_attestation(&nested, &policy, &MemoryReplayStore::default(), "s")
        .expect("nested key is not an error");
    assert!(result.is_none());
}

#[test]
fn a_window_without_a_clock_is_refused() {
    let signed = common::signed(1, 1, 100);
    let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
    let policy = policy_for(&trusted, &signed.device, Some(50), None);
    let error = verification_error(verify_attestation(
        &signed.meta,
        &policy,
        &MemoryReplayStore::default(),
        "s",
    ));
    assert!(matches!(error, AttestationError::ClockMissing));
}

#[test]
fn a_future_dated_attestation_is_stale_and_age_equal_to_max_is_accepted() {
    let signed = common::signed(1, 1, 100);
    let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
    let future = policy_for(&trusted, &signed.device, Some(50), Some(90));
    let error = verification_error(verify_attestation(
        &signed.meta,
        &future,
        &MemoryReplayStore::default(),
        "s",
    ));
    assert!(matches!(error, AttestationError::Stale { age_secs: -10, max: 50 }));
    let boundary = policy_for(&trusted, &signed.device, Some(50), Some(150));
    assert!(verify_attestation(&signed.meta, &boundary, &MemoryReplayStore::default(), "s")
        .expect("age equal to max")
        .is_some());
}

#[test]
fn confirming_an_already_advanced_sequence_is_a_replay() {
    let signed = common::signed(5, 1, 100);
    let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
    let policy = policy_for(&trusted, &signed.device, None, None);
    let replay = MemoryReplayStore::default();
    let first = verify_attestation(&signed.meta, &policy, &replay, "s")
        .expect("verify")
        .expect("present");
    let second = verify_attestation(&signed.meta, &policy, &replay, "s")
        .expect("verify")
        .expect("present");
    confirm(&replay, first.pending).expect("first confirm");
    let error = confirm(&replay, second.pending).expect_err("second confirm is a replay");
    assert!(matches!(error, AttestationError::Replay { last: 5, got: 5, .. }));
}

#[test]
fn object_at_key_decodes() {
    let signed = common::signed(3, 2, 100);
    let decoded = locate(&signed.meta, DEFAULT_META_KEY)
        .expect("valid object should decode")
        .expect("key is present");
    assert_eq!(decoded, signed.attestation);
}

#[test]
fn non_object_at_key_is_not_object() {
    for value in [json!("abc"), json!([]), json!(null), json!(42)] {
        let meta = json!({DEFAULT_META_KEY: value});
        let error = locate(&meta, DEFAULT_META_KEY).expect_err("non-object must be rejected");
        assert!(matches!(error, AttestationError::NotObject), "got {error}");
    }
}

#[test]
fn unknown_field_is_rejected() {
    let signed = common::signed(1, 1, 100);

    let mut top = to_json(&signed.attestation);
    top["bogusField"] = json!("typo");
    let error = locate(&json!({DEFAULT_META_KEY: top}), DEFAULT_META_KEY)
        .expect_err("unknown top-level field must be rejected");
    assert!(matches!(error, AttestationError::Decode(_)), "got {error}");

    let mut nested = to_json(&signed.attestation);
    nested["messages"][0]["bogusField"] = json!(1);
    let error = locate(&json!({DEFAULT_META_KEY: nested}), DEFAULT_META_KEY)
        .expect_err("unknown message field must be rejected");
    assert!(matches!(error, AttestationError::Decode(_)), "got {error}");

    // The deleted outcome field is an unknown field now.
    let mut outcome = to_json(&signed.attestation);
    outcome["messages"][0]["verificationOutcome"] = json!("DELEGATED_KEY");
    let error = locate(&json!({DEFAULT_META_KEY: outcome}), DEFAULT_META_KEY)
        .expect_err("verificationOutcome must be rejected");
    assert!(matches!(error, AttestationError::Decode(_)), "got {error}");

    // One field spelled both ways is a duplicate.
    let mut twice = to_json(&signed.attestation);
    twice["batch_sequence"] = twice["batchSequence"].clone();
    let error = locate(&json!({DEFAULT_META_KEY: twice}), DEFAULT_META_KEY)
        .expect_err("a field given in camelCase and snake_case must be rejected");
    assert!(matches!(error, AttestationError::Decode(_)), "got {error}");
}

#[test]
fn bad_timestamp_is_rejected() {
    let signed = common::signed(1, 1, 100);
    let object = to_json(&signed.attestation);

    for bad in [
        "not-a-time",
        "2026-10-24T00:00:00+0100",
        "2026-10-24T00:00:00+01:60",
        "2026-02-30T00:00:00Z",
        "2026-10-24T00:00:60Z",
    ] {
        let mut changed = object.clone();
        changed["attestedAt"] = json!(bad);
        let error = locate(&json!({DEFAULT_META_KEY: changed}), DEFAULT_META_KEY)
            .expect_err("bad timestamp must be rejected");
        assert!(matches!(error, AttestationError::Decode(_)), "{bad}: got {error}");
    }

    // RFC 3339 allows more than nine fraction digits. identity-crypto's
    // Timestamp (Task A2) accepts them and keeps the first nine, so this is an
    // accepted spelling (truncated, not rounded: ...899 gives 123456789).
    let mut long_fraction = object.clone();
    long_fraction["attestedAt"] = json!("2026-10-24T00:00:00.1234567899Z");
    let decoded = locate(&json!({DEFAULT_META_KEY: long_fraction}), DEFAULT_META_KEY)
        .expect("a ten-digit fraction is valid RFC 3339")
        .expect("key is present");
    assert_eq!(decoded.attested_at.expect("attested_at present").nanos, 123_456_789);

    // Control: a valid timestamp with a nine-digit fraction and a +01:00 offset.
    let mut valid = object;
    valid["attestedAt"] = json!("2026-10-24T00:00:00.123456789+01:00");
    let decoded = locate(&json!({DEFAULT_META_KEY: valid}), DEFAULT_META_KEY)
        .expect("valid timestamp decodes")
        .expect("key is present");
    let attested_at = decoded.attested_at.expect("attested_at present");
    // 2026-10-24T00:00:00+01:00 is 2026-10-23T23:00:00Z.
    assert_eq!(attested_at.seconds, 1_792_796_400);
    assert_eq!(attested_at.nanos, 123_456_789);
}

#[test]
fn missing_attested_at_is_rejected_by_verify() {
    let signed = common::signed(1, 1, 100);
    let mut object = to_json(&signed.attestation);
    object
        .as_object_mut()
        .expect("object")
        .remove("attestedAt");
    let meta = json!({DEFAULT_META_KEY: object});

    let decoded = locate(&meta, DEFAULT_META_KEY)
        .expect("locate decodes without attestedAt")
        .expect("key is present");
    assert!(decoded.attested_at.is_none());

    let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
    let policy = policy_for(&trusted, &signed.device, None, None);
    let error = verification_error(verify_attestation(&meta, &policy, &MemoryReplayStore::default(), "s"));
    assert!(
        matches!(&error, AttestationError::Transcript(message) if message.contains("attested_at")),
        "got {error}"
    );
}


#[test]
fn missing_underscore_meta_is_none() {
    let request = json!({"jsonrpc": "2.0", "method": "session/prompt", "params": {}});
    let result = locate(&request["params"]["_meta"], DEFAULT_META_KEY)
        .expect("absent _meta is not an error");
    assert!(result.is_none());
}

#[test]
fn attach_then_locate_round_trips() {
    let signed = common::signed(4, 2, 100);
    let mut meta = Map::new();
    attach(&mut meta, DEFAULT_META_KEY, &signed.attestation).expect("attach");
    let decoded = locate(&Value::Object(meta), DEFAULT_META_KEY)
        .expect("attached value decodes")
        .expect("key is present");
    assert_eq!(decoded, signed.attestation);
}

#[test]
fn attach_replaces_an_existing_key() {
    let signed = common::signed(4, 1, 100);
    let mut meta = Map::new();
    meta.insert(DEFAULT_META_KEY.to_owned(), json!("stale value"));
    meta.insert("other-key".to_owned(), json!({"kept": true}));
    attach(&mut meta, DEFAULT_META_KEY, &signed.attestation).expect("attach");
    assert_eq!(meta.len(), 2, "attach replaces the key and keeps others");
    assert_eq!(meta["other-key"], json!({"kept": true}));
    let decoded = locate(&Value::Object(meta), DEFAULT_META_KEY)
        .expect("replaced value decodes")
        .expect("key is present");
    assert_eq!(decoded, signed.attestation);
}

#[test]
fn author_genesis_and_cert_are_exposed_on_every_body() {
    let signed = common::signed(1, 2, 100);
    let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
    let policy = policy_for(&trusted, &signed.device, None, None);
    let verified = verify_attestation(&signed.meta, &policy, &MemoryReplayStore::default(), "s")
        .expect("verify")
        .expect("present");
    assert_eq!(verified.delivery.messages.len(), 2);
    for body in &verified.delivery.messages {
        assert_eq!(body.author_genesis, signed.key);
        assert_eq!(body.delegation_cert.mode, 0);
        assert_eq!(body.delegation_cert.signature, vec![7; 64]);
        assert_eq!(
            body.delegation_cert.principal_genesis,
            Some(pb::PublicKey::from(&signed.key))
        );
    }
}

#[test]
fn missing_author_genesis_or_cert_is_a_transcript_error() {
    for strip_cert in [false, true] {
        let signed = common::signed(1, 1, 100);
        let mut object = to_json(&signed.attestation);
        let message = &mut object["messages"][0];
        if strip_cert {
            message.as_object_mut().expect("message object").remove("delegationCert");
        } else {
            message.as_object_mut().expect("message object").remove("authorGenesis");
        }
        let meta = json!({DEFAULT_META_KEY: object});
        let trusted = vec![("delivery-key".to_owned(), signed.key.clone())];
        let policy = policy_for(&trusted, &signed.device, None, None);
        let error = verification_error(verify_attestation(&meta, &policy, &MemoryReplayStore::default(), "s"));
        assert!(matches!(error, AttestationError::Transcript(_)), "strip_cert={strip_cert}: got {error}");
    }
}

fn test_key() -> pb::PublicKey {
    pb::PublicKey::from(&identity_crypto::PublicKey::from(&SigningKeyPair::generate()))
}

/// A delegation cert in the given mode. Mode 0 forbids `host_genesis` and
/// `subject`; mode 1 requires both.
fn test_cert(mode: u32) -> pb::DelegationCert {
    let vouched = mode == 1;
    pb::DelegationCert {
        not_before_unix_seconds: 1_700_000_000,
        not_after_unix_seconds: 1_800_000_000,
        signature: vec![7; 64],
        principal_genesis: Some(test_key()),
        mode,
        device: Some(test_key()),
        session: Some(test_key()),
        host_genesis: vouched.then(test_key),
        subject: vouched.then(|| "instance-1".to_owned()),
    }
}

fn test_message(mode: u32) -> pb::AttestedMessage {
    pb::AttestedMessage {
        message_id: "message-1".to_owned(),
        room_id: "room-1".to_owned(),
        body_text: "hello".to_owned(),
        delegation_cert: Some(test_cert(mode)),
        author_genesis: Some(test_key()),
    }
}

fn round_trip_cases() -> Vec<(&'static str, pb::DeliveryAttestation)> {
    let base = pb::DeliveryAttestation {
        key_id: "delivery-key".to_owned(),
        batch_sequence: 9,
        attested_at: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 250_000_000,
        }),
        messages: vec![test_message(1), test_message(0)],
        signature: vec![1; 64],
        recipient_devices: vec![test_key(), test_key()],
    };
    let mut mode_zero = base.clone();
    mode_zero.messages = vec![test_message(0)];
    let mut mode_one = base.clone();
    mode_one.messages = vec![test_message(1)];
    let mut empty_messages = base.clone();
    empty_messages.messages = Vec::new();
    let mut sequence_zero = base.clone();
    sequence_zero.batch_sequence = 0;
    let mut empty_key_id = base.clone();
    empty_key_id.key_id = String::new();
    let mut defaulted_cert = base.clone();
    defaulted_cert.messages = vec![pb::AttestedMessage {
        delegation_cert: Some(pb::DelegationCert {
            principal_genesis: Some(test_key()),
            device: Some(test_key()),
            session: Some(test_key()),
            ..Default::default()
        }),
        ..test_message(0)
    }];
    vec![
        ("all fields set", base),
        ("mode-0 cert message", mode_zero),
        ("mode-1 cert message", mode_one),
        ("empty messages", empty_messages),
        ("batch_sequence 0", sequence_zero),
        ("empty key_id", empty_key_id),
        ("mode-0 cert with default fields", defaulted_cert),
    ]
}

#[test]
fn pbjson_round_trip_keeps_the_transcript() {
    for (name, original) in round_trip_cases() {
        let original_transcript = delivery_attestation_transcript(&original)
            .unwrap_or_else(|error| panic!("{name}: original transcript errors: {error}"));
        let meta = json!({DEFAULT_META_KEY: to_json(&original)});
        let decoded = locate(&meta, DEFAULT_META_KEY)
            .unwrap_or_else(|error| panic!("{name}: locate failed: {error}"))
            .unwrap_or_else(|| panic!("{name}: key is present"));
        assert_eq!(decoded, original, "{name}: decoded value differs");
        let decoded_transcript = delivery_attestation_transcript(&decoded)
            .unwrap_or_else(|error| panic!("{name}: decoded transcript errors: {error}"));
        assert_eq!(decoded_transcript, original_transcript, "{name}: transcript differs");
    }
}
