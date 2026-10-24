use std::fs;

use identity_crypto::transcripts::delivery_attestation_transcript;
use identity_crypto::PublicKey;
use message_attestation::locate::locate;
use message_attestation::{
    verify_attestation, AttestationError, AttestationPolicy, MemoryReplayStore, ReplayStore,
    DEFAULT_META_KEY,
};
use serde_json::Value;

fn public_key(value: &Value) -> PublicKey {
    PublicKey::from_hex(value.as_str().expect("hex key"))
        .expect("valid vector public key")
}

fn error_name(error: &AttestationError) -> &'static str {
    match error {
        AttestationError::NotObject => "NotObject",
        AttestationError::Decode(_) => "Decode",
        AttestationError::Encode(_) => "Encode",
        AttestationError::Sign(_) => "Sign",
        AttestationError::EmptyMessages => "EmptyMessages",
        AttestationError::NoRecipients => "NoRecipients",
        AttestationError::UnknownKeyId(_) => "UnknownKeyId",
        AttestationError::OwnDevicesMissing => "OwnDevicesMissing",
        AttestationError::NotARecipient => "NotARecipient",
        AttestationError::Transcript(_) => "Transcript",
        AttestationError::BadSignature => "BadSignature",
        AttestationError::Stale { .. } => "Stale",
        AttestationError::ClockMissing => "ClockMissing",
        AttestationError::Replay { .. } => "Replay",
        AttestationError::Store(_) => "Store",
    }
}

fn number(value: &Value) -> i64 {
    value.as_i64().expect("integer vector field")
}

#[test]
fn every_vector_case_agrees() {
    // A mismatch is decided against the schema, never by regenerating the file to match Rust.
    let path = format!("{}/vectors/attestation.json", env!("CARGO_MANIFEST_DIR"));
    let document: Value = serde_json::from_str(&fs::read_to_string(path).expect("vectors file"))
        .expect("vector JSON");
    let mut failures = Vec::new();

    for case in document["cases"].as_array().expect("cases array") {
        let name = case["name"].as_str().expect("case name");
        let trusted_values = case["trusted"].as_object().expect("trusted object");
        let trusted: Vec<(String, PublicKey)> = trusted_values
            .iter()
            .map(|(key_id, key)| (key_id.clone(), public_key(key)))
            .collect();
        let own_values = case["own_devices"].as_array().expect("own devices array");
        let own: Vec<PublicKey> = own_values.iter().map(public_key).collect();
        let store = MemoryReplayStore::default();
        for prior in case["prior_sequences"].as_array().expect("prior sequences") {
            let accepted = store
                .record(
                    prior["scope"].as_str().expect("prior scope"),
                    prior["key_id"].as_str().expect("prior key id"),
                    prior["last"].as_u64().expect("prior sequence"),
                )
                .expect("preload replay store");
            if !accepted {
                failures.push(format!("{name}: could not preload replay state"));
            }
        }

        let now = case["now_unix"].as_i64();
        let max_age = case["max_age_secs"].as_i64();
        // The `_meta` object: the proto3-JSON attestation under DEFAULT_META_KEY.
        let meta = &case["meta"];
        let policy = AttestationPolicy {
            meta_key: DEFAULT_META_KEY,
            trusted: &trusted,
            own_devices: Some(&own),
            max_age_secs: max_age,
            now_unix: now,
        };
        let result = verify_attestation(
            meta,
            &policy,
            &store,
            case["scope"].as_str().expect("scope"),
        );

        if let Some(transcript_hex) = case["transcript_hex"].as_str() {
            match locate(meta, DEFAULT_META_KEY) {
                Ok(Some(attestation)) => {
                    match delivery_attestation_transcript(&attestation) {
                        Ok(transcript) => {
                            let expected = hex::decode(transcript_hex).expect("transcript hex");
                            if transcript != expected {
                                failures.push(format!("{name}: transcript mismatch"));
                            }
                        }
                        Err(error) => failures.push(format!("{name}: transcript error: {error}")),
                    }
                }
                Ok(None) => failures.push(format!("{name}: expected attestation")),
                Err(error) => failures.push(format!("{name}: locate error: {error}")),
            }
        }

        let expected = &case["expected"];
        if expected.get("none").and_then(Value::as_bool) == Some(true) {
            if !matches!(result, Ok(None)) {
                failures.push(format!("{name}: expected none"));
            }
            continue;
        }
        if let Some(expected_error) = expected.get("error").and_then(Value::as_str) {
            match result {
                Err(error) if error_name(&error) == expected_error => {}
                Err(error) => failures.push(format!(
                    "{name}: expected {expected_error}, got {}",
                    error_name(&error)
                )),
                Ok(Some(_)) => failures.push(format!("{name}: expected {expected_error}, got success")),
                Ok(None) => failures.push(format!("{name}: expected {expected_error}, got none")),
            }
            continue;
        }

        let delivery = match result {
            Ok(Some(verified)) => verified.delivery,
            Ok(None) => {
                failures.push(format!("{name}: expected verified delivery, got none"));
                continue;
            }
            Err(error) => {
                failures.push(format!("{name}: expected success, got {error}"));
                continue;
            }
        };
        let expected_ok = &expected["ok"];
        if delivery.key_id != expected_ok["key_id"]
            || delivery.batch_sequence != expected_ok["batch_sequence"].as_u64().unwrap()
            || delivery.attested_at_unix != number(&expected_ok["attested_at_unix"])
        {
            failures.push(format!("{name}: delivery header mismatch"));
        }
        let expected_messages = expected_ok["messages"].as_array().expect("messages");
        if delivery.messages.len() != expected_messages.len() {
            failures.push(format!("{name}: message count mismatch"));
            continue;
        }
        for (actual, expected_message) in delivery.messages.iter().zip(expected_messages) {
            // Every message carries an author and a delegation cert (the transcript requires both).
            let actual_author = hex::encode(actual.author_genesis.as_bytes());
            if actual.message_id != expected_message["message_id"]
                || actual.room_id != expected_message["room_id"]
                || actual.body_text != expected_message["body_text"]
                || expected_message["author_genesis_hex"].as_str() != Some(actual_author.as_str())
            {
                failures.push(format!("{name}: message mismatch"));
            }
        }
    }

    assert!(failures.is_empty(), "vector failures:\n{}", failures.join("\n"));
}
