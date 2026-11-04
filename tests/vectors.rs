//! Checks vectors/delivery.json, written by vectors/gen.py without any Rust code, against the crate.

use identity_crypto::transcripts::delivery_transcript;
use identity_crypto::{PrincipalId, PublicKey};
use message_attestation::{
    locate, render, verify_delivery_meta, AttestationError, DeliveryPolicy, MemoryReplayStore,
    ReplayStore, Trust, DEFAULT_META_KEY, RENDER_VERSION,
};
use serde_json::Value;

fn error_name(e: &AttestationError) -> &'static str {
    match e {
        AttestationError::Replay { .. } => "Replay",
        AttestationError::Store(_) => "Store",
        AttestationError::InvalidMessage { .. } => "InvalidMessage",
        AttestationError::Sign(_) => "Sign",
        AttestationError::NotObject => "NotObject",
        AttestationError::Decode(_) => "Decode",
        AttestationError::Encode(_) => "Encode",
        AttestationError::EmptyMessages => "EmptyMessages",
        AttestationError::NoRecipients => "NoRecipients",
        AttestationError::Transcript(_) => "Transcript",
        AttestationError::InvalidDeliveryId => "InvalidDeliveryId",
        AttestationError::InvalidVia { .. } => "InvalidVia",
        AttestationError::UnknownDeliverer(_) => "UnknownDeliverer",
        AttestationError::DelivererDevice(_) => "DelivererDevice",
        AttestationError::WrongRecipient => "WrongRecipient",
        AttestationError::WrongAudience { .. } => "WrongAudience",
        AttestationError::MessageSignature { .. } => "MessageSignature",
        AttestationError::WrongBodyType { .. } => "WrongBodyType",
        AttestationError::BadSignature => "BadSignature",
        AttestationError::OwnDevicesMissing => "OwnDevicesMissing",
        AttestationError::NotARecipient => "NotARecipient",
        AttestationError::Stale { .. } => "Stale",
        AttestationError::UnknownRenderVersion(_) => "UnknownRenderVersion",
        AttestationError::SessionExpired { .. } => "SessionExpired",
        e => panic!("unnamed error {e:?}"),
    }
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("{key} is not a string"))
}

/// Runs one case; `Err` carries what disagreed.
fn check(case: &Value) -> Result<(), String> {
    let trusted: Vec<PrincipalId> = case["trusted"]
        .as_array()
        .ok_or("trusted")?
        .iter()
        .map(|t| PrincipalId::parse_canonical(t.as_str().unwrap()).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let self_id = PrincipalId::parse_canonical(str_of(case, "self_id")).map_err(|e| e.to_string())?;
    let own: Vec<PublicKey> = case["own_devices"]
        .as_array()
        .ok_or("own_devices")?
        .iter()
        .map(|k| PublicKey::from_hex(k.as_str().unwrap()).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let store = MemoryReplayStore::default();
    for p in case["prior_sequences"].as_array().ok_or("prior_sequences")? {
        store
            .record(str_of(p, "scope"), str_of(p, "key"), p["last"].as_u64().unwrap())
            .map_err(|e| e.to_string())?;
    }
    let policy = DeliveryPolicy {
        trusted: &trusted,
        self_id: &self_id,
        own_devices: &own,
        max_age_secs: case["max_age_secs"].as_i64(),
        now_unix: case["now_unix"].as_i64().ok_or("now_unix")?,
    };

    if let Some(hex_str) = case["transcript_hex"].as_str() {
        let delivery = locate(&case["meta"], DEFAULT_META_KEY)
            .map_err(|e| format!("locate: {e}"))?
            .ok_or("transcript_hex given but no delivery in meta")?;
        let got = hex::encode(delivery_transcript(&delivery).map_err(|e| e.to_string())?);
        if got != hex_str {
            return Err(format!("transcript differs:\n  rust {got}\n  gen  {hex_str}"));
        }
    }

    let outcome = verify_delivery_meta(&case["meta"], DEFAULT_META_KEY, &policy, &store);
    let expected = &case["expected"];
    if let Some(name) = expected["error"].as_str() {
        return match outcome {
            Err(e) if error_name(&e) == name => Ok(()),
            Err(e) => Err(format!("expected error {name}, got {} ({e})", error_name(&e))),
            Ok(_) => Err(format!("expected error {name}, got a result")),
        };
    }
    if expected["none"].as_bool() == Some(true) {
        return match outcome {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Err("expected none, got a delivery".into()),
            Err(e) => Err(format!("expected none, got error {}", error_name(&e))),
        };
    }
    let ok = &expected["ok"];
    let verified = match outcome {
        Ok(Some(v)) => v,
        Ok(None) => return Err("expected ok, got none".into()),
        Err(e) => return Err(format!("expected ok, got error {} ({e})", error_name(&e))),
    };
    let want = ok["messages"].as_array().ok_or("ok.messages")?;
    let got = verified.delivery.messages();
    if got.len() != want.len() {
        return Err(format!("expected {} messages, got {}", want.len(), got.len()));
    }
    for (g, w) in got.iter().zip(want) {
        if g.author().to_string() != str_of(w, "author") {
            return Err(format!("author {} != {}", g.author(), str_of(w, "author")));
        }
        if g.message().message_id != str_of(w, "message_id") {
            return Err(format!("message id {} != {}", g.message().message_id, str_of(w, "message_id")));
        }
    }
    let rendered = render(&verified.delivery, &self_id, Trust::Verified);
    if rendered != str_of(ok, "render") {
        return Err(format!("render differs:\n  rust {rendered}\n  gen  {}", str_of(ok, "render")));
    }
    Ok(())
}

#[test]
fn delivery_vectors_match_the_independent_generator() {
    assert_eq!(RENDER_VERSION, 1, "vectors were written for render version 1");
    let file = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/delivery.json"))
        .expect("vectors/delivery.json");
    let doc: Value = serde_json::from_str(&file).unwrap();
    let mut failures = Vec::new();
    let mut checked = 0;
    for case in doc["cases"].as_array().unwrap() {
        checked += 1;
        if let Err(why) = check(case) {
            failures.push(format!("{}: {why}", str_of(case, "name")));
        }
    }
    assert!(failures.is_empty(), "{} failing:\n{}", failures.len(), failures.join("\n"));
    assert_eq!(checked, 22);
}
