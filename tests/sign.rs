use identity_crypto::jwk_duo::SigningKeyPair;
use identity_crypto::pb;
use identity_crypto::{PublicKey, Timestamp};
use message_attestation::{
    attach, confirm, sign_attestation, verify_attestation, AttestationError, AttestationPolicy,
    MemoryReplayStore, ReplayStore, UnsignedAttestation, Verified, DEFAULT_META_KEY,
};
use serde_json::{Map, Value};

/// The signer's key is the delivery key, the author's genesis and the device
/// that holds the mode-0 cert. The session is a second key, so device != session.
struct Fixture {
    signer: SigningKeyPair,
    signer_public: PublicKey,
    signer_pb: pb::PublicKey,
    session: pb::PublicKey,
    recipient: PublicKey,
}

fn fixture() -> Fixture {
    let signer = SigningKeyPair::generate();
    let signer_public = PublicKey::from(&signer);
    let signer_pb = pb::PublicKey::from(&signer_public);
    let session = pb::PublicKey::from(&PublicKey::from(&SigningKeyPair::generate()));
    let recipient = PublicKey::from(&SigningKeyPair::generate());
    Fixture {
        signer,
        signer_public,
        signer_pb,
        session,
        recipient,
    }
}

fn mode0_message(fx: &Fixture, message_id: &str, body: &str) -> pb::AttestedMessage {
    pb::AttestedMessage {
        message_id: message_id.to_owned(),
        room_id: "room-1".to_owned(),
        body_text: body.to_owned(),
        delegation_cert: Some(pb::DelegationCert {
            not_before_unix_seconds: 1_700_000_000,
            not_after_unix_seconds: 1_800_000_000,
            signature: vec![7; 64],
            principal_genesis: Some(fx.signer_pb.clone()),
            mode: 0,
            device: Some(fx.signer_pb.clone()),
            session: Some(fx.session.clone()),
            host_genesis: None,
            subject: None,
        }),
        author_genesis: Some(fx.signer_pb.clone()),
    }
}

fn mode1_message(fx: &Fixture, message_id: &str, body: &str) -> pb::AttestedMessage {
    let principal = pb::PublicKey::from(&PublicKey::from(&SigningKeyPair::generate()));
    let host = pb::PublicKey::from(&PublicKey::from(&SigningKeyPair::generate()));
    pb::AttestedMessage {
        message_id: message_id.to_owned(),
        room_id: "room-1".to_owned(),
        body_text: body.to_owned(),
        delegation_cert: Some(pb::DelegationCert {
            not_before_unix_seconds: 1_700_000_000,
            not_after_unix_seconds: 1_800_000_000,
            signature: vec![9; 64],
            principal_genesis: Some(principal.clone()),
            mode: 1,
            device: Some(fx.signer_pb.clone()),
            session: Some(fx.session.clone()),
            host_genesis: Some(host),
            subject: Some("ops-agent".to_owned()),
        }),
        author_genesis: Some(principal),
    }
}

fn unsigned(
    fx: &Fixture,
    batch_sequence: u64,
    messages: Vec<pb::AttestedMessage>,
) -> UnsignedAttestation {
    UnsignedAttestation {
        batch_sequence,
        attested_at: Timestamp {
            seconds: 1_750_000_000,
            nanos: 0,
        },
        messages,
        recipient_devices: vec![pb::PublicKey::from(&fx.recipient)],
    }
}

fn sign_error(result: Result<pb::DeliveryAttestation, AttestationError>) -> AttestationError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("signing unexpectedly succeeded"),
    }
}

fn verification_error(result: Result<Option<Verified>, AttestationError>) -> AttestationError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("verification unexpectedly succeeded"),
    }
}

/// Attaches the attestation into an empty `_meta` object, as a sender would.
fn meta_with(attestation: &pb::DeliveryAttestation) -> Value {
    let mut meta = Map::new();
    attach(&mut meta, DEFAULT_META_KEY, attestation).expect("attach");
    Value::Object(meta)
}

fn verify(
    fx: &Fixture,
    meta: &Value,
    trusted: Vec<(String, PublicKey)>,
    replay: &dyn ReplayStore,
) -> Result<Option<Verified>, AttestationError> {
    let own = [fx.recipient.clone()];
    let policy = AttestationPolicy {
        meta_key: DEFAULT_META_KEY,
        trusted: &trusted,
        own_devices: Some(own.as_slice()),
        max_age_secs: None,
        now_unix: None,
    };
    verify_attestation(meta, &policy, replay, "scope")
}

#[test]
fn signed_attestation_verifies() {
    let fx = fixture();
    let attestation = sign_attestation(
        &fx.signer,
        unsigned(&fx, 7, vec![mode0_message(&fx, "m1", "hello")]),
    )
    .expect("sign");
    let meta = meta_with(&attestation);
    let thumbprint = PublicKey::from(&fx.signer).thumbprint();
    let trusted = vec![(thumbprint.clone(), fx.signer_public.clone())];
    let replay = MemoryReplayStore::default();

    let verified = verify(&fx, &meta, trusted, &replay)
        .expect("verifies")
        .expect("attestation present");
    assert_eq!(verified.delivery.key_id, thumbprint);
    assert_eq!(verified.delivery.batch_sequence, 7);
    assert_eq!(verified.delivery.messages.len(), 1);
    assert_eq!(verified.delivery.messages[0].body_text, "hello");

    assert_eq!(replay.last_seen("scope", &thumbprint).expect("store"), None);
    confirm(&replay, verified.pending).expect("confirm");
    assert_eq!(
        replay.last_seen("scope", &thumbprint).expect("store"),
        Some(7)
    );
}

#[test]
fn key_id_is_the_signer_thumbprint() {
    let fx = fixture();
    let attestation = sign_attestation(
        &fx.signer,
        unsigned(&fx, 1, vec![mode0_message(&fx, "m1", "hello")]),
    )
    .expect("sign");
    // jwk_duo's own derivation, independent of PublicKey::thumbprint.
    use identity_crypto::jwk_duo::KeyPair as _;
    let thumbprint = fx.signer.calculate_key_id().expect("jwk_duo key id");
    assert_eq!(attestation.key_id, thumbprint);
    assert_eq!(thumbprint.len(), 43, "RFC 7638 thumbprint is 43 unpadded chars");
}

#[test]
fn tampered_body_is_rejected() {
    let fx = fixture();
    let attestation = sign_attestation(
        &fx.signer,
        unsigned(&fx, 1, vec![mode0_message(&fx, "m1", "hello")]),
    )
    .expect("sign");
    let mut tampered = attestation.clone();
    tampered.messages[0].body_text = "goodbye".to_owned();
    let meta = meta_with(&tampered);
    let trusted = vec![(attestation.key_id.clone(), fx.signer_public.clone())];

    let error = verification_error(verify(&fx, &meta, trusted, &MemoryReplayStore::default()));
    assert!(
        matches!(error, AttestationError::BadSignature),
        "expected BadSignature, got {error:?}"
    );
}

#[test]
fn wrong_key_is_rejected() {
    let fx = fixture();
    let attestation = sign_attestation(
        &fx.signer,
        unsigned(&fx, 1, vec![mode0_message(&fx, "m1", "hello")]),
    )
    .expect("sign");
    let meta = meta_with(&attestation);
    let other = PublicKey::from(&SigningKeyPair::generate());
    let trusted = vec![(attestation.key_id.clone(), other)];

    let error = verification_error(verify(&fx, &meta, trusted, &MemoryReplayStore::default()));
    assert!(
        matches!(error, AttestationError::BadSignature),
        "expected BadSignature, got {error:?}"
    );
}

#[test]
fn empty_messages_is_rejected_at_sign_time() {
    let fx = fixture();
    let error = sign_error(sign_attestation(&fx.signer, unsigned(&fx, 1, Vec::new())));
    assert!(
        matches!(error, AttestationError::EmptyMessages),
        "expected EmptyMessages, got {error:?}"
    );
}

#[test]
fn empty_recipients_is_rejected_at_sign_time() {
    let fx = fixture();
    let mut input = unsigned(&fx, 1, vec![mode0_message(&fx, "m1", "hello")]);
    input.recipient_devices.clear();
    let error = sign_error(sign_attestation(&fx.signer, input));
    assert!(
        matches!(error, AttestationError::NoRecipients),
        "expected NoRecipients, got {error:?}"
    );
}

#[test]
fn missing_author_genesis_is_rejected_at_sign_time() {
    let fx = fixture();
    let mut message = mode0_message(&fx, "m1", "hello");
    message.author_genesis = None;
    let error = sign_error(sign_attestation(
        &fx.signer,
        unsigned(&fx, 1, vec![message]),
    ));
    assert!(
        matches!(error, AttestationError::Transcript(_)),
        "expected Transcript, got {error:?}"
    );
}

#[test]
fn missing_delegation_cert_is_rejected_at_sign_time() {
    let fx = fixture();
    let mut message = mode0_message(&fx, "m1", "hello");
    message.delegation_cert = None;
    let error = sign_error(sign_attestation(
        &fx.signer,
        unsigned(&fx, 1, vec![message]),
    ));
    assert!(
        matches!(error, AttestationError::Transcript(_)),
        "expected Transcript, got {error:?}"
    );
}

/// `attested_at` is a required field of `UnsignedAttestation`, so a missing
/// value cannot be built. The transcript's own `attested_at` check is reached
/// through an out-of-range `nanos` instead.
#[test]
fn invalid_attested_at_is_rejected_at_sign_time() {
    let fx = fixture();
    let mut input = unsigned(&fx, 1, vec![mode0_message(&fx, "m1", "hello")]);
    input.attested_at = Timestamp {
        seconds: 1_750_000_000,
        nanos: 1_000_000_000,
    };
    let error = sign_error(sign_attestation(&fx.signer, input));
    assert!(
        matches!(error, AttestationError::Transcript(_)),
        "expected Transcript, got {error:?}"
    );
}

#[test]
fn public_only_signer_is_a_sign_error() {
    let fx = fixture();
    let public_only =
        SigningKeyPair::import_public_key_raw(fx.signer_public.as_bytes()).expect("import");
    let error = sign_error(sign_attestation(
        &public_only,
        unsigned(&fx, 1, vec![mode0_message(&fx, "m1", "hello")]),
    ));
    assert!(
        matches!(error, AttestationError::Sign(_)),
        "expected Sign, got {error:?}"
    );
}

#[test]
fn output_carries_batch_sequence_and_a_64_byte_signature() {
    let fx = fixture();
    let attestation = sign_attestation(
        &fx.signer,
        unsigned(&fx, 42, vec![mode0_message(&fx, "m1", "hello")]),
    )
    .expect("sign");
    assert_eq!(attestation.batch_sequence, 42);
    assert_eq!(attestation.signature.len(), 64);
    assert_eq!(attestation.recipient_devices.len(), 1);
    assert_eq!(attestation.messages.len(), 1);
}

#[test]
fn mode_1_cert_message_signs_and_verifies() {
    let fx = fixture();
    let attestation = sign_attestation(
        &fx.signer,
        unsigned(&fx, 3, vec![mode1_message(&fx, "m1", "delegated")]),
    )
    .expect("sign");
    let meta = meta_with(&attestation);
    let trusted = vec![(attestation.key_id.clone(), fx.signer_public.clone())];

    let verified = verify(&fx, &meta, trusted, &MemoryReplayStore::default())
        .expect("verifies")
        .expect("attestation present");
    let body = &verified.delivery.messages[0];
    assert_eq!(body.body_text, "delegated");
    assert_eq!(body.delegation_cert.mode, 1);
    assert_eq!(body.delegation_cert.subject.as_deref(), Some("ops-agent"));
}
