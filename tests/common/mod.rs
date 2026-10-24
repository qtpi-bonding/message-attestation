use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use identity_crypto::jwk_duo::SigningKeyPair;
use identity_crypto::pb;
use identity_crypto::transcripts::delivery_attestation_transcript;
use identity_crypto::PublicKey;
use message_attestation::DEFAULT_META_KEY;
use prost::Message;
use prost_types::Timestamp;
use serde_json::{json, Value};

pub struct SignedAttestation {
    pub attestation: pb::DeliveryAttestation,
    pub raw: Vec<u8>,
    pub meta: Value,
    pub key: PublicKey,
    pub device: PublicKey,
}

pub fn signed(sequence: u64, message_count: usize, attested_at: i64) -> SignedAttestation {
    let signer = SigningKeyPair::generate();
    let key = PublicKey::from(&signer);
    let device = key.clone();
    let public_key = pb::PublicKey::from(&key);
    let messages = (0..message_count)
        .map(|index| pb::AttestedMessage {
            message_id: format!("message-{index}"),
            room_id: "room-1".to_owned(),
            body_text: format!("body-{index}"),
            verification_outcome: pb::VerificationOutcome::DirectKey as i32,
            delegation_cert: None,
            author_genesis: Some(public_key.clone()),
        })
        .collect();
    let mut attestation = pb::DeliveryAttestation {
        key_id: "delivery-key".to_owned(),
        batch_sequence: sequence,
        attested_at: Some(Timestamp {
            seconds: attested_at,
            nanos: 0,
        }),
        messages,
        signature: Vec::new(),
        recipient_devices: vec![public_key],
    };
    let transcript = delivery_attestation_transcript(&attestation).expect("test transcript");
    attestation.signature = signer.sign_bytes(&transcript).expect("test signature").to_vec();
    let raw = attestation.encode_to_vec();
    let meta = json!({DEFAULT_META_KEY: STANDARD.encode(&raw)});
    SignedAttestation {
        attestation,
        raw,
        meta,
        key,
        device,
    }
}
