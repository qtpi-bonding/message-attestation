use identity_crypto::jwk_duo::SigningKeyPair;
use identity_crypto::pb;
use identity_crypto::transcripts::delivery_attestation_transcript;
use identity_crypto::{PublicKey, Timestamp};
use message_attestation::{attach, DEFAULT_META_KEY};
use serde_json::{Map, Value};

pub struct SignedAttestation {
    pub attestation: pb::DeliveryAttestation,
    pub meta: Value,
    pub key: PublicKey,
    pub device: PublicKey,
}

/// Signs a batch with one key that is the delivery key, the author's genesis
/// and the recipient device. Every message carries a mode-0 delegation cert
/// (principal and device are the signer, the session is a second key), since
/// the transcript requires one on every message.
pub fn signed(sequence: u64, message_count: usize, attested_at: i64) -> SignedAttestation {
    let signer = SigningKeyPair::generate();
    let key = PublicKey::from(&signer);
    let device = key.clone();
    let public_key = pb::PublicKey::from(&key);
    let session = pb::PublicKey::from(&PublicKey::from(&SigningKeyPair::generate()));
    let messages = (0..message_count)
        .map(|index| pb::AttestedMessage {
            message_id: format!("message-{index}"),
            room_id: "room-1".to_owned(),
            body_text: format!("body-{index}"),
            delegation_cert: Some(pb::DelegationCert {
                not_before_unix_seconds: 1_700_000_000,
                not_after_unix_seconds: 1_800_000_000,
                signature: vec![7; 64],
                principal_genesis: Some(public_key.clone()),
                mode: 0,
                device: Some(public_key.clone()),
                session: Some(session.clone()),
                host_genesis: None,
                subject: None,
            }),
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
    let mut meta = Map::new();
    attach(&mut meta, DEFAULT_META_KEY, &attestation).expect("test attach");
    SignedAttestation {
        attestation,
        meta: Value::Object(meta),
        key,
        device,
    }
}
