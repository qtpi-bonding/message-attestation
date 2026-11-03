//! Signing a Delivery. The signer is a caller-owned device key; the crate
//! holds no key storage, reads no clock and persists nothing.

use identity_crypto::jwk_duo::SigningKeyPair;
use identity_crypto::transcripts::delivery_transcript;
use identity_crypto::{pb, verify_p256, PrincipalId, PublicKey, Timestamp};

use crate::message::{check_target, is_valid_id};
use crate::AttestationError;

pub const DEFAULT_META_KEY: &str = "message-attestation/v2";

/// An author-signed message with the targets it is delivered under.
pub struct OutgoingMessage {
    pub message: pb::SignedMessage,
    pub via: Vec<pb::Target>,
}

/// Everything a signed Delivery carries except `signer_device` and `signature`.
pub struct UnsignedDelivery {
    pub delivery_id: String,
    pub recipient_id: PrincipalId,
    pub recipient_devices: Vec<PublicKey>,
    pub sequence: u64,
    pub attested_at: Timestamp,
    pub messages: Vec<OutgoingMessage>,
}

/// Signs `unsigned` with the deliverer's DEVICE. `device_delegation` (its
/// root to that device) is carried as `signer_device`. The authors are not
/// re-verified: the deliverer has done that against its own directory.
pub fn sign_delivery(
    device: &SigningKeyPair,
    device_delegation: &pb::KeyDelegation,
    unsigned: UnsignedDelivery,
) -> Result<pb::Delivery, AttestationError> {
    if unsigned.messages.is_empty() {
        return Err(AttestationError::EmptyMessages);
    }
    if unsigned.recipient_devices.is_empty() {
        return Err(AttestationError::NoRecipients);
    }
    if !is_valid_id(&unsigned.delivery_id) {
        return Err(AttestationError::InvalidDeliveryId);
    }
    for (index, m) in unsigned.messages.iter().enumerate() {
        if m.via.is_empty() || m.via.iter().any(|t| check_target(t, "via").is_err()) {
            return Err(AttestationError::InvalidVia { index });
        }
    }

    let device_key = PublicKey::from(device);
    if device_delegation.delegated != Some(pb::PublicKey::from(&device_key)) {
        return Err(AttestationError::Sign(
            "device_delegation does not delegate this device".to_string(),
        ));
    }

    let (messages, via) = unsigned
        .messages
        .into_iter()
        .map(|m| (m.message, pb::Targets { targets: m.via }))
        .unzip();
    let mut delivery = pb::Delivery {
        delivery_id: unsigned.delivery_id,
        recipient_id: unsigned.recipient_id.to_string(),
        recipient_devices: unsigned.recipient_devices.iter().map(pb::PublicKey::from).collect(),
        sequence: unsigned.sequence,
        attested_at: Some(unsigned.attested_at),
        messages,
        via,
        signer_device: Some(device_delegation.clone()),
        signature: Vec::new(),
    };

    let transcript = delivery_transcript(&delivery)
        .map_err(|error| AttestationError::Transcript(error.to_string()))?;
    let signature = device
        .sign_bytes(&transcript)
        .map_err(|error| AttestationError::Sign(error.to_string()))?;
    delivery.signature = signature.to_vec();

    verify_p256(&device_key, &transcript, &delivery.signature)
        .map_err(|error| AttestationError::Sign(format!("self-verification failed: {error}")))?;
    Ok(delivery)
}
