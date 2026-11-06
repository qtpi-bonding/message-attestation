//! Signing a Delivery. The signer is a caller-owned device key; the crate
//! holds no key storage, reads no clock and persists nothing.

use identity_crypto::jwk_duo::SigningKeyPair;
use identity_crypto::transcripts::delivery_transcript;
use identity_crypto::{pb, verify_carried_message, verify_p256, PrincipalId, PublicKey, Timestamp};

use crate::message::{check_target, is_valid_id};
use crate::names::ResolvedPrincipal;
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
    /// Names the registry bound to authors of `messages`; sorted by id when signed.
    pub names: Vec<ResolvedPrincipal>,
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

    let device_principal = device_delegation
        .principal_genesis
        .as_ref()
        .and_then(|g| PublicKey::try_from(g).ok())
        .map(PrincipalId::from_genesis);
    let mut names = unsigned.names;
    if !names.is_empty() {
        let deliverer = device_principal.ok_or_else(|| {
            AttestationError::Sign("device_delegation has no principal_genesis".to_string())
        })?;
        let mut authors = Vec::with_capacity(unsigned.messages.len());
        for (index, m) in unsigned.messages.iter().enumerate() {
            let carried = verify_carried_message(&m.message, &deliverer.to_string())
                .map_err(|e| AttestationError::MessageSignature { index, reason: e.to_string() })?;
            authors.push(carried.author().clone());
        }
        if let Some(stray) = names.iter().find(|n| !authors.contains(n.id())) {
            return Err(AttestationError::StrayName { principal: stray.id().to_string() });
        }
        names.sort_by_key(|n| n.id().to_string());
    }
    let names = names
        .into_iter()
        .map(|n| pb::PrincipalName {
            principal_id: n.id().to_string(),
            name: n.name().as_str().to_string(),
        })
        .collect();

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
        names,
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
