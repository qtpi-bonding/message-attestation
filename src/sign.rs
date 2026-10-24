//! Signing of delivery attestations.
//!
//! This crate is no longer verify-only: it also signs. The signer is a
//! caller-owned `jwk_duo::SigningKeyPair`; the crate holds no key storage,
//! reads no clock and persists nothing. The caller also chooses
//! `batch_sequence`, which is its own counter. `sign_attestation` builds the
//! attestation and its signature; `locate` and `attach` move it in and out of
//! `_meta`.

use identity_crypto::jwk_duo::SigningKeyPair;
use identity_crypto::transcripts::delivery_attestation_transcript;
use identity_crypto::{pb, verify_p256, PublicKey, Timestamp};

use crate::AttestationError;

/// Everything a signed attestation carries except `key_id` and `signature`,
/// which `sign_attestation` derives from the signer.
pub struct UnsignedAttestation {
    pub batch_sequence: u64,
    pub attested_at: Timestamp,
    pub messages: Vec<pb::AttestedMessage>,
    pub recipient_devices: Vec<pb::PublicKey>,
}

/// Signs `unsigned` with `signer`.
///
/// `key_id` is the thumbprint of the signer's public key, the same value a
/// verifier's trusted-key table is keyed by. The signature covers the
/// delivery-attestation transcript of the attestation with an empty
/// `signature`. The output is checked against `verify_p256` before it is
/// returned; a failure there is a defect, reported as `Sign`.
pub fn sign_attestation(
    signer: &SigningKeyPair,
    unsigned: UnsignedAttestation,
) -> Result<pb::DeliveryAttestation, AttestationError> {
    if unsigned.messages.is_empty() {
        return Err(AttestationError::EmptyMessages);
    }
    if unsigned.recipient_devices.is_empty() {
        return Err(AttestationError::NoRecipients);
    }

    let signer_key = PublicKey::from(signer);
    let mut attestation = pb::DeliveryAttestation {
        key_id: signer_key.thumbprint(),
        batch_sequence: unsigned.batch_sequence,
        attested_at: Some(unsigned.attested_at),
        messages: unsigned.messages,
        signature: Vec::new(),
        recipient_devices: unsigned.recipient_devices,
    };

    let transcript = delivery_attestation_transcript(&attestation)
        .map_err(|error| AttestationError::Transcript(error.to_string()))?;
    let signature = signer
        .sign_bytes(&transcript)
        .map_err(|error| AttestationError::Sign(error.to_string()))?;
    attestation.signature = signature.to_vec();

    verify_p256(&signer_key, &transcript, &attestation.signature)
        .map_err(|error| AttestationError::Sign(format!("self-verification failed: {error}")))?;
    Ok(attestation)
}
