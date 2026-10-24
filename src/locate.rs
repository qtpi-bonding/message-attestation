use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use prost::Message;

use crate::AttestationError;

pub fn locate(
    meta: &serde_json::Value,
    meta_key: &str,
) -> Result<Option<(Vec<u8>, identity_crypto::pb::DeliveryAttestation)>, AttestationError> {
    let Some(value) = meta.get(meta_key) else {
        return Ok(None);
    };
    let encoded = value.as_str().ok_or(AttestationError::NotString)?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|error| AttestationError::Base64(error.to_string()))?;
    let attestation = identity_crypto::pb::DeliveryAttestation::decode(bytes.as_slice())
        .map_err(|error| AttestationError::Decode(error.to_string()))?;
    Ok(Some((bytes, attestation)))
}
