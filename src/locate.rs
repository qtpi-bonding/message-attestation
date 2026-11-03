use identity_crypto::pb;

use crate::AttestationError;

/// Reads the Delivery at the top level of `meta` under `meta_key`.
///
/// `meta` is the ACP `_meta` object itself. A missing key, or a `meta` that
/// is not an object (for example `Null` from a request with no `_meta`), is
/// `Ok(None)`. A present value that is not a JSON object is `NotObject`.
/// The value is decoded by the generated proto3-JSON serde of `pb::Delivery`,
/// which rejects unknown fields and non-canonical `bytes` and `Timestamp`
/// spellings as its own decoder does.
pub fn locate(
    meta: &serde_json::Value,
    meta_key: &str,
) -> Result<Option<pb::Delivery>, AttestationError> {
    let Some(value) = meta.get(meta_key) else {
        return Ok(None);
    };
    if !value.is_object() {
        return Err(AttestationError::NotObject);
    }
    serde_json::from_value::<pb::Delivery>(value.clone())
        .map(Some)
        .map_err(|error| AttestationError::Decode(error.to_string()))
}

/// Writes `delivery` into `meta` under `meta_key` as its proto3-JSON object,
/// replacing any value already there. The inverse of [`locate`].
pub fn attach(
    meta: &mut serde_json::Map<String, serde_json::Value>,
    meta_key: &str,
    delivery: &pb::Delivery,
) -> Result<(), AttestationError> {
    let value = serde_json::to_value(delivery)
        .map_err(|error| AttestationError::Encode(error.to_string()))?;
    meta.insert(meta_key.to_owned(), value);
    Ok(())
}
