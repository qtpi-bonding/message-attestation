#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("replay for {key_id}: last {last}, got {got}")]
    Replay { key_id: String, last: u64, got: u64 },
    #[error("store: {0}")]
    Store(String),
    #[error("invalid message {field}: {reason}")]
    InvalidMessage { field: &'static str, reason: &'static str },
    #[error("sign: {0}")]
    Sign(String),
    #[error("delivery is not a JSON object")]
    NotObject,
    #[error("decode: {0}")]
    Decode(String),
    #[error("encode: {0}")]
    Encode(String),
    #[error("delivery has no messages")]
    EmptyMessages,
    #[error("delivery has no recipient devices")]
    NoRecipients,
    #[error("transcript: {0}")]
    Transcript(String),
    #[error("delivery_id must be 1-128 of [A-Za-z0-9._:-]")]
    InvalidDeliveryId,
    #[error("invalid via for message {index}")]
    InvalidVia { index: usize },
}
