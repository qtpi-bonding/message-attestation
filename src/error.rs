#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("attestation value is not a JSON object")]
    NotObject,
    #[error("decode: {0}")]
    Decode(String),
    #[error("encode: {0}")]
    Encode(String),
    #[error("sign: {0}")]
    Sign(String),
    #[error("attestation has no messages")]
    EmptyMessages,
    #[error("attestation has no recipient devices")]
    NoRecipients,
    #[error("unknown key id: {0}")]
    UnknownKeyId(String),
    #[error("own device list missing or empty")]
    OwnDevicesMissing,
    #[error("own device is not a recipient")]
    NotARecipient,
    #[error("transcript: {0}")]
    Transcript(String),
    #[error("bad signature")]
    BadSignature,
    #[error("stale attestation: age {age_secs}s, max {max}s")]
    Stale { age_secs: i64, max: i64 },
    #[error("freshness window set without now_unix")]
    ClockMissing,
    #[error("replay for {key_id}: last {last}, got {got}")]
    Replay { key_id: String, last: u64, got: u64 },
    #[error("store: {0}")]
    Store(String),
}
