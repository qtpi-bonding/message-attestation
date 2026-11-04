#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttestationError {
    #[error("replay for deliverer {principal}: last {last}, got {got}")]
    Replay { principal: String, last: u64, got: u64 },
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
    #[error("deliverer {0} is not trusted")]
    UnknownDeliverer(String),
    #[error("deliverer device: {0}")]
    DelivererDevice(String),
    #[error("delivery is for another recipient")]
    WrongRecipient,
    #[error("message {index} is not addressed to the deliverer")]
    WrongAudience { index: usize },
    #[error("message {index} signature chain: {reason}")]
    MessageSignature { index: usize, reason: String },
    #[error("message {index} body is not a Message")]
    WrongBodyType { index: usize },
    #[error("bad delivery signature")]
    BadSignature,
    #[error("no own devices configured")]
    OwnDevicesMissing,
    #[error("none of the own devices is a recipient")]
    NotARecipient,
    #[error("delivery age {age}s outside the window of {skew}s ahead of now to {max}s old", skew = identity_crypto::SKEW_SECONDS)]
    Stale { age: i64, max: i64 },
    #[error("unknown render version {0}")]
    UnknownRenderVersion(u32),
    #[error("session is not valid at {now} (window ends {not_after})")]
    SessionExpired { not_after: i64, now: i64 },
}
