pub type Source = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, thiserror::Error, coded_error::CodedError)]
#[non_exhaustive]
#[coded(namespace = "message.attestation")]
pub enum AttestationError {
    #[error("replay for deliverer {principal}: last {last}, got {got}")]
    #[coded(code = "replay", class = Logical, grpc = AlreadyExists)]
    Replay {
        principal: String,
        last: u64,
        got: u64,
    },
    #[error("store failed")]
    #[coded(code = "store", class = Infrastructure, grpc = Unavailable)]
    Store(#[source] Source),
    #[error("invalid message {field}: {reason}")]
    #[coded(code = "invalid_message", class = Logical, grpc = InvalidArgument)]
    InvalidMessage {
        field: &'static str,
        reason: &'static str,
    },
    #[error("sign: {0}")]
    #[coded(code = "sign", class = Infrastructure, grpc = Unavailable)]
    Sign(#[source] Source),
    #[error("delivery is not a JSON object")]
    #[coded(code = "not_object", class = Logical, grpc = InvalidArgument)]
    NotObject,
    #[error("decode: {0}")]
    #[coded(code = "decode", class = Logical, grpc = InvalidArgument)]
    Decode(#[source] Source),
    #[error("encode: {0}")]
    #[coded(code = "encode", class = Infrastructure, grpc = Unavailable)]
    Encode(#[source] Source),
    #[error("delivery has no messages")]
    #[coded(code = "empty_messages", class = Logical, grpc = InvalidArgument)]
    EmptyMessages,
    #[error("delivery has no recipient devices")]
    #[coded(code = "no_recipients", class = Logical, grpc = InvalidArgument)]
    NoRecipients,
    #[error("transcript: {0}")]
    #[coded(code = "transcript", class = Logical, grpc = InvalidArgument)]
    Transcript(#[source] Source),
    #[error("delivery_id must be 1-128 of [A-Za-z0-9._:-]")]
    #[coded(code = "invalid_delivery_id", class = Logical, grpc = InvalidArgument)]
    InvalidDeliveryId,
    #[error("invalid via for message {index}")]
    #[coded(code = "invalid_via", class = Logical, grpc = InvalidArgument)]
    InvalidVia { index: usize },
    #[error("deliverer {0} is not trusted")]
    #[coded(code = "unknown_deliverer", class = Logical, grpc = Unauthenticated)]
    UnknownDeliverer(String),
    #[error("deliverer device: {0}")]
    #[coded(code = "deliverer_device", class = Logical, grpc = Unauthenticated)]
    DelivererDevice(#[source] Source),
    #[error("delivery is for another recipient")]
    #[coded(code = "wrong_recipient", class = Logical, grpc = PermissionDenied)]
    WrongRecipient,
    #[error("message {index} is not addressed to the deliverer")]
    #[coded(code = "wrong_audience", class = Logical, grpc = PermissionDenied)]
    WrongAudience { index: usize },
    #[error("message {index} signature chain: {reason}")]
    #[coded(code = "message_signature", class = Logical, grpc = Unauthenticated)]
    MessageSignature { index: usize, reason: String },
    #[error("message {index} body is not a Message")]
    #[coded(code = "wrong_body_type", class = Logical, grpc = InvalidArgument)]
    WrongBodyType { index: usize },
    #[error("bad delivery signature")]
    #[coded(code = "bad_signature", class = Logical, grpc = Unauthenticated)]
    BadSignature,
    #[error("no own devices configured")]
    #[coded(code = "own_devices_missing", class = Infrastructure, grpc = Unavailable)]
    OwnDevicesMissing,
    #[error("none of the own devices is a recipient")]
    #[coded(code = "not_a_recipient", class = Logical, grpc = PermissionDenied)]
    NotARecipient,
    #[error(
        "delivery age {age}s outside the window of {skew}s ahead of now to {max}s old",
        skew = identity_crypto::SKEW_SECONDS
    )]
    #[coded(code = "stale", class = Logical, grpc = FailedPrecondition)]
    Stale { age: i64, max: i64 },
    #[error("unknown render version {0}")]
    #[coded(code = "unknown_render_version", class = Infrastructure, grpc = Unavailable)]
    UnknownRenderVersion(u32),
    #[error("session is not valid at {now} (window ends {not_after})")]
    #[coded(code = "session_expired", class = Logical, grpc = FailedPrecondition)]
    SessionExpired { not_after: i64, now: i64 },
    #[error("send: {0}")]
    #[coded(code = "send", class = Infrastructure, grpc = Unavailable)]
    Send(#[source] Source),
    #[error("send command failed ({status:?}): {stderr}")]
    #[coded(code = "send_failed", class = Infrastructure, grpc = Unavailable)]
    SendFailed { status: Option<i32>, stderr: String },
    #[error("send command timed out after {secs}s")]
    #[coded(code = "send_timeout", class = Transient, grpc = DeadlineExceeded)]
    SendTimeout { secs: u64 },
    #[error("invalid name: {reason}")]
    #[coded(code = "invalid_name", class = Logical, grpc = InvalidArgument)]
    InvalidName { reason: &'static str },
    #[error("name for {principal}, who authors no message in the delivery")]
    #[coded(code = "stray_name", class = Logical, grpc = InvalidArgument)]
    StrayName { principal: String },
    #[error("too many messages: {count} (max {max})")]
    #[coded(code = "too_many_messages", class = Logical, grpc = InvalidArgument)]
    TooManyMessages { count: usize, max: usize },
    #[error("recipient device {index} is not a public key")]
    #[coded(code = "invalid_recipient_device", class = Logical, grpc = InvalidArgument)]
    InvalidRecipientDevice { index: usize },
    #[error("no OS randomness")]
    #[coded(code = "randomness", class = Infrastructure, grpc = Unavailable)]
    Randomness(#[source] Source),
}
