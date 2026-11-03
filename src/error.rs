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
}
