pub mod error;
pub mod message;
pub mod replay;

pub use error::AttestationError;
pub use message::{
    is_valid_id, sign_hosted_message, sign_message, validate_message, validate_target, MessageKey,
    MAX_ID_LEN, MAX_TARGETS, MESSAGE_BODY_TYPE,
};
pub use replay::{FileReplayStore, MemoryReplayStore, ReplayStore};
