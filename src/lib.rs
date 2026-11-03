pub mod error;
pub mod locate;
pub mod message;
pub mod replay;
pub mod sign;
pub mod verify;

pub use error::AttestationError;
pub use message::{
    is_valid_id, sign_hosted_message, sign_message, validate_message, validate_target, MessageKey,
    MAX_ID_LEN, MAX_TARGETS, MESSAGE_BODY_TYPE,
};
pub use replay::{FileReplayStore, MemoryReplayStore, ReplayStore};
pub use locate::{attach, locate};
pub use sign::{sign_delivery, OutgoingMessage, UnsignedDelivery, DEFAULT_META_KEY};
pub use verify::{
    confirm, verify_delivery, verify_delivery_meta, DeliveryPolicy, PendingSequence, Verified,
    VerifiedDelivery, VerifiedMessage,
};
