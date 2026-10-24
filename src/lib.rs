pub mod error;
pub mod locate;
pub mod replay;
pub mod verify;

pub use error::AttestationError;
pub use replay::{FileReplayStore, MemoryReplayStore, ReplayStore};
pub use verify::{
    confirm, verify_attestation, AttestationPolicy, PendingSequence, TrustedKeys, Verified,
    VerifiedBody, VerifiedDelivery,
};

pub const DEFAULT_META_KEY: &str = "message-attestation/v1";
