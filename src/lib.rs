pub mod error;
pub mod locate;
pub mod replay;

pub use error::AttestationError;

pub const DEFAULT_META_KEY: &str = "message-attestation/v1";
