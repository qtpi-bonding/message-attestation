//! A local helper that holds a device key and signs room messages over a unix
//! socket, on the shared request-signer server.

pub mod config;
pub mod error;
pub mod message_op;

pub use config::{load_config, parse_config, MessageConfig};
pub use error::MessageSignerError;
pub use message_op::{MessageOp, SESSION_REMINT_AFTER_SECONDS, SESSION_TTL_SECONDS};
