#[cfg(not(unix))]
compile_error!("message-attestation needs a unix target");

mod error;
mod locate;
mod message;
mod names;
mod principal;
mod render;
mod replay;
mod reply;
mod send;
mod sign;
mod tool;
mod verify;

pub use error::AttestationError;
pub use locate::{attach, locate};
pub use message::{
    is_valid_id, parse_target, parse_targets, sign_hosted_message, sign_message, validate_message,
    validate_target, MessageKey, MAX_ID_LEN, MAX_MESSAGES, MAX_TARGETS, MESSAGE_BODY_TYPE,
};
pub use names::{RegisteredName, ResolvedPrincipal, MAX_NAME_LEN};
pub use render::{render, render_message, MessageView, RenderOptions, Trust, RENDER_VERSION};
pub use replay::{
    FileReplayStore, MemoryReplayStore, ReplayStateError, ReplayStore, REPLAY_STATE_MAX_BYTES,
};
pub use reply::{
    compose_reply, new_message_id, parse_tool_input, ComposedReply, ReplyDraft, ReplySigner,
    MAX_BODY_BYTES,
};
pub use send::{send_bytes, send_via_command, SendCommand, SendOutcome, SEND_OUTPUT_CAP};
pub use sign::{sign_delivery, OutgoingMessage, UnsignedDelivery, DEFAULT_META_KEY};
pub use tool::{
    run_send_message, send_message_tool, SendMessageResult, ToolDefinition, SEND_MESSAGE_TOOL,
};
pub use verify::{
    confirm, verify_delivery, verify_delivery_meta, DeliveryPolicy, PendingSequence, Verified,
    VerifiedDelivery, VerifiedMessage,
};
