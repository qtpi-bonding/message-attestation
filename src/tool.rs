use identity_crypto::PrincipalId;
use serde_json::json;

use crate::error::AttestationError;
use crate::reply::{compose_reply, parse_tool_input, ReplySigner};
use crate::send::{send_via_command, SendCommand};

pub const SEND_MESSAGE_TOOL: &str = "send_message";

const DESCRIPTION: &str = "Send a message as yourself. `to` lists rooms (`room:<id>`) and agents or people (`p256:<hex>`), at most 64. To reply, pass the message's id as `reply_to` and usually the same `to` list. `mentions` are `p256:` ids you want to notify. Returns the new message's id.";

/// What a host registers with its model: the tool's name, description and
/// JSON Schema input.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolDefinition {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: serde_json::Value,
}

/// The schema'"'"'s `maxLength` counts characters and is only a hint to the model;
/// `MAX_BODY_BYTES` counts UTF-8 bytes and is what `parse_tool_input` enforces.
pub fn send_message_tool() -> ToolDefinition {
    ToolDefinition {
        name: SEND_MESSAGE_TOOL,
        description: DESCRIPTION,
        input_schema: json!({
            "type": "object",
            "properties": {
                "to": {
                    "type": "array",
                    "items": { "type": "string" },
                    "minItems": 1,
                    "maxItems": crate::message::MAX_TARGETS,
                },
                "body": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": crate::reply::MAX_BODY_BYTES,
                },
                "reply_to": { "type": "string" },
                "references": { "type": "array", "items": { "type": "string" } },
                "mentions": { "type": "array", "items": { "type": "string" } },
            },
            "required": ["to", "body"],
            "additionalProperties": false,
        }),
    }
}

const MAX_ERROR_BYTES: usize = 1024;

/// What the model is told after `run_send_message`.
#[derive(Clone, Debug, PartialEq)]
pub enum SendMessageResult {
    /// `output` is the command's stdout as JSON when it parses, else a string.
    Sent { message_id: String, output: serde_json::Value },
    /// `message_id` is set once the reply was composed.
    Failed { message_id: Option<String>, error: String },
}

fn model_line(text: &str) -> String {
    let line = text.lines().next().unwrap_or("");
    let mut end = line.len().min(MAX_ERROR_BYTES);
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    line[..end].to_owned()
}

fn failure_text(e: &AttestationError) -> String {
    match e {
        AttestationError::SendFailed { stderr, .. } => {
            let first = model_line(stderr);
            if first.is_empty() { "send failed".to_owned() } else { first }
        }
        AttestationError::SendTimeout { .. } => "send timed out".to_owned(),
        other => model_line(&other.to_string()),
    }
}

impl SendMessageResult {
    /// `{"message_id", "status": "sent"|"failed", "output"?, "error"?}`. `error`
    /// is one line of at most 1024 bytes, never the full stderr.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Sent { message_id, output } => {
                json!({"message_id": message_id, "status": "sent", "output": output})
            }
            Self::Failed { message_id, error } => {
                json!({"message_id": message_id, "status": "failed", "error": error})
            }
        }
    }

    /// For MCP `isError`.
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

/// parse, compose, send, result. Never panics; every failure becomes `Failed`.
/// Blocking: tokio hosts call it inside `spawn_blocking`.
pub fn run_send_message(
    input: &serde_json::Value,
    signer: &ReplySigner,
    deliverer: &PrincipalId,
    now_unix: i64,
    cmd: &SendCommand,
) -> SendMessageResult {
    let failed = |message_id: Option<String>, e: &AttestationError| SendMessageResult::Failed {
        message_id,
        error: failure_text(e),
    };
    let draft = match parse_tool_input(input) {
        Ok(d) => d,
        Err(e) => return failed(None, &e),
    };
    let reply = match compose_reply(signer, deliverer, now_unix, draft) {
        Ok(r) => r,
        Err(e) => return failed(None, &e),
    };
    match send_via_command(cmd, &reply) {
        Ok(out) => {
            let text = out.stdout.trim();
            let output = serde_json::from_str(text).unwrap_or_else(|_| serde_json::Value::String(text.to_owned()));
            SendMessageResult::Sent { message_id: reply.message_id, output }
        }
        Err(e) => failed(Some(reply.message_id), &e),
    }
}
