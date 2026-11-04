use serde_json::json;

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
