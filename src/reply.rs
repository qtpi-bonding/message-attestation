use std::sync::Arc;

use identity_crypto::{
    pb, HostedSessionCredential, PrincipalId, SessionCredential, Timestamp,
};
use serde_json::Value;

use crate::error::AttestationError;
use crate::message::{sign_hosted_message, sign_message};

pub const MAX_BODY_BYTES: usize = 65536;

const KNOWN_FIELDS: [&str; 5] = ["to", "body", "reply_to", "references", "mentions"];

fn invalid(field: &'static str, reason: &'static str) -> AttestationError {
    AttestationError::InvalidMessage { field, reason }
}

/// What the model supplied, before ids and signatures.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplyDraft {
    pub to: Vec<pb::Target>,
    pub body: String,
    pub reply_to: Option<String>,
    pub references: Vec<String>,
    pub mentions: Vec<String>,
}

/// Owned and Clone, so a host can keep one per agent across async tasks.
#[derive(Clone)]
pub enum ReplySigner {
    Keyed { session: Arc<SessionCredential>, device_delegation: pb::KeyDelegation },
    Hosted { session: Arc<HostedSessionCredential> },
}

#[derive(Clone, Debug)]
pub struct ComposedReply {
    pub message_id: String,
    pub signed: pb::SignedMessage,
}

fn strings(v: &Value, field: &'static str) -> Result<Vec<String>, AttestationError> {
    match v {
        Value::Null => Ok(vec![]),
        Value::Array(a) => a
            .iter()
            .map(|s| s.as_str().map(str::to_owned).ok_or_else(|| invalid(field, "not a string")))
            .collect(),
        _ => Err(invalid(field, "not an array")),
    }
}

fn target(s: &str) -> Result<pb::Target, AttestationError> {
    let t = if let Some(id) = s.strip_prefix("room:") {
        pb::target::Target::RoomId(id.to_owned())
    } else if s.starts_with("p256:") {
        pb::target::Target::RecipientId(s.to_owned())
    } else {
        return Err(invalid("to", "must start with room: or p256:"));
    };
    Ok(pb::Target { target: Some(t) })
}

/// Enforces the tool's input shape itself. Ids and principals are checked
/// later, by `compose_reply`.
pub fn parse_tool_input(input: &Value) -> Result<ReplyDraft, AttestationError> {
    let obj = input.as_object().ok_or_else(|| invalid("input", "not an object"))?;
    if obj.keys().any(|k| !KNOWN_FIELDS.contains(&k.as_str())) {
        return Err(invalid("input", "unknown field"));
    }
    let to = match obj.get("to") {
        None | Some(Value::Null) => return Err(invalid("to", "missing")),
        Some(Value::Array(_)) => strings(&obj["to"], "to")?,
        Some(_) => return Err(invalid("to", "not an array")),
    };
    if to.is_empty() {
        return Err(invalid("to", "empty"));
    }
    let to = to.iter().map(|s| target(s)).collect::<Result<Vec<_>, _>>()?;
    let body = match obj.get("body") {
        None | Some(Value::Null) => return Err(invalid("body", "missing")),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return Err(invalid("body", "not a string")),
    };
    if body.is_empty() {
        return Err(invalid("body", "empty"));
    }
    check_body_size(&body)?;
    let reply_to = match obj.get("reply_to") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(invalid("reply_to", "not a string")),
    };
    let list = |k: &'static str| obj.get(k).map_or(Ok(vec![]), |v| strings(v, k));
    Ok(ReplyDraft { to, body, reply_to, references: list("references")?, mentions: list("mentions")? })
}

fn check_body_size(body: &str) -> Result<(), AttestationError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(invalid("body", "too long"));
    }
    Ok(())
}

/// "m-" followed by 32 lowercase hex characters of OS randomness.
pub fn new_message_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("OS randomness is available");
    let mut id = String::with_capacity(34);
    id.push_str("m-");
    for b in bytes {
        id.push(char::from_digit(u32::from(b >> 4), 16).expect("nibble"));
        id.push(char::from_digit(u32::from(b & 15), 16).expect("nibble"));
    }
    id
}

fn check_window(
    not_before: i64,
    not_after: i64,
    now: i64,
) -> Result<(), AttestationError> {
    if now < not_before || now > not_after {
        return Err(AttestationError::SessionExpired { not_after, now });
    }
    Ok(())
}

/// Checks the signer is valid at `now_unix`, checks the body size, mints the
/// id, sets `authored_at = issued_at = now_unix` and signs with
/// `audience = deliverer`.
pub fn compose_reply(
    signer: &ReplySigner,
    deliverer: &PrincipalId,
    now_unix: i64,
    draft: ReplyDraft,
) -> Result<ComposedReply, AttestationError> {
    match signer {
        ReplySigner::Keyed { session, device_delegation } => {
            let cert = session.cert();
            check_window(cert.not_before_unix_seconds, cert.not_after_unix_seconds, now_unix)?;
            check_window(
                device_delegation.issued_at_unix_seconds,
                device_delegation.not_after_unix_seconds,
                now_unix,
            )?;
        }
        ReplySigner::Hosted { session } => {
            let cert = session.cert();
            check_window(cert.not_before_unix_seconds, cert.not_after_unix_seconds, now_unix)?;
        }
    }
    check_body_size(&draft.body)?;
    let message_id = new_message_id();
    let message = pb::Message {
        message_id: message_id.clone(),
        to: draft.to,
        reply_to: draft.reply_to,
        references: draft.references,
        mentions: draft.mentions,
        authored_at: Some(Timestamp { seconds: now_unix, nanos: 0 }),
        body: draft.body,
    };
    let signed = match signer {
        ReplySigner::Keyed { session, device_delegation } => {
            sign_message(session, device_delegation.clone(), deliverer, now_unix, &message)?
        }
        ReplySigner::Hosted { session } => sign_hosted_message(session, deliverer, now_unix, &message)?,
    };
    Ok(ComposedReply { message_id, signed })
}
