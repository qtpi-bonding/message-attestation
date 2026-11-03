use identity_crypto::{
    message_nonce, pb, HostedSessionCredential, PrincipalId, SessionCredential,
};
use prost::Message as _;

use crate::error::AttestationError;

pub const MESSAGE_BODY_TYPE: &str = "type.googleapis.com/identitycrypto.v1.Message";
pub const MAX_TARGETS: usize = 64;
pub const MAX_ID_LEN: usize = 128;

const ID_REASON: &str = "must be 1-128 of [A-Za-z0-9._:-]";

/// 1..=MAX_ID_LEN bytes, each in [A-Za-z0-9._:-].
pub fn is_valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID_LEN
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn invalid(field: &'static str, reason: &'static str) -> AttestationError {
    AttestationError::InvalidMessage { field, reason }
}

fn is_canonical_principal(s: &str) -> bool {
    PrincipalId::parse_canonical(s).is_ok()
}

pub(crate) fn check_target(t: &pb::Target, field: &'static str) -> Result<(), AttestationError> {
    match &t.target {
        None => Err(invalid(field, "target not set")),
        Some(pb::target::Target::RoomId(id)) if !is_valid_id(id) => {
            Err(invalid(field, "room id must be 1-128 of [A-Za-z0-9._:-]"))
        }
        Some(pb::target::Target::RecipientId(id)) if !is_canonical_principal(id) => {
            Err(invalid(field, "recipient is not a canonical principal id"))
        }
        Some(_) => Ok(()),
    }
}

/// The target rules alone, used for a Message's `to`.
pub fn validate_target(t: &pb::Target) -> Result<(), AttestationError> {
    check_target(t, "to")
}

/// The id, `to`, `reply_to`, `references` and `mentions` rules, in field order.
/// Shared by `validate_message` and `render_message`.
pub(crate) fn check_fields(
    message_id: &str,
    to: &[pb::Target],
    reply_to: Option<&str>,
    references: &[String],
    mentions: &[String],
) -> Result<(), AttestationError> {
    if !is_valid_id(message_id) {
        return Err(invalid("message_id", ID_REASON));
    }
    if to.is_empty() {
        return Err(invalid("to", "empty"));
    }
    if to.len() > MAX_TARGETS {
        return Err(invalid("to", "more than 64 targets"));
    }
    to.iter().try_for_each(validate_target)?;
    if reply_to.is_some_and(|r| !is_valid_id(r)) {
        return Err(invalid("reply_to", ID_REASON));
    }
    if references.iter().any(|r| !is_valid_id(r)) {
        return Err(invalid("references", ID_REASON));
    }
    if mentions.iter().any(|p| !is_canonical_principal(p)) {
        return Err(invalid("mentions", "not a canonical principal id"));
    }
    Ok(())
}

/// What a renderer needs checked beyond `check_fields`: the author and `via`.
pub(crate) fn check_author_and_via(
    author_id: &str,
    via: &[pb::Target],
) -> Result<(), AttestationError> {
    if !is_canonical_principal(author_id) {
        return Err(invalid("author_id", "not a canonical principal id"));
    }
    if via.is_empty() {
        return Err(invalid("via", "empty"));
    }
    via.iter().try_for_each(|t| check_target(t, "via"))
}

/// Every Message rule, in field order.
pub fn validate_message(m: &pb::Message) -> Result<(), AttestationError> {
    check_fields(&m.message_id, &m.to, m.reply_to.as_deref(), &m.references, &m.mentions)?;
    if m.authored_at.is_none() {
        return Err(invalid("authored_at", "missing"));
    }
    Ok(())
}

pub fn sign_message(
    session: &SessionCredential,
    device_delegation: pb::KeyDelegation,
    audience: &PrincipalId,
    issued_at_unix: i64,
    message: &pb::Message,
) -> Result<pb::SignedMessage, AttestationError> {
    validate_message(message)?;
    session
        .sign_message(
            Some(device_delegation),
            &audience.to_string(),
            message_nonce(&message.message_id),
            issued_at_unix,
            None,
            MESSAGE_BODY_TYPE,
            &message.encode_to_vec(),
        )
        .map_err(|e| AttestationError::Sign(e.to_string()))
}

pub fn sign_hosted_message(
    session: &HostedSessionCredential,
    audience: &PrincipalId,
    issued_at_unix: i64,
    message: &pb::Message,
) -> Result<pb::SignedMessage, AttestationError> {
    validate_message(message)?;
    session
        .sign_message(
            &audience.to_string(),
            message_nonce(&message.message_id),
            issued_at_unix,
            None,
            MESSAGE_BODY_TYPE,
            &message.encode_to_vec(),
        )
        .map_err(|e| AttestationError::Sign(e.to_string()))
}

/// The one spelling of a message's identity for a recipient's seen set.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageKey {
    pub author: PrincipalId,
    pub message_id: String,
}
