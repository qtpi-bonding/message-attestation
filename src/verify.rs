//! Verifying a Delivery. Reads no clock and persists nothing until `confirm`.

use identity_crypto::transcripts::delivery_transcript;
use identity_crypto::{
    pb, verify_carried_message, verify_p256, verify_root_device_delegation, PrincipalId, PublicKey,
    SKEW_SECONDS,
};
use prost::Message as _;

use crate::locate::locate;
use crate::message::{is_valid_id, validate_message, MessageKey, MESSAGE_BODY_TYPE};
use crate::names::{RegisteredName, ResolvedPrincipal};
use crate::render::MessageView;
use crate::replay::ReplayStore;
use crate::AttestationError;

/// Trusted deliverers are principals, not keys.
pub struct DeliveryPolicy<'a> {
    pub trusted: &'a [PrincipalId],
    pub self_id: &'a PrincipalId,
    pub own_devices: &'a [PublicKey],
    pub max_age_secs: Option<i64>,
    /// The deliverer's device delegation is checked at this time.
    pub now_unix: i64,
}

#[derive(Clone, Debug)]
pub struct VerifiedMessage {
    author: PrincipalId,
    author_id: String,
    message: pb::Message,
    via: Vec<pb::Target>,
    author_name: Option<RegisteredName>,
}

impl VerifiedMessage {
    pub fn author(&self) -> &PrincipalId {
        &self.author
    }
    pub fn message(&self) -> &pb::Message {
        &self.message
    }
    pub fn via(&self) -> &[pb::Target] {
        &self.via
    }
    /// The name the deliverer signed for this author, if any.
    pub fn author_name(&self) -> Option<&RegisteredName> {
        self.author_name.as_ref()
    }
    /// The renderer's input, borrowing from this message.
    pub fn view(&self) -> MessageView<'_> {
        let m = &self.message;
        MessageView {
            message_id: &m.message_id,
            author_id: &self.author_id,
            to: &m.to,
            via: &self.via,
            reply_to: m.reply_to.as_deref(),
            references: &m.references,
            mentions: &m.mentions,
            author_name: self.author_name.as_ref().map(RegisteredName::as_str),
            body: &m.body,
        }
    }
    pub fn key(&self) -> MessageKey {
        MessageKey { author: self.author.clone(), message_id: self.message.message_id.clone() }
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedDelivery {
    delivery_id: String,
    recipient_id: PrincipalId,
    deliverer: PrincipalId,
    deliverer_device: PublicKey,
    sequence: u64,
    attested_at_unix: i64,
    messages: Vec<VerifiedMessage>,
    names: Vec<ResolvedPrincipal>,
}

impl VerifiedDelivery {
    pub fn delivery_id(&self) -> &str {
        &self.delivery_id
    }
    pub fn recipient_id(&self) -> &PrincipalId {
        &self.recipient_id
    }
    pub fn deliverer(&self) -> &PrincipalId {
        &self.deliverer
    }
    pub fn deliverer_device(&self) -> &PublicKey {
        &self.deliverer_device
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn attested_at_unix(&self) -> i64 {
        self.attested_at_unix
    }
    /// In signed order.
    pub fn messages(&self) -> &[VerifiedMessage] {
        &self.messages
    }
    /// Every signed name, sorted by principal id.
    pub fn names(&self) -> &[ResolvedPrincipal] {
        &self.names
    }
}

#[derive(Debug)]
#[must_use]
pub struct PendingSequence {
    scope: String,
    key: String,
    sequence: u64,
}

#[derive(Debug)]
#[must_use]
pub struct Verified {
    pub delivery: VerifiedDelivery,
    pub pending: PendingSequence,
}

pub fn verify_delivery(
    delivery: &pb::Delivery,
    policy: &DeliveryPolicy<'_>,
    replay: &dyn ReplayStore,
) -> Result<Verified, AttestationError> {
    if delivery.messages.is_empty() {
        return Err(AttestationError::EmptyMessages);
    }
    let transcript_err = |e: identity_crypto::Error| AttestationError::Transcript(e.to_string());
    let signer_device = delivery
        .signer_device
        .as_ref()
        .ok_or_else(|| AttestationError::Transcript("missing signer_device".to_string()))?;
    let genesis = signer_device
        .principal_genesis
        .as_ref()
        .ok_or_else(|| AttestationError::Transcript("missing signer_device.principal_genesis".to_string()))?;
    let deliverer = PrincipalId::from_genesis(PublicKey::try_from(genesis).map_err(transcript_err)?);
    let deliverer_str = deliverer.to_string();
    if !policy.trusted.contains(&deliverer) {
        return Err(AttestationError::UnknownDeliverer(deliverer_str));
    }
    let device = verify_root_device_delegation(signer_device, &deliverer, policy.now_unix)
        .map_err(|e| AttestationError::DelivererDevice(e.to_string()))?;

    let transcript = delivery_transcript(delivery).map_err(transcript_err)?;
    verify_p256(&device, &transcript, &delivery.signature)
        .map_err(|_| AttestationError::BadSignature)?;

    if !is_valid_id(&delivery.delivery_id) {
        return Err(AttestationError::InvalidDeliveryId);
    }
    if delivery.recipient_id != policy.self_id.to_string() {
        return Err(AttestationError::WrongRecipient);
    }
    if policy.own_devices.is_empty() {
        return Err(AttestationError::OwnDevicesMissing);
    }
    let is_recipient = delivery.recipient_devices.iter().any(|d| {
        PublicKey::try_from(d).is_ok_and(|k| policy.own_devices.contains(&k))
    });
    if !is_recipient {
        return Err(AttestationError::NotARecipient);
    }

    let attested_at_unix = delivery
        .attested_at
        .as_ref()
        .ok_or_else(|| AttestationError::Transcript("missing attested_at".to_string()))?
        .seconds;
    if let Some(max) = policy.max_age_secs {
        // A delivery may be dated up to the clock skew identity-crypto allows
        // ahead of `now_unix`, as the deliverer delegation check does.
        let age = policy.now_unix.saturating_sub(attested_at_unix);
        if age < -SKEW_SECONDS || age > max {
            return Err(AttestationError::Stale { age, max });
        }
    }

    let scope = policy.self_id.to_string();
    if let Some(last) = replay.last_seen(&scope, &deliverer_str)? {
        if last >= delivery.sequence {
            return Err(AttestationError::Replay {
                principal: deliverer_str,
                last,
                got: delivery.sequence,
            });
        }
    }

    let mut messages = Vec::with_capacity(delivery.messages.len());
    for (index, signed) in delivery.messages.iter().enumerate() {
        let carried = verify_carried_message(signed, &deliverer_str).map_err(|e| match e {
            identity_crypto::Error::WrongAudience => AttestationError::WrongAudience { index },
            other => AttestationError::MessageSignature { index, reason: other.to_string() },
        })?;
        if carried.body_type() != MESSAGE_BODY_TYPE {
            return Err(AttestationError::WrongBodyType { index });
        }
        let message = pb::Message::decode(carried.body())
            .map_err(|e| AttestationError::Decode(e.to_string()))?;
        validate_message(&message)?;
        let via = delivery
            .via
            .get(index)
            .map(|t| t.targets.clone())
            .unwrap_or_default();
        if via.is_empty() || via.iter().any(|t| !message.to.contains(t))
        {
            return Err(AttestationError::InvalidVia { index });
        }
        messages.push(VerifiedMessage {
            author: carried.author().clone(),
            author_id: carried.author().to_string(),
            message,
            via,
            author_name: None,
        });
    }

    let mut names = Vec::with_capacity(delivery.names.len());
    for entry in &delivery.names {
        let name = RegisteredName::parse(&entry.name)?;
        let id = PrincipalId::parse_canonical(&entry.principal_id)
            .map_err(|e| AttestationError::Transcript(e.to_string()))?;
        let mut authored = false;
        for m in messages.iter_mut().filter(|m| m.author == id) {
            m.author_name = Some(name.clone());
            authored = true;
        }
        if !authored {
            return Err(AttestationError::StrayName { principal: entry.principal_id.clone() });
        }
        names.push(ResolvedPrincipal::from_signed(id, name));
    }

    Ok(Verified {
        delivery: VerifiedDelivery {
            delivery_id: delivery.delivery_id.clone(),
            recipient_id: policy.self_id.clone(),
            deliverer,
            deliverer_device: device,
            sequence: delivery.sequence,
            attested_at_unix,
            messages,
            names,
        },
        pending: PendingSequence { scope, key: deliverer_str, sequence: delivery.sequence },
    })
}

/// `locate` then `verify_delivery`; `Ok(None)` when `meta` has no value at `meta_key`.
pub fn verify_delivery_meta(
    meta: &serde_json::Value,
    meta_key: &str,
    policy: &DeliveryPolicy<'_>,
    replay: &dyn ReplayStore,
) -> Result<Option<Verified>, AttestationError> {
    match locate(meta, meta_key)? {
        None => Ok(None),
        Some(delivery) => verify_delivery(&delivery, policy, replay).map(Some),
    }
}

pub fn confirm(replay: &dyn ReplayStore, pending: PendingSequence) -> Result<(), AttestationError> {
    if replay.record(&pending.scope, &pending.key, pending.sequence)? {
        return Ok(());
    }
    let last = replay.last_seen(&pending.scope, &pending.key)?.unwrap_or(0);
    Err(AttestationError::Replay { principal: pending.key, last, got: pending.sequence })
}
