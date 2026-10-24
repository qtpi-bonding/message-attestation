use identity_crypto::pb;
use identity_crypto::{verify_p256, PublicKey};

use crate::locate::locate;
use crate::replay::ReplayStore;
use crate::AttestationError;

pub trait TrustedKeys {
    fn get(&self, key_id: &str) -> Option<&PublicKey>;
}

impl TrustedKeys for [(String, PublicKey)] {
    fn get(&self, key_id: &str) -> Option<&PublicKey> {
        self.iter()
            .find(|(candidate, _)| candidate == key_id)
            .map(|(_, key)| key)
    }
}

impl TrustedKeys for Vec<(String, PublicKey)> {
    fn get(&self, key_id: &str) -> Option<&PublicKey> {
        <[(String, PublicKey)] as TrustedKeys>::get(self.as_slice(), key_id)
    }
}

pub struct AttestationPolicy<'a> {
    pub meta_key: &'a str,
    pub trusted: &'a dyn TrustedKeys,
    pub own_devices: Option<&'a [PublicKey]>,
    pub max_age_secs: Option<i64>,
    pub now_unix: Option<i64>,
}

pub struct VerifiedBody {
    pub message_id: String,
    pub room_id: String,
    pub body_text: String,
    pub author_genesis: Option<PublicKey>,
    pub outcome: pb::VerificationOutcome,
    pub delegation_cert: Option<pb::DelegationCert>,
}

pub struct VerifiedDelivery {
    pub key_id: String,
    pub batch_sequence: u64,
    pub attested_at_unix: i64,
    pub messages: Vec<VerifiedBody>,
    pub raw: Vec<u8>,
}

#[must_use]
pub struct PendingSequence {
    scope: String,
    key_id: String,
    sequence: u64,
}

#[must_use]
pub struct Verified {
    pub delivery: VerifiedDelivery,
    pub pending: PendingSequence,
}

pub fn verify_attestation(
    meta: &serde_json::Value,
    policy: &AttestationPolicy<'_>,
    replay: &dyn ReplayStore,
    scope: &str,
) -> Result<Option<Verified>, AttestationError> {
    let Some((raw, attestation)) = locate(meta, policy.meta_key)? else {
        return Ok(None);
    };

    if attestation.messages.is_empty() {
        return Err(AttestationError::EmptyMessages);
    }

    let own_devices = policy
        .own_devices
        .filter(|devices| !devices.is_empty())
        .ok_or(AttestationError::OwnDevicesMissing)?;

    let mut recipient_match = false;
    for recipient in &attestation.recipient_devices {
        let decoded = PublicKey::try_from(recipient)
            .map_err(|error| AttestationError::Transcript(error.to_string()))?;
        if own_devices.iter().any(|device| device == &decoded) {
            recipient_match = true;
        }
    }
    if !recipient_match {
        return Err(AttestationError::NotARecipient);
    }

    let key = policy
        .trusted
        .get(&attestation.key_id)
        .ok_or_else(|| AttestationError::UnknownKeyId(attestation.key_id.clone()))?;
    let transcript = identity_crypto::transcripts::delivery_attestation_transcript(&attestation)
        .map_err(|error| AttestationError::Transcript(error.to_string()))?;
    verify_p256(key, &transcript, &attestation.signature)
        .map_err(|_| AttestationError::BadSignature)?;

    let attested_at = attestation
        .attested_at
        .as_ref()
        .ok_or_else(|| AttestationError::Transcript("missing attested_at".to_owned()))?;
    if let Some(max) = policy.max_age_secs {
        let now = policy.now_unix.ok_or(AttestationError::ClockMissing)?;
        let age = now.checked_sub(attested_at.seconds).unwrap_or(i64::MAX);
        if age < 0 || age > max {
            return Err(AttestationError::Stale {
                age_secs: age,
                max,
            });
        }
    }

    if let Some(last) = replay.last_seen(scope, &attestation.key_id)? {
        if attestation.batch_sequence <= last {
            return Err(AttestationError::Replay {
                key_id: attestation.key_id.clone(),
                last,
                got: attestation.batch_sequence,
            });
        }
    }

    let messages = attestation
        .messages
        .iter()
        .map(|message| {
            let author_genesis = message
                .author_genesis
                .as_ref()
                .map(PublicKey::try_from)
                .transpose()
                .map_err(|error| AttestationError::Transcript(error.to_string()))?;
            Ok(VerifiedBody {
                message_id: message.message_id.clone(),
                room_id: message.room_id.clone(),
                body_text: message.body_text.clone(),
                author_genesis,
                outcome: pb::VerificationOutcome::try_from(message.verification_outcome)
                    .map_err(|error| AttestationError::Transcript(error.to_string()))?,
                delegation_cert: message.delegation_cert.clone(),
            })
        })
        .collect::<Result<Vec<_>, AttestationError>>()?;

    let pending = PendingSequence {
        scope: scope.to_owned(),
        key_id: attestation.key_id.clone(),
        sequence: attestation.batch_sequence,
    };
    Ok(Some(Verified {
        delivery: VerifiedDelivery {
            key_id: attestation.key_id,
            batch_sequence: attestation.batch_sequence,
            attested_at_unix: attested_at.seconds,
            messages,
            raw,
        },
        pending,
    }))
}

pub fn confirm(
    replay: &dyn ReplayStore,
    pending: PendingSequence,
) -> Result<(), AttestationError> {
    let accepted = replay.record(&pending.scope, &pending.key_id, pending.sequence)?;
    if accepted {
        return Ok(());
    }
    let last = replay
        .last_seen(&pending.scope, &pending.key_id)?
        .unwrap_or(0);
    Err(AttestationError::Replay {
        key_id: pending.key_id,
        last,
        got: pending.sequence,
    })
}
