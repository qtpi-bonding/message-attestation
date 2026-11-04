#![allow(dead_code)]

use identity_crypto::jwk_duo::GenerationService;
use identity_crypto::{
    delegate_device, mint_hosted_session, mint_session, pb, principal_id, signing_public,
    HostedAgent, HostedSessionCredential, HostingDaemon, PrincipalId, PublicKey, SessionCredential,
    Timestamp,
};
use message_attestation::{sign_delivery, sign_message, DeliveryPolicy, OutgoingMessage, UnsignedDelivery};

pub const T0: i64 = 1_700_000_000;
pub const DAY: i64 = 86_400;

pub struct Author {
    pub id: PrincipalId,
    pub session: SessionCredential,
    pub delegation: pb::KeyDelegation,
}

pub fn author(now: i64) -> Author {
    author_with(now, DAY, 3600)
}

/// An author whose device delegation and session last the given seconds from `now`.
pub fn author_with(now: i64, delegation_secs: i64, session_secs: i64) -> Author {
    author_issued(now, now, delegation_secs, session_secs)
}

/// Like `author_with`, but the device delegation is issued at `delegation_at`.
pub fn author_issued(now: i64, delegation_at: i64, delegation_secs: i64, session_secs: i64) -> Author {
    let root = GenerationService::generate_key_duo();
    let device = GenerationService::generate_key_duo();
    let id = principal_id(&root);
    let delegation = delegate_device(&root, &id, &device, delegation_at, delegation_at + delegation_secs).unwrap();
    let session = mint_session(device.signing_key_pair(), &signing_public(&root), now, now + session_secs).unwrap();
    Author { id, session, delegation }
}

pub fn message(id: &str, to: Vec<pb::Target>) -> pb::Message {
    pb::Message {
        message_id: id.to_string(),
        to,
        reply_to: None,
        references: vec![],
        mentions: vec![],
        authored_at: Some(identity_crypto::Timestamp { seconds: T0, nanos: 0 }),
        body: "hello".to_string(),
    }
}

pub fn room(id: &str) -> pb::Target {
    pb::Target { target: Some(pb::target::Target::RoomId(id.to_string())) }
}

pub fn person(id: &PrincipalId) -> pb::Target {
    pb::Target { target: Some(pb::target::Target::RecipientId(id.to_string())) }
}

pub struct Deliverer {
    pub id: PrincipalId,
    pub device: identity_crypto::jwk_duo::KeyDuo,
    pub delegation: pb::KeyDelegation,
}

pub fn deliverer(now: i64) -> Deliverer {
    let root = GenerationService::generate_key_duo();
    let device = GenerationService::generate_key_duo();
    let id = principal_id(&root);
    let delegation = delegate_device(&root, &id, &device, now, now + DAY).unwrap();
    Deliverer { id, device, delegation }
}

pub struct HostedAuthor {
    pub id: PrincipalId,
    pub session: HostedSessionCredential,
}

/// A daemon-hosted agent whose session lasts an hour from `now`.
pub fn hosted_author(now: i64) -> HostedAuthor {
    let droot = GenerationService::generate_key_duo();
    let ddev = GenerationService::generate_key_duo();
    let did = principal_id(&droot);
    let ddel = delegate_device(&droot, &did, &ddev, now, now + DAY).unwrap();
    let aroot = GenerationService::generate_key_duo();
    let adev = GenerationService::generate_key_duo();
    let id = principal_id(&aroot);
    let adel = delegate_device(&aroot, &id, &adev, now, now + DAY).unwrap();
    let session = mint_hosted_session(
        HostingDaemon { device: ddev.signing_key_pair(), device_delegation: &ddel },
        HostedAgent { device: adev.signing_key_pair(), device_delegation: &adel, rotations: &[] },
        &format!("{}/agent", did.short_id()),
        now,
        now + 3600,
    )
    .unwrap();
    HostedAuthor { id, session }
}

pub struct Fx {
    pub dl: Deliverer,
    pub recipient: Author,
    pub own: Vec<PublicKey>,
    pub trusted: Vec<PrincipalId>,
    pub msg: pb::Message,
    pub via: Vec<pb::Target>,
    pub delivery: pb::Delivery,
}

pub fn unsigned(recipient: &Author, own: &[PublicKey], seq: u64, at: i64, ms: Vec<OutgoingMessage>) -> UnsignedDelivery {
    UnsignedDelivery {
        delivery_id: format!("d-{seq}"),
        recipient_id: recipient.id.clone(),
        recipient_devices: own.to_vec(),
        sequence: seq,
        attested_at: Timestamp { seconds: at, nanos: 0 },
        messages: ms,
    }
}

pub fn device_key() -> PublicKey {
    PublicKey::from(GenerationService::generate_key_duo().signing_key_pair())
}

pub fn fx() -> Fx {
    let dl = deliverer(T0);
    let a = author(T0);
    let recipient = author(T0);
    let own = vec![device_key()];
    let msg = message("m-1", vec![room("r"), person(&recipient.id)]);
    let signed = sign_message(&a.session, a.delegation.clone(), &dl.id, T0, &msg).unwrap();
    let via = vec![room("r")];
    let delivery = sign_delivery(
        dl.device.signing_key_pair(),
        &dl.delegation,
        unsigned(&recipient, &own, 1, T0, vec![OutgoingMessage { message: signed, via: via.clone() }]),
    )
    .unwrap();
    Fx { trusted: vec![dl.id.clone()], dl, recipient, own, msg, via, delivery }
}

pub fn policy(f: &Fx) -> DeliveryPolicy<'_> {
    DeliveryPolicy {
        trusted: &f.trusted,
        self_id: &f.recipient.id,
        own_devices: &f.own,
        max_age_secs: None,
        now_unix: T0,
    }
}

/// Re-signs a delivery of `msgs` with the fixture's deliverer.
pub fn resign(f: &Fx, msgs: Vec<OutgoingMessage>) -> pb::Delivery {
    sign_delivery(f.dl.device.signing_key_pair(), &f.dl.delegation, unsigned(&f.recipient, &f.own, 1, T0, msgs))
        .unwrap()
}

/// A delivery of one hand-built SignedMessage from a fresh author.
pub fn with_signed(f: &Fx, s: pb::SignedMessage, via: Vec<pb::Target>) -> pb::Delivery {
    resign(f, vec![OutgoingMessage { message: s, via }])
}

