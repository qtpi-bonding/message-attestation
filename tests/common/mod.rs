#![allow(dead_code)]

use identity_crypto::jwk_duo::GenerationService;
use identity_crypto::{
    delegate_device, mint_session, pb, principal_id, signing_public, PrincipalId, SessionCredential,
};

pub const T0: i64 = 1_700_000_000;
pub const DAY: i64 = 86_400;

pub struct Author {
    pub id: PrincipalId,
    pub session: SessionCredential,
    pub delegation: pb::KeyDelegation,
}

pub fn author(now: i64) -> Author {
    let root = GenerationService::generate_key_duo();
    let device = GenerationService::generate_key_duo();
    let id = principal_id(&root);
    let delegation = delegate_device(&root, &id, &device, now, now + DAY).unwrap();
    let session = mint_session(device.signing_key_pair(), &signing_public(&root), now, now + 3600).unwrap();
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
