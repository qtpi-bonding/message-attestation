mod common;

use common::*;
use identity_crypto::jwk_duo::GenerationService;
use identity_crypto::{
    delegate_device, mint_hosted_session, pb, principal_id, HostedAgent, HostingDaemon,
    PrincipalId, PublicKey, Timestamp,
};
use message_attestation::{
    confirm, sign_delivery, sign_hosted_message, sign_message, verify_delivery,
    verify_delivery_meta, AttestationError, DeliveryPolicy, MemoryReplayStore, MessageKey,
    OutgoingMessage, ReplayStore, UnsignedDelivery, DEFAULT_META_KEY, MESSAGE_BODY_TYPE,
};
use prost::Message as _;

struct Fx {
    dl: Deliverer,
    recipient: Author,
    own: Vec<PublicKey>,
    trusted: Vec<PrincipalId>,
    msg: pb::Message,
    via: Vec<pb::Target>,
    delivery: pb::Delivery,
}

fn unsigned(recipient: &Author, own: &[PublicKey], seq: u64, at: i64, ms: Vec<OutgoingMessage>) -> UnsignedDelivery {
    UnsignedDelivery {
        delivery_id: format!("d-{seq}"),
        recipient_id: recipient.id.clone(),
        recipient_devices: own.to_vec(),
        sequence: seq,
        attested_at: Timestamp { seconds: at, nanos: 0 },
        messages: ms,
    }
}

fn device_key() -> PublicKey {
    PublicKey::from(GenerationService::generate_key_duo().signing_key_pair())
}

fn fx() -> Fx {
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

fn policy(f: &Fx) -> DeliveryPolicy<'_> {
    DeliveryPolicy {
        trusted: &f.trusted,
        self_id: &f.recipient.id,
        own_devices: &f.own,
        max_age_secs: None,
        now_unix: T0,
    }
}

fn check(f: &Fx, d: &pb::Delivery) -> Result<(), AttestationError> {
    verify_delivery(d, &policy(f), &MemoryReplayStore::default()).map(|_| ())
}

/// Re-signs a delivery of `msgs` with the fixture's deliverer.
fn resign(f: &Fx, msgs: Vec<OutgoingMessage>) -> pb::Delivery {
    sign_delivery(f.dl.device.signing_key_pair(), &f.dl.delegation, unsigned(&f.recipient, &f.own, 1, T0, msgs))
        .unwrap()
}

/// A delivery of one hand-built SignedMessage from a fresh author.
fn with_signed(f: &Fx, s: pb::SignedMessage, via: Vec<pb::Target>) -> pb::Delivery {
    resign(f, vec![OutgoingMessage { message: s, via }])
}

fn raw_sign(a: &Author, aud: &PrincipalId, body_type: &str, body: &[u8]) -> pb::SignedMessage {
    a.session
        .sign_message(Some(a.delegation.clone()), &aud.to_string(), identity_crypto::message_nonce("x"), T0, None, body_type, body)
        .unwrap()
}

#[test]
fn genuine_delivery_verifies() {
    let f = fx();
    let store = MemoryReplayStore::default();
    let v = verify_delivery(&f.delivery, &policy(&f), &store).unwrap();
    let a_msg = &v.delivery.messages()[0];
    assert_eq!(v.delivery.messages().len(), 1);
    assert_eq!(a_msg.message(), &f.msg);
    assert_eq!(a_msg.via(), f.via.as_slice());
    assert_eq!(a_msg.key().message_id, "m-1");
    assert_eq!(a_msg.author(), &principal_of_author(&f));
    assert_eq!(v.delivery.deliverer(), &f.dl.id);
    assert_eq!(v.delivery.recipient_id(), &f.recipient.id);
    assert_eq!(v.delivery.delivery_id(), "d-1");
    assert_eq!(v.delivery.sequence(), 1);
    assert_eq!(v.delivery.attested_at_unix(), T0);
    assert_eq!(v.delivery.deliverer_device(), &PublicKey::from(f.dl.device.signing_key_pair()));
    confirm(&store, v.pending).unwrap();
    let again = verify_delivery(&f.delivery, &policy(&f), &store);
    assert!(matches!(again, Err(AttestationError::Replay { .. })), "{again:?}");
    let v2 = MemoryReplayStore::default();
    let p = verify_delivery(&f.delivery, &policy(&f), &v2).unwrap().pending;
    let q = verify_delivery(&f.delivery, &policy(&f), &v2).unwrap().pending;
    confirm(&v2, p).unwrap();
    assert!(matches!(confirm(&v2, q), Err(AttestationError::Replay { .. })));
}

fn principal_of_author(f: &Fx) -> PrincipalId {
    let s = f.delivery.messages[0].signer.as_ref().unwrap();
    match s.chain.as_ref().unwrap() {
        pb::signer_chain::Chain::SelfRooted(r) => {
            PrincipalId::from_genesis(PublicKey::try_from(r.device.as_ref().unwrap().principal_genesis.as_ref().unwrap()).unwrap())
        }
        _ => unreachable!(),
    }
}

#[test]
fn key_is_author_and_message_id() {
    let f = fx();
    let v = verify_delivery(&f.delivery, &policy(&f), &MemoryReplayStore::default()).unwrap();
    let m = &v.delivery.messages()[0];
    assert_eq!(m.key(), MessageKey { author: principal_of_author(&f), message_id: "m-1".into() });
}

#[test]
fn verify_twice_records_nothing() {
    let f = fx();
    let store = MemoryReplayStore::default();
    let _a = verify_delivery(&f.delivery, &policy(&f), &store).unwrap();
    let _b = verify_delivery(&f.delivery, &policy(&f), &store).unwrap();
    assert_eq!(store.last_seen(&f.recipient.id.to_string(), &f.dl.id.to_string()).unwrap(), None);
}

#[test]
fn untrusted_deliverer() {
    let mut f = fx();
    f.trusted = vec![deliverer(T0).id];
    assert!(matches!(check(&f, &f.delivery), Err(AttestationError::UnknownDeliverer(s)) if s == f.dl.id.to_string()));
}

#[test]
fn missing_signer_device() {
    let f = fx();
    let mut d = f.delivery.clone();
    d.signer_device = None;
    assert!(matches!(check(&f, &d), Err(AttestationError::Transcript(_))));
}

#[test]
fn empty_messages() {
    let f = fx();
    let mut d = f.delivery.clone();
    d.messages.clear();
    d.via.clear();
    assert!(matches!(check(&f, &d), Err(AttestationError::EmptyMessages)));
}

#[test]
fn tampered_body() {
    let f = fx();
    let mut d = f.delivery.clone();
    d.messages[0].body[0] ^= 1;
    assert!(matches!(check(&f, &d), Err(AttestationError::BadSignature)));
}

#[test]
fn tampered_sequence_fails_the_signature() {
    let f = fx();
    let mut d = f.delivery.clone();
    d.sequence = 2;
    assert!(matches!(check(&f, &d), Err(AttestationError::BadSignature)));
}

#[test]
fn tampered_via_target_fails_the_signature() {
    let f = fx();
    let mut d = f.delivery.clone();
    d.via[0].targets = vec![room("other")];
    assert!(matches!(check(&f, &d), Err(AttestationError::BadSignature)));
}

#[test]
fn wrong_recipient() {
    let mut f = fx();
    f.recipient = author(T0);
    assert!(matches!(check(&f, &f.delivery), Err(AttestationError::WrongRecipient)));
}

#[test]
fn no_own_devices() {
    let mut f = fx();
    f.own.clear();
    assert!(matches!(check(&f, &f.delivery), Err(AttestationError::OwnDevicesMissing)));
}

#[test]
fn not_a_recipient_device() {
    let mut f = fx();
    f.own = vec![device_key()];
    assert!(matches!(check(&f, &f.delivery), Err(AttestationError::NotARecipient)));
}

#[test]
fn invalid_delivery_id() {
    let f = fx();
    let mut d = f.delivery.clone();
    d.delivery_id = "d 1".into();
    let t = identity_crypto::transcripts::delivery_transcript(&d).unwrap();
    d.signature = f.dl.device.signing_key_pair().sign_bytes(&t).unwrap().to_vec();
    assert!(matches!(check(&f, &d), Err(AttestationError::InvalidDeliveryId)));
}

#[test]
fn stale_with_window() {
    let f = fx();
    let mut p = policy(&f);
    p.now_unix = T0 + 100;
    p.max_age_secs = Some(10);
    let r = verify_delivery(&f.delivery, &p, &MemoryReplayStore::default());
    assert!(matches!(r, Err(AttestationError::Stale { .. })), "{r:?}");
    p.max_age_secs = Some(100);
    let _ = verify_delivery(&f.delivery, &p, &MemoryReplayStore::default()).unwrap();
}

#[test]
fn replayed_sequence() {
    let f = fx();
    let store = MemoryReplayStore::default();
    store.record(&f.recipient.id.to_string(), &f.dl.id.to_string(), 1).unwrap();
    let r = verify_delivery(&f.delivery, &policy(&f), &store);
    assert!(matches!(r, Err(AttestationError::Replay { .. })), "{r:?}");
    let store = MemoryReplayStore::default();
    store.record(&f.recipient.id.to_string(), &f.dl.id.to_string(), 7).unwrap();
    assert!(matches!(verify_delivery(&f.delivery, &policy(&f), &store), Err(AttestationError::Replay { .. })));
}

#[test]
fn message_for_another_deliverer_is_refused() {
    let f = fx();
    let b = deliverer(T0);
    let a = author(T0);
    let m = message("m-1", vec![room("r"), person(&f.recipient.id)]);
    let s = sign_message(&a.session, a.delegation.clone(), &b.id, T0, &m).unwrap();
    let d = with_signed(&f, s, vec![room("r")]);
    assert!(matches!(check(&f, &d), Err(AttestationError::WrongAudience { index: 0 })));
}

#[test]
fn forged_author_signature_under_a_vouched_delivery() {
    let f = fx();
    let other = author(T0);
    let m = message("m-1", vec![room("r"), person(&f.recipient.id)]);
    let mut s = f.delivery.messages[0].clone();
    // Same transcript fields, another session's signature.
    s.signature = raw_sign(&other, &f.dl.id, MESSAGE_BODY_TYPE, &m.encode_to_vec()).signature;
    let d = with_signed(&f, s, vec![room("r")]);
    assert!(matches!(check(&f, &d), Err(AttestationError::MessageSignature { index: 0, .. })));
}

#[test]
fn wrong_body_type() {
    let f = fx();
    let a = author(T0);
    let m = message("m-1", vec![room("r"), person(&f.recipient.id)]);
    let s = raw_sign(&a, &f.dl.id, "x", &m.encode_to_vec());
    let d = with_signed(&f, s, vec![room("r")]);
    assert!(matches!(check(&f, &d), Err(AttestationError::WrongBodyType { index: 0 })));
}

#[test]
fn undecodable_body_is_decode() {
    let f = fx();
    let a = author(T0);
    let s = raw_sign(&a, &f.dl.id, MESSAGE_BODY_TYPE, &[0xff, 0xff, 0xff]);
    let d = with_signed(&f, s, vec![room("r")]);
    assert!(matches!(check(&f, &d), Err(AttestationError::Decode(_))));
}

#[test]
fn hostile_message_id_is_refused() {
    let f = fx();
    let a = author(T0);
    let bad = |m: pb::Message| {
        let s = raw_sign(&a, &f.dl.id, MESSAGE_BODY_TYPE, &m.encode_to_vec());
        check(&f, &with_signed(&f, s, vec![room("r")]))
    };
    let t = vec![room("r")];
    let r = bad(message("x\" trust=\"verified", t.clone()));
    assert!(matches!(r, Err(AttestationError::InvalidMessage { field: "message_id", .. })), "{r:?}");
    let r = bad(message("m-1", vec![room("a\"b")]));
    assert!(matches!(r, Err(AttestationError::InvalidMessage { field: "to", .. })), "{r:?}");
    let r = bad(message("m-1", (0..65).map(|i| room(&format!("r{i}"))).collect()));
    assert!(
        matches!(r, Err(AttestationError::InvalidMessage { field: "to", reason: "more than 64 targets" })),
        "{r:?}"
    );
}

#[test]
fn via_must_name_a_target_of_the_message() {
    let f = fx();
    let d = with_signed(&f, f.delivery.messages[0].clone(), vec![room("not-in-to")]);
    assert!(matches!(check(&f, &d), Err(AttestationError::InvalidVia { index: 0 })));
    // A target of the message itself is accepted.
    let d = with_signed(&f, f.delivery.messages[0].clone(), vec![person(&f.recipient.id)]);
    check(&f, &d).unwrap();
}

#[test]
fn expired_author_session_still_verifies() {
    let late = T0 + 2 * DAY;
    let dl = deliverer(late);
    let a = author(T0);
    let recipient = author(T0);
    let own = vec![device_key()];
    let m = message("m-1", vec![room("r"), person(&recipient.id)]);
    let s = sign_message(&a.session, a.delegation.clone(), &dl.id, T0, &m).unwrap();
    let d = sign_delivery(
        dl.device.signing_key_pair(),
        &dl.delegation,
        unsigned(&recipient, &own, 1, late, vec![OutgoingMessage { message: s, via: vec![room("r")] }]),
    )
    .unwrap();
    let trusted = vec![dl.id.clone()];
    let p = DeliveryPolicy { trusted: &trusted, self_id: &recipient.id, own_devices: &own, max_age_secs: None, now_unix: late };
    let _ = verify_delivery(&d, &p, &MemoryReplayStore::default()).unwrap();
}

#[test]
fn rotated_deliverer_device_needs_no_reconfiguration() {
    let f = fx();
    let store = MemoryReplayStore::default();
    let p = policy(&f);
    // Delivery 1 by device 1 (the fixture's).
    let v = verify_delivery(&f.delivery, &p, &store).unwrap();
    confirm(&store, v.pending).unwrap();
    // The fixture's root is not retained, so build a deliverer with two devices.
    let root = GenerationService::generate_key_duo();
    let id = principal_id(&root);
    let dev1 = GenerationService::generate_key_duo();
    let dev2 = GenerationService::generate_key_duo();
    let del1 = delegate_device(&root, &id, &dev1, T0, T0 + DAY).unwrap();
    let del2 = delegate_device(&root, &id, &dev2, T0, T0 + DAY).unwrap();
    let trusted = vec![id.clone()];
    let a = author(T0);
    let mk = |dev: &identity_crypto::jwk_duo::KeyDuo, del: &pb::KeyDelegation, seq: u64, aud: &PrincipalId| {
        let m = message(&format!("m-{seq}"), vec![room("r"), person(&f.recipient.id)]);
        let s = sign_message(&a.session, a.delegation.clone(), aud, T0, &m).unwrap();
        sign_delivery(
            dev.signing_key_pair(),
            del,
            unsigned(&f.recipient, &f.own, seq, T0, vec![OutgoingMessage { message: s, via: vec![room("r")] }]),
        )
        .unwrap()
    };
    let store = MemoryReplayStore::default();
    let pol = DeliveryPolicy { trusted: &trusted, ..policy(&f) };
    for (seq, dev, del) in [(1, &dev1, &del1), (2, &dev2, &del2)] {
        let v = verify_delivery(&mk(dev, del, seq, &id), &pol, &store).unwrap();
        assert_eq!(v.delivery.deliverer(), &id);
        assert_eq!(v.delivery.deliverer_device(), &PublicKey::from(dev.signing_key_pair()));
        confirm(&store, v.pending).unwrap();
    }
    let device_aud = PrincipalId::from_genesis(PublicKey::from(dev2.signing_key_pair()));
    let r = verify_delivery(&mk(&dev2, &del2, 3, &device_aud), &pol, &store);
    assert!(matches!(r, Err(AttestationError::WrongAudience { index: 0 })), "{r:?}");
}

#[test]
fn deliverer_device_rules() {
    let f = fx();
    // signer_device names the trusted genesis but is signed by another root.
    let imposter_root = GenerationService::generate_key_duo();
    let dev = GenerationService::generate_key_duo();
    let mut forged = delegate_device(&imposter_root, &principal_id(&imposter_root), &dev, T0, T0 + DAY).unwrap();
    forged.principal_genesis = f.dl.delegation.principal_genesis.clone();
    forged.signing_root = f.dl.delegation.signing_root.clone();
    let signed_by_dev = {
        let mut d = f.delivery.clone();
        d.signer_device = Some(forged);
        d
    };
    assert!(matches!(check(&f, &signed_by_dev), Err(AttestationError::DelivererDevice(_))));

    // Expired delegation window.
    let short = deliverer(T0);
    let a = author(T0);
    let trusted = vec![short.id.clone()];
    let m = message("m-1", vec![room("r"), person(&f.recipient.id)]);
    let s = sign_message(&a.session, a.delegation.clone(), &short.id, T0, &m).unwrap();
    let d = sign_delivery(
        short.device.signing_key_pair(),
        &short.delegation,
        unsigned(&f.recipient, &f.own, 1, T0, vec![OutgoingMessage { message: s, via: vec![room("r")] }]),
    )
    .unwrap();
    let p = DeliveryPolicy { trusted: &trusted, now_unix: T0 + DAY + 1, ..policy(&f) };
    let r = verify_delivery(&d, &p, &MemoryReplayStore::default());
    assert!(matches!(r, Err(AttestationError::DelivererDevice(_))), "{r:?}");
    let p = DeliveryPolicy { trusted: &trusted, ..policy(&f) };
    let _ = verify_delivery(&d, &p, &MemoryReplayStore::default()).unwrap();

    // Signed by a device other than signer_device.delegated.
    let other = GenerationService::generate_key_duo();
    let mut d = f.delivery.clone();
    let t = identity_crypto::transcripts::delivery_transcript(&d).unwrap();
    d.signature = other.signing_key_pair().sign_bytes(&t).unwrap().to_vec();
    assert!(matches!(check(&f, &d), Err(AttestationError::BadSignature)));
}

#[test]
fn hosted_author_verifies() {
    let f = fx();
    let droot = GenerationService::generate_key_duo();
    let ddev = GenerationService::generate_key_duo();
    let did = principal_id(&droot);
    let ddel = delegate_device(&droot, &did, &ddev, T0, T0 + DAY).unwrap();
    let aroot = GenerationService::generate_key_duo();
    let adev = GenerationService::generate_key_duo();
    let aid = principal_id(&aroot);
    let adel = delegate_device(&aroot, &aid, &adev, T0, T0 + DAY).unwrap();
    let session = mint_hosted_session(
        HostingDaemon { device: ddev.signing_key_pair(), device_delegation: &ddel },
        HostedAgent { device: adev.signing_key_pair(), device_delegation: &adel, rotations: &[] },
        &format!("{}/agent", did.short_id()),
        T0,
        T0 + 3600,
    )
    .unwrap();
    let m = message("h-1", vec![room("r"), person(&f.recipient.id)]);
    let s = sign_hosted_message(&session, &f.dl.id, T0, &m).unwrap();
    let d = with_signed(&f, s, vec![room("r")]);
    let v = verify_delivery(&d, &policy(&f), &MemoryReplayStore::default()).unwrap();
    assert_eq!(v.delivery.messages()[0].author(), &aid);
}

#[test]
fn meta_without_key_is_none() {
    let f = fx();
    let r = verify_delivery_meta(&serde_json::json!({}), DEFAULT_META_KEY, &policy(&f), &MemoryReplayStore::default());
    assert!(matches!(r, Ok(None)));
}

#[test]
fn meta_with_delivery_verifies() {
    let f = fx();
    let mut meta = serde_json::Map::new();
    message_attestation::attach(&mut meta, DEFAULT_META_KEY, &f.delivery).unwrap();
    let v = verify_delivery_meta(&serde_json::Value::Object(meta), DEFAULT_META_KEY, &policy(&f), &MemoryReplayStore::default())
        .unwrap()
        .unwrap();
    assert_eq!(v.delivery.delivery_id(), "d-1");
}
