mod common;

use common::*;
use identity_crypto::transcripts::delivery_transcript;
use identity_crypto::{verify_p256, PublicKey, Timestamp};
use message_attestation::{
    attach, locate, sign_delivery, sign_message, AttestationError, OutgoingMessage,
    UnsignedDelivery, DEFAULT_META_KEY,
};

fn outgoing(a: &Author, recipient: &identity_crypto::PrincipalId, id: &str) -> OutgoingMessage {
    let m = message(id, vec![person(recipient)]);
    let message = sign_message(&a.session, Some(a.delegation.clone()), &recipient.to_string(), T0, &m).unwrap();
    OutgoingMessage { message, via: vec![room("r")] }
}

fn unsigned(recipient: &Author, messages: Vec<OutgoingMessage>) -> UnsignedDelivery {
    let dev = identity_crypto::jwk_duo::GenerationService::generate_key_duo();
    UnsignedDelivery {
        delivery_id: "d-1".to_string(),
        recipient_id: recipient.id.clone(),
        recipient_devices: vec![PublicKey::from(dev.signing_key_pair())],
        sequence: 1,
        attested_at: Timestamp { seconds: T0, nanos: 0 },
        messages,
        names: vec![],
    }
}

#[test]
fn signed_delivery_verifies_under_the_signer() {
    let dl = deliverer(T0);
    let a = author(T0);
    let recipient = author(T0);
    let o = outgoing(&a, &recipient.id, "m-1");
    let u = unsigned(&recipient, vec![OutgoingMessage { message: o.message.clone(), via: o.via.clone() }]);
    let d = sign_delivery(dl.device.signing_key_pair(), &dl.delegation, u).unwrap();
    let device_pub = PublicKey::from(dl.device.signing_key_pair());
    verify_p256(&device_pub, &delivery_transcript(&d).unwrap(), &d.signature).unwrap();
    assert_eq!(d.signer_device, Some(dl.delegation.clone()));
    assert_eq!(d.messages[0], o.message);
    assert_eq!(d.via[0].targets, o.via);
    assert_eq!(d.recipient_id, recipient.id.to_string());
    assert_eq!(d.delivery_id, "d-1");
}

#[test]
fn sign_delivery_refusals() {
    let dl = deliverer(T0);
    let other = deliverer(T0);
    let a = author(T0);
    let recipient = author(T0);
    let mk = || vec![outgoing(&a, &recipient.id, "m-1")];
    let sign = |u: UnsignedDelivery| sign_delivery(dl.device.signing_key_pair(), &dl.delegation, u);

    let e = sign_delivery(other.device.signing_key_pair(), &dl.delegation, unsigned(&recipient, mk()));
    assert!(matches!(e, Err(AttestationError::Sign(_))), "{e:?}");
    assert!(matches!(sign(unsigned(&recipient, vec![])), Err(AttestationError::EmptyMessages)));
    let mut u = unsigned(&recipient, mk());
    u.recipient_devices.clear();
    assert!(matches!(sign(u), Err(AttestationError::NoRecipients)));
    let mut u = unsigned(&recipient, mk());
    u.delivery_id = "d 1".to_string();
    assert!(matches!(sign(u), Err(AttestationError::InvalidDeliveryId)));
    let mut ms = mk();
    ms.push(OutgoingMessage { via: vec![], ..outgoing(&a, &recipient.id, "m-2") });
    assert!(matches!(
        sign(unsigned(&recipient, ms)),
        Err(AttestationError::InvalidVia { index: 1 })
    ));
}

#[test]
fn attach_then_locate_round_trips() {
    let dl = deliverer(T0);
    let a = author(T0);
    let recipient = author(T0);
    let u = unsigned(&recipient, vec![outgoing(&a, &recipient.id, "m-1")]);
    let d = sign_delivery(dl.device.signing_key_pair(), &dl.delegation, u).unwrap();
    let mut meta = serde_json::Map::new();
    attach(&mut meta, DEFAULT_META_KEY, &d).unwrap();
    let v = serde_json::Value::Object(meta);
    assert_eq!(locate(&v, DEFAULT_META_KEY).unwrap(), Some(d));
    assert_eq!(locate(&v, "other-key").unwrap(), None);
    let s = serde_json::json!({ DEFAULT_META_KEY: "x" });
    assert!(matches!(locate(&s, DEFAULT_META_KEY), Err(AttestationError::NotObject)));
}

#[test]
fn sign_message_with_none_delegation_is_not_carried_verifiable() {
    // identity-crypto's carried-message verifier requires `self_rooted.device`, so a
    // None-delegation message (root key as its own device) is not carried-verifiable:
    // pin that it signs, carries no device delegation, and names the root as genesis.
    let a = author_self_rooted(T0);
    let recipient = author(T0);
    let m = message("m-1", vec![person(&recipient.id)]);
    let aud = recipient.id.to_string();
    let signed = sign_message(&a.session, None, &aud, T0, &m).unwrap();
    let Some(identity_crypto::pb::signer_chain::Chain::SelfRooted(s)) =
        signed.signer.as_ref().and_then(|s| s.chain.clone())
    else {
        panic!("not self-rooted")
    };
    assert!(s.device.is_none());
    let genesis = s.session.unwrap().principal_genesis.unwrap();
    assert_eq!(
        identity_crypto::PrincipalId::from_genesis(identity_crypto::PublicKey::try_from(&genesis).unwrap()),
        a.id
    );
    assert!(identity_crypto::verify_carried_message(&signed, &aud).is_err());
}

#[test]
fn sign_message_with_some_delegation_verifies_delegated() {
    let a = author(T0);
    let recipient = author(T0);
    let m = message("m-1", vec![person(&recipient.id)]);
    let aud = recipient.id.to_string();
    let signed = sign_message(&a.session, Some(a.delegation.clone()), &aud, T0, &m).unwrap();
    let v = identity_crypto::verify_carried_message(&signed, &aud).unwrap();
    assert_eq!(v.author(), &a.id);
}

#[test]
fn string_audience_mismatch_is_wrong_audience() {
    let f = fx();
    let a = author(T0);
    let m = message("m-1", vec![room("r"), person(&f.recipient.id)]);
    let s = sign_message(&a.session, Some(a.delegation.clone()), "p256:aaa", T0, &m).unwrap();
    let d = with_signed(&f, s, vec![room("r")]);
    let r = message_attestation::verify_delivery(&d, &policy(&f), &message_attestation::MemoryReplayStore::default());
    assert!(matches!(r, Err(AttestationError::WrongAudience { index: 0 })), "{r:?}");
}

#[test]
fn invalid_message_is_refused_before_signing() {
    let a = author(T0);
    let m = message("m-1", vec![]);
    let e = sign_message(&a.session, None, "p256:aaa", T0, &m).unwrap_err();
    assert!(matches!(e, AttestationError::InvalidMessage { field: "to", .. }), "{e:?}");
}

#[test]
fn hosted_signature_takes_a_string_audience() {
    let h = hosted_author(T0);
    let d = author(T0);
    let m = message("h-1", vec![room("r")]);
    let aud = d.id.to_string();
    let s = message_attestation::sign_hosted_message(&h.session, &aud, T0, &m).unwrap();
    let v = identity_crypto::verify_carried_message(&s, &aud).unwrap();
    assert_eq!(v.author(), &h.id);
}
