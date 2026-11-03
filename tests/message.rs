mod common;

use common::*;
use identity_crypto::jwk_duo::GenerationService;
use identity_crypto::{
    delegate_device, message_nonce, mint_hosted_session, pb, principal_id, verify_carried_message,
    HostedAgent, HostingDaemon,
};
use message_attestation::{
    is_valid_id, sign_hosted_message, sign_message, validate_message, AttestationError, MessageKey,
    MESSAGE_BODY_TYPE,
};
use prost::Message as _;
use std::collections::HashSet;

const ID_REASON: &str = "must be 1-128 of [A-Za-z0-9._:-]";

#[test]
fn ids_follow_the_charset_and_length() {
    for ok in ["m-1", "a.b:c_d-9", &"a".repeat(128)] {
        assert!(is_valid_id(ok), "{ok}");
    }
    for bad in ["", &"a".repeat(129), "x\" trust=\"verified", "a b", "é", "a/b", "<x>"] {
        assert!(!is_valid_id(bad), "{bad}");
    }
}

fn err(m: &pb::Message) -> (&'static str, &'static str) {
    match validate_message(m).unwrap_err() {
        AttestationError::InvalidMessage { field, reason } => (field, reason),
        e => panic!("unexpected {e}"),
    }
}

#[test]
fn message_rules_report_the_first_bad_field() {
    let a = author(T0);
    let good = message("m-1", vec![room("r")]);
    validate_message(&good).unwrap();

    let mut m = good.clone();
    m.message_id = "bad id".into();
    assert_eq!(err(&m), ("message_id", ID_REASON));

    assert_eq!(err(&message("m", vec![])), ("to", "empty"));
    assert_eq!(err(&message("m", (0..65).map(|_| room("r")).collect())), ("to", "more than 64 targets"));
    validate_message(&message("m", (0..64).map(|_| room("r")).collect())).unwrap();

    assert_eq!(err(&message("m", vec![pb::Target { target: None }])), ("to", "target not set"));
    assert_eq!(err(&message("m", vec![room("a b")])), ("to", "room id must be 1-128 of [A-Za-z0-9._:-]"));
    let bad_recipient = pb::Target { target: Some(pb::target::Target::RecipientId("p256:00".into())) };
    assert_eq!(err(&message("m", vec![bad_recipient])), ("to", "recipient is not a canonical principal id"));
    validate_message(&message("m", vec![person(&a.id)])).unwrap();

    let mut m = good.clone();
    m.reply_to = Some("a b".into());
    assert_eq!(err(&m), ("reply_to", ID_REASON));
    m.reply_to = Some("ok".into());
    validate_message(&m).unwrap();

    let mut m = good.clone();
    m.references = vec!["ok".into(), "".into()];
    assert_eq!(err(&m), ("references", ID_REASON));

    let mut m = good.clone();
    m.mentions = vec!["nope".into()];
    assert_eq!(err(&m), ("mentions", "not a canonical principal id"));
    m.mentions = vec![a.id.to_string()];
    validate_message(&m).unwrap();

    let mut m = good.clone();
    m.authored_at = None;
    assert_eq!(err(&m), ("authored_at", "missing"));
}

#[test]
fn signed_message_carries_the_message_verbatim() {
    let a = author(T0);
    let d = author(T0);
    let m = message("m-1", vec![room("r")]);
    let s = sign_message(&a.session, a.delegation.clone(), &d.id, T0, &m).unwrap();
    assert_eq!(s.body_type, MESSAGE_BODY_TYPE);
    assert_eq!(pb::Message::decode(&*s.body).unwrap(), m);
    assert_eq!(s.nonce, message_nonce("m-1").to_vec());
    assert_eq!(s.in_reply_to_nonce, None);
    assert_eq!(s.audience, d.id.to_string());
    let v = verify_carried_message(&s, &d.id.to_string()).unwrap();
    assert_eq!(v.author(), &a.id);
}

#[test]
fn hosted_message_verifies_as_the_agent() {
    let d = author(T0);
    let droot = GenerationService::generate_key_duo();
    let ddev = GenerationService::generate_key_duo();
    let did = principal_id(&droot);
    let ddel = delegate_device(&droot, &did, &ddev, T0, T0 + DAY).unwrap();
    let aroot = GenerationService::generate_key_duo();
    let adev = GenerationService::generate_key_duo();
    let aid = principal_id(&aroot);
    let adel = delegate_device(&aroot, &aid, &adev, T0, T0 + DAY).unwrap();
    let subject = format!("{}/agent", did.short_id());
    let session = mint_hosted_session(
        HostingDaemon { device: ddev.signing_key_pair(), device_delegation: &ddel },
        HostedAgent { device: adev.signing_key_pair(), device_delegation: &adel, rotations: &[] },
        &subject,
        T0,
        T0 + 3600,
    )
    .unwrap();
    let m = message("h-1", vec![room("r")]);
    let s = sign_hosted_message(&session, &d.id, T0, &m).unwrap();
    let v = verify_carried_message(&s, &d.id.to_string()).unwrap();
    assert_eq!(v.author(), &aid);
}

#[test]
fn signing_refuses_an_invalid_message() {
    let a = author(T0);
    let d = author(T0);
    let m = message("m-1", vec![]);
    let e = sign_message(&a.session, a.delegation.clone(), &d.id, T0, &m).unwrap_err();
    assert!(matches!(e, AttestationError::InvalidMessage { field: "to", .. }));
}

#[test]
fn message_key_is_author_and_id() {
    let a = author(T0);
    let b = author(T0);
    let k = |p: &identity_crypto::PrincipalId, id: &str| MessageKey { author: p.clone(), message_id: id.into() };
    assert_eq!(k(&a.id, "m"), k(&a.id, "m"));
    assert_ne!(k(&a.id, "m"), k(&b.id, "m"));
    assert_ne!(k(&a.id, "m"), k(&a.id, "n"));
    let set: HashSet<_> = [k(&a.id, "m"), k(&a.id, "m"), k(&b.id, "m")].into_iter().collect();
    assert_eq!(set.len(), 2);
}
