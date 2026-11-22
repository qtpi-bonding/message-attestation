mod common;

use coded_error::{CodedError, ErrorClass, GrpcCode};
use common::*;
use identity_crypto::pb;
use message_attestation::{
    parse_target, parse_targets, validate_target, AttestationError, MAX_TARGETS,
};

fn invalid_text(r: Result<pb::Target, AttestationError>) -> String {
    match r.unwrap_err() {
        AttestationError::TargetInvalid(msg) => msg,
        e => panic!("{e:?}"),
    }
}

fn invalid_list_text(r: Result<Vec<pb::Target>, AttestationError>) -> String {
    match r.unwrap_err() {
        AttestationError::TargetInvalid(msg) => msg,
        e => panic!("{e:?}"),
    }
}

#[test]
fn parse_target_accepts_room_and_person_forms() {
    assert_eq!(
        parse_target("room:room-a").unwrap(),
        pb::Target {
            target: Some(pb::target::Target::RoomId("room-a".to_string())),
        }
    );
    let text = format!("p256:{}", "a".repeat(130));
    assert_eq!(
        parse_target(&text).unwrap(),
        pb::Target {
            target: Some(pb::target::Target::RecipientId(text.clone())),
        }
    );
}

#[test]
fn parse_target_rejects_a_bare_word_and_names_both_forms() {
    let msg = invalid_text(parse_target("room-a"));
    assert!(msg.contains("room:<id>"), "{msg}");
    assert!(msg.contains("p256:"), "{msg}");
    assert_eq!(
        msg,
        "target \"room-a\" is neither `room:<id>` nor a `p256:<130 hex>` principal id"
    );
}

#[test]
fn parse_targets_accepts_a_good_list_in_order() {
    let id = author(T0).id;
    let texts = vec!["room:a".to_string(), id.to_string()];
    assert_eq!(parse_targets(&texts).unwrap(), vec![room("a"), person(&id)]);
}

#[test]
fn parse_targets_refuses_an_empty_list() {
    let msg = invalid_list_text(parse_targets(&[]));
    assert_eq!(msg, "at least one target is required");
}

#[test]
fn parse_targets_refuses_65_targets_but_accepts_64() {
    assert_eq!(MAX_TARGETS, 64);
    let texts: Vec<String> = (0..65).map(|i| format!("room:r{i}")).collect();
    assert_eq!(
        invalid_list_text(parse_targets(&texts)),
        "more than 64 targets"
    );
    let ok: Vec<String> = (0..64).map(|i| format!("room:r{i}")).collect();
    assert_eq!(parse_targets(&ok).unwrap().len(), 64);
}

#[test]
fn parse_targets_refuses_a_duplicate() {
    let texts = vec!["room:a".to_string(), "room:a".to_string()];
    assert_eq!(
        invalid_list_text(parse_targets(&texts)),
        "target \"room:a\" appears twice"
    );
}

#[test]
fn parse_targets_names_the_text_of_a_malformed_person_id() {
    let texts = vec!["p256:abc".to_string()];
    let msg = invalid_list_text(parse_targets(&texts));
    assert!(msg.starts_with("target \"p256:abc\": "), "{msg}");
    let inner = match validate_target(&pb::Target {
        target: Some(pb::target::Target::RecipientId("p256:abc".to_string())),
    })
    .unwrap_err()
    {
        AttestationError::InvalidMessage { reason, .. } => reason,
        e => panic!("{e:?}"),
    };
    assert!(msg.contains(inner), "{msg}");
}

#[test]
fn target_invalid_is_a_coded_logical_invalid_argument() {
    let e = AttestationError::TargetInvalid("x".into());
    assert_eq!(e.code(), "message.attestation.target_invalid");
    assert_eq!(e.class(), ErrorClass::Logical);
    assert_eq!(e.overrides().grpc, Some(GrpcCode::InvalidArgument));
    assert_eq!(e.to_string(), "x");
}
