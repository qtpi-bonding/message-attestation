//! Pins every `AttestationError` code string, class and gRPC code (the wire table).

use coded_error::{fingerprint, CodedError, ErrorClass, GrpcCode};
use identity_crypto::SignerError;
use message_attestation::AttestationError;
use std::collections::HashSet;
use std::error::Error;

fn src() -> Box<dyn Error + Send + Sync> {
    "x".into()
}

fn all() -> Vec<(&'static str, AttestationError)> {
    use AttestationError as E;
    vec![
        (
            "Replay",
            E::Replay {
                principal: "p".into(),
                last: 5,
                got: 3,
            },
        ),
        ("Store", E::Store(src())),
        (
            "InvalidMessage",
            E::InvalidMessage {
                field: "f",
                reason: "r",
            },
        ),
        ("Sign", E::Sign(src())),
        ("NotObject", E::NotObject),
        ("Decode", E::Decode(src())),
        ("Encode", E::Encode(src())),
        ("EmptyMessages", E::EmptyMessages),
        ("NoRecipients", E::NoRecipients),
        ("Transcript", E::Transcript(src())),
        ("InvalidDeliveryId", E::InvalidDeliveryId),
        ("InvalidVia", E::InvalidVia { index: 0 }),
        ("UnknownDeliverer", E::UnknownDeliverer("d".into())),
        ("DelivererDevice", E::DelivererDevice(src())),
        ("WrongRecipient", E::WrongRecipient),
        ("WrongAudience", E::WrongAudience { index: 0 }),
        (
            "MessageSignature",
            E::MessageSignature {
                index: 0,
                reason: "r".into(),
            },
        ),
        ("WrongBodyType", E::WrongBodyType { index: 0 }),
        ("BadSignature", E::BadSignature),
        ("OwnDevicesMissing", E::OwnDevicesMissing),
        ("NotARecipient", E::NotARecipient),
        ("Stale", E::Stale { age: 1, max: 2 }),
        ("UnknownRenderVersion", E::UnknownRenderVersion(9)),
        (
            "SessionExpired",
            E::SessionExpired {
                not_after: 1,
                now: 2,
            },
        ),
        ("Send", E::Send(src())),
        (
            "SendFailed",
            E::SendFailed {
                status: Some(1),
                stderr: "e".into(),
            },
        ),
        ("SendTimeout", E::SendTimeout { secs: 1 }),
        ("InvalidName", E::InvalidName { reason: "r" }),
        (
            "StrayName",
            E::StrayName {
                principal: "p".into(),
            },
        ),
        (
            "TooManyMessages",
            E::TooManyMessages {
                count: 257,
                max: 256,
            },
        ),
        (
            "InvalidRecipientDevice",
            E::InvalidRecipientDevice { index: 0 },
        ),
        ("Randomness", E::Randomness(src())),
    ]
}

use ErrorClass::{Infrastructure as I, Logical as L, Transient as T};
use GrpcCode::{
    AlreadyExists as AE, DeadlineExceeded as DE, FailedPrecondition as FP, InvalidArgument as IA,
    PermissionDenied as PD, Unauthenticated as UA, Unavailable as UN,
};

/// (variant, full code, class, grpc): the former structmux `refusal_code` table.
const TABLE: [(&str, &str, ErrorClass, GrpcCode); 32] = [
    (
        "UnknownDeliverer",
        "message.attestation.unknown_deliverer",
        L,
        UA,
    ),
    (
        "DelivererDevice",
        "message.attestation.deliverer_device",
        L,
        UA,
    ),
    ("BadSignature", "message.attestation.bad_signature", L, UA),
    (
        "MessageSignature",
        "message.attestation.message_signature",
        L,
        UA,
    ),
    (
        "NotARecipient",
        "message.attestation.not_a_recipient",
        L,
        PD,
    ),
    (
        "WrongRecipient",
        "message.attestation.wrong_recipient",
        L,
        PD,
    ),
    ("WrongAudience", "message.attestation.wrong_audience", L, PD),
    ("Replay", "message.attestation.replay", L, AE),
    ("Stale", "message.attestation.stale", L, FP),
    (
        "SessionExpired",
        "message.attestation.session_expired",
        L,
        FP,
    ),
    (
        "InvalidMessage",
        "message.attestation.invalid_message",
        L,
        IA,
    ),
    (
        "InvalidDeliveryId",
        "message.attestation.invalid_delivery_id",
        L,
        IA,
    ),
    ("InvalidVia", "message.attestation.invalid_via", L, IA),
    (
        "WrongBodyType",
        "message.attestation.wrong_body_type",
        L,
        IA,
    ),
    ("Decode", "message.attestation.decode", L, IA),
    ("Transcript", "message.attestation.transcript", L, IA),
    ("NotObject", "message.attestation.not_object", L, IA),
    ("NoRecipients", "message.attestation.no_recipients", L, IA),
    ("EmptyMessages", "message.attestation.empty_messages", L, IA),
    ("InvalidName", "message.attestation.invalid_name", L, IA),
    ("StrayName", "message.attestation.stray_name", L, IA),
    (
        "TooManyMessages",
        "message.attestation.too_many_messages",
        L,
        IA,
    ),
    (
        "InvalidRecipientDevice",
        "message.attestation.invalid_recipient_device",
        L,
        IA,
    ),
    ("Store", "message.attestation.store", I, UN),
    ("Sign", "message.attestation.sign", I, UN),
    ("Encode", "message.attestation.encode", I, UN),
    (
        "OwnDevicesMissing",
        "message.attestation.own_devices_missing",
        I,
        UN,
    ),
    (
        "UnknownRenderVersion",
        "message.attestation.unknown_render_version",
        I,
        UN,
    ),
    ("Send", "message.attestation.send", I, UN),
    ("SendFailed", "message.attestation.send_failed", I, UN),
    ("Randomness", "message.attestation.randomness", I, UN),
    ("SendTimeout", "message.attestation.send_timeout", T, DE),
];

#[test]
fn codes_are_unique_and_in_grammar() {
    let errors = all();
    assert_eq!(errors.len(), 32);
    let codes: HashSet<&str> = errors.iter().map(|(_, e)| e.code()).collect();
    assert_eq!(codes.len(), errors.len());
    for code in codes {
        assert!(coded_error::is_valid_code(code), "{code}");
        assert!(code.starts_with("message.attestation."), "{code}");
    }
}

#[test]
fn class_and_grpc_match_the_wire_table() {
    let errors = all();
    assert_eq!(TABLE.len(), errors.len());
    for (name, code, class, grpc) in TABLE {
        let (_, e) = errors
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("no variant {name}"));
        assert_eq!(e.code(), code, "{name}");
        assert_eq!(e.class(), class, "{name}");
        assert_eq!(e.overrides().grpc, Some(grpc), "{name}");
    }
}

#[test]
fn fingerprints_are_stable() {
    let fp = |code: &str, class| fingerprint(code, class, "message-attestation");
    assert_eq!(
        fp("message.attestation.bad_signature", L),
        "1081abc0a9da89f6"
    );
    assert_eq!(fp("message.attestation.replay", L), "2d2192c95dcc86ac");
    assert_eq!(fp("message.attestation.store", I), "9d16da37f8b9a72e");
}

#[test]
fn replay_keeps_its_fields_and_detail() {
    let e = AttestationError::Replay {
        principal: "alice".into(),
        last: 7,
        got: 3,
    };
    assert_eq!(e.to_string(), "replay for deliverer alice: last 7, got 3");
    assert!(matches!(
        e,
        AttestationError::Replay {
            last: 7,
            got: 3,
            ..
        }
    ));
}

#[test]
fn store_display_holds_no_path() {
    let e = AttestationError::Store("/secret/dir/replay.json: denied".into());
    let text = e.to_string();
    assert_eq!(text, "store failed");
    assert!(!text.contains('/') && !text.contains("secret"));
    assert!(e.source().expect("source").to_string().contains("denied"));
}

#[test]
fn sign_failure_keeps_its_source() {
    let e = AttestationError::Sign(Box::new(SignerError::Cancelled));
    assert!(matches!(
        e.source().unwrap().downcast_ref::<SignerError>(),
        Some(SignerError::Cancelled)
    ));
}

#[test]
fn max_messages_is_exported() {
    assert_eq!(message_attestation::MAX_MESSAGES, 256);
}
