mod common;

use common::*;
use identity_crypto::pb;
use message_attestation::{
    compose_reply, is_valid_id, new_message_id, parse_tool_input, send_message_tool,
    verify_delivery, AttestationError, MemoryReplayStore, ReplyDraft, ReplySigner,
    MAX_BODY_BYTES, SEND_MESSAGE_TOOL,
};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;

const DESCRIPTION: &str = "Send a message as yourself. `to` lists rooms (`room:<id>`) and agents or people (`p256:<hex>`), at most 64. To reply, pass the message's id as `reply_to` and usually the same `to` list. `mentions` are `p256:` ids you want to notify. Returns the new message's id.";

fn field_of(r: Result<ReplyDraft, AttestationError>) -> (&'static str, &'static str) {
    match r.unwrap_err() {
        AttestationError::InvalidMessage { field, reason } => (field, reason),
        e => panic!("{e:?}"),
    }
}

fn pid() -> String {
    author(T0).id.to_string()
}

#[test]
fn tool_definition_matches() {
    let t = send_message_tool();
    assert_eq!(SEND_MESSAGE_TOOL, "send_message");
    assert_eq!(t.name, "send_message");
    assert_eq!(t.description, DESCRIPTION);
    let s = &t.input_schema;
    assert_eq!(s["type"], "object");
    assert_eq!(s["required"], json!(["to", "body"]));
    assert_eq!(s["additionalProperties"], json!(false));
    assert_eq!(s["properties"]["to"]["type"], "array");
    assert_eq!(s["properties"]["to"]["items"]["type"], "string");
    assert_eq!(s["properties"]["to"]["minItems"], 1);
    assert_eq!(s["properties"]["to"]["maxItems"], 64);
    assert_eq!(s["properties"]["body"]["type"], "string");
    assert_eq!(s["properties"]["body"]["minLength"], 1);
    assert_eq!(s["properties"]["body"]["maxLength"], 65536);
    assert_eq!(s["properties"]["reply_to"]["type"], "string");
    for k in ["references", "mentions"] {
        assert_eq!(s["properties"][k]["type"], "array");
        assert_eq!(s["properties"][k]["items"]["type"], "string");
    }
    assert_eq!(s["properties"].as_object().unwrap().len(), 5);
}

#[test]
fn parses_rooms_people_reply_and_mentions() {
    let p = pid();
    let d = parse_tool_input(&json!({
        "to": ["room:r1", p],
        "body": "hi",
        "reply_to": "m-1",
        "references": ["m-0"],
        "mentions": [p],
    }))
    .unwrap();
    assert_eq!(d.to, vec![room("r1"), pb::Target { target: Some(pb::target::Target::RecipientId(p.clone())) }]);
    assert_eq!(d.body, "hi");
    assert_eq!(d.reply_to.as_deref(), Some("m-1"));
    assert_eq!(d.references, vec!["m-0".to_string()]);
    assert_eq!(d.mentions, vec![p]);
}

#[test]
fn null_optional_fields_are_absent() {
    let d = parse_tool_input(&json!({
        "to": ["room:r1"], "body": "hi", "reply_to": null, "references": null, "mentions": null
    }))
    .unwrap();
    assert_eq!(d.reply_to, None);
    assert!(d.references.is_empty());
    assert!(d.mentions.is_empty());
}

#[test]
fn unknown_field_is_refused() {
    for k in ["message_id", "audience", "To"] {
        let mut v = json!({"to": ["room:r1"], "body": "hi"});
        v[k] = json!("x");
        assert_eq!(field_of(parse_tool_input(&v)).0, "input", "{k}");
    }
    assert_eq!(field_of(parse_tool_input(&json!("hi"))).0, "input");
    assert_eq!(field_of(parse_tool_input(&json!([]))).0, "input");
}

#[test]
fn target_without_prefix_is_refused() {
    for t in ["abc", "you"] {
        assert_eq!(field_of(parse_tool_input(&json!({"to": [t], "body": "hi"}))).0, "to", "{t}");
    }
}

#[test]
fn empty_body_is_refused() {
    let r = parse_tool_input(&json!({"to": ["room:r1"], "body": ""}));
    assert_eq!(field_of(r), ("body", "empty"));
}

#[test]
fn missing_to_is_refused() {
    assert_eq!(field_of(parse_tool_input(&json!({"body": "hi"}))).0, "to");
    assert_eq!(field_of(parse_tool_input(&json!({"to": [], "body": "hi"}))).0, "to");
}

#[test]
fn wrong_type_is_refused() {
    let cases: [(&str, Value); 5] = [
        ("to", json!({"to": "room:r1", "body": "hi"})),
        ("body", json!({"to": ["room:r1"], "body": 5})),
        ("reply_to", json!({"to": ["room:r1"], "body": "hi", "reply_to": 3})),
        ("references", json!({"to": ["room:r1"], "body": "hi", "references": "m"})),
        ("mentions", json!({"to": ["room:r1"], "body": "hi", "mentions": [1]})),
    ];
    for (f, v) in cases {
        assert_eq!(field_of(parse_tool_input(&v)).0, f);
    }
    assert_eq!(field_of(parse_tool_input(&json!({"to": [5], "body": "hi"}))).0, "to");
}

#[test]
fn oversized_body_is_refused() {
    assert_eq!(MAX_BODY_BYTES, 65536);
    let a = author(T0);
    let signer = ReplySigner::Keyed { session: Arc::new(a.session), device_delegation: a.delegation };
    let d = deliverer(T0);
    let draft = |n: usize| ReplyDraft {
        to: vec![room("r")],
        body: "a".repeat(n),
        reply_to: None,
        references: vec![],
        mentions: vec![],
    };
    let e = compose_reply(&signer, &d.id, T0, draft(65537)).unwrap_err();
    assert!(matches!(e, AttestationError::InvalidMessage { field: "body", reason: "too long" }), "{e:?}");
    compose_reply(&signer, &d.id, T0, draft(65536)).unwrap();
    let r = parse_tool_input(&json!({"to": ["room:r1"], "body": "a".repeat(65537)}));
    assert_eq!(field_of(r), ("body", "too long"));
}

fn draft_for(f: &Fx) -> ReplyDraft {
    ReplyDraft {
        to: vec![room("r"), person(&f.recipient.id)],
        body: "hi".into(),
        reply_to: None,
        references: vec![],
        mentions: vec![],
    }
}

fn verified_one(f: &Fx, c: &message_attestation::ComposedReply) -> message_attestation::VerifiedMessage {
    let d = with_signed(f, c.signed.clone(), vec![room("r")]);
    let v = verify_delivery(&d, &policy(f), &MemoryReplayStore::default()).unwrap();
    assert_eq!(v.delivery.messages().len(), 1);
    v.delivery.messages()[0].clone()
}

#[test]
fn compose_keyed_signs_a_message_that_verifies() {
    let f = fx();
    let a = author(T0);
    let id = a.id.clone();
    let signer = ReplySigner::Keyed { session: Arc::new(a.session), device_delegation: a.delegation };
    let c = compose_reply(&signer, &f.dl.id, T0, draft_for(&f)).unwrap();
    let m = verified_one(&f, &c);
    assert_eq!(m.author(), &id);
    assert_eq!(m.message().body, "hi");
    assert_eq!(m.message().message_id, c.message_id);
    assert_eq!(m.message().authored_at.as_ref().unwrap().seconds, T0);
}

#[test]
fn compose_hosted_signs_a_message_that_verifies() {
    let f = fx();
    let h = hosted_author(T0);
    let id = h.id.clone();
    let signer = ReplySigner::Hosted { session: Arc::new(h.session) };
    let c = compose_reply(&signer, &f.dl.id, T0, draft_for(&f)).unwrap();
    let m = verified_one(&f, &c);
    assert_eq!(m.author(), &id);
    assert_eq!(m.message().body, "hi");
    assert_eq!(m.message().message_id, c.message_id);
}

fn expired(r: Result<message_attestation::ComposedReply, AttestationError>, not_after: i64, now: i64) {
    match r.unwrap_err() {
        AttestationError::SessionExpired { not_after: na, now: n } => assert_eq!((na, n), (not_after, now)),
        e => panic!("{e:?}"),
    }
}

#[test]
fn expired_session_is_refused_keyed() {
    let f = fx();
    let a = author(T0);
    let signer = ReplySigner::Keyed { session: Arc::new(a.session), device_delegation: a.delegation };
    let now = T0 + 3601;
    expired(compose_reply(&signer, &f.dl.id, now, draft_for(&f)), T0 + 3600, now);
    compose_reply(&signer, &f.dl.id, T0 + 3600, draft_for(&f)).unwrap();
    let before = T0 - 1;
    assert!(matches!(
        compose_reply(&signer, &f.dl.id, before, draft_for(&f)),
        Err(AttestationError::SessionExpired { .. })
    ));
}

#[test]
fn expired_session_is_refused_hosted() {
    let f = fx();
    let h = hosted_author(T0);
    let signer = ReplySigner::Hosted { session: Arc::new(h.session) };
    let now = T0 + 3601;
    expired(compose_reply(&signer, &f.dl.id, now, draft_for(&f)), T0 + 3600, now);
    compose_reply(&signer, &f.dl.id, T0 + 3600, draft_for(&f)).unwrap();
    assert!(matches!(
        compose_reply(&signer, &f.dl.id, T0 - 1, draft_for(&f)),
        Err(AttestationError::SessionExpired { .. })
    ));
}

#[test]
fn expired_delegation_is_refused_keyed() {
    let f = fx();
    let a = author_with(T0, 600, 3600);
    let signer = ReplySigner::Keyed { session: Arc::new(a.session), device_delegation: a.delegation };
    compose_reply(&signer, &f.dl.id, T0 + 600, draft_for(&f)).unwrap();
    let now = T0 + 601;
    expired(compose_reply(&signer, &f.dl.id, now, draft_for(&f)), T0 + 600, now);
}

#[test]
fn compose_refuses_hostile_reply_to_and_65_targets() {
    let f = fx();
    let a = author(T0);
    let signer = ReplySigner::Keyed { session: Arc::new(a.session), device_delegation: a.delegation };
    let mut d = draft_for(&f);
    d.reply_to = Some("x\" y".into());
    let e = compose_reply(&signer, &f.dl.id, T0, d).unwrap_err();
    assert!(matches!(e, AttestationError::InvalidMessage { field: "reply_to", .. }), "{e:?}");
    let mut d = draft_for(&f);
    d.to = (0..65).map(|i| room(&format!("r{i}"))).collect();
    let e = compose_reply(&signer, &f.dl.id, T0, d).unwrap_err();
    assert!(matches!(e, AttestationError::InvalidMessage { field: "to", .. }), "{e:?}");
}

#[test]
fn message_ids_are_fresh_and_well_formed() {
    let ids: Vec<String> = (0..1000).map(|_| new_message_id()).collect();
    let set: HashSet<&String> = ids.iter().collect();
    assert_eq!(set.len(), 1000);
    for id in &ids {
        assert_eq!(id.len(), 34, "{id}");
        assert!(id.starts_with("m-"), "{id}");
        assert!(id[2..].bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')), "{id}");
        assert!(is_valid_id(id), "{id}");
    }
}
