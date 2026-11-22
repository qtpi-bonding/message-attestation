//! End-to-end `sign_message` behaviour through the shared server.

mod common;

use common::*;
use identity_crypto::pb;
use prost::Message as _;
use std::sync::Arc;

const BODY_MARK: &str = "body-secret-marker-9c1d";

fn message_config(deliverer: &str) -> message_attestation_signer::MessageConfig {
    toml::from_str(&format!("deliverer = {deliverer:?}\n")).expect("message config")
}

fn server(
    dir: &std::path::Path,
    deliverer: &str,
    now: i64,
) -> (
    identity_request_signer::Server,
    message_attestation_signer::MessageOp,
    Arc<LogSink>,
    Arc<TestClock>,
) {
    let clock = TestClock::new(now);
    let op =
        message_attestation_signer::MessageOp::new(dir, &message_config(deliverer), clock.clone())
            .expect("build MessageOp");
    let log = LogSink::new();
    let socket = dir.join("test.sock");
    let config = identity_request_signer::Config::parse(&format!(
        "{}server_id = {SERVER:?}\n",
        config_text(dir, &socket)
    ))
    .expect("config");
    let mut server =
        identity_request_signer::Server::new(config, clock.clone(), log.sink()).expect("server");
    server
        .register_op(Box::new(op.clone()))
        .expect("register op");
    (server, op, log, clock)
}

fn sign_request(to: &[&str], body: &str) -> String {
    let to_json: Vec<String> = to.iter().map(|t| format!("{t:?}")).collect();
    format!(
        "{{\"op\":\"sign_message\",\"to\":[{}],\"body\":{body:?},\"reply_to\":null,\"references\":[],\"mentions\":[]}}",
        to_json.join(",")
    )
}

fn exchange(server: &identity_request_signer::Server, request: &str) -> serde_json::Value {
    let line = server.handle_line(request.as_bytes());
    serde_json::from_str(&line).expect("the reply is JSON")
}

fn sign_one(
    server: &identity_request_signer::Server,
    to: &[&str],
    body: &str,
) -> (pb::SignedMessage, serde_json::Value) {
    let reply = exchange(server, &sign_request(to, body));
    assert_eq!(reply["ok"], true, "reply: {reply}");
    let signed_bytes = decode_b64(reply["signed_b64"].as_str().expect("signed_b64"));
    let signed = pb::SignedMessage::decode(signed_bytes.as_slice()).expect("decode SignedMessage");
    (signed, reply)
}

#[test]
fn round_trip_signs_a_verifiable_message() {
    let dir = DeviceOnlyDir::new(T0, 91 * 86400);
    let deliverer = principal_string(dir.path());
    let (server, _op, _log, _clock) = server(dir.path(), &deliverer, T0);
    let (signed, reply) = sign_one(&server, &[ROOM, &deliverer], "hello there");

    let carried = identity_crypto::verify_carried_message(&signed, &deliverer)
        .expect("the signed message verifies against the deliverer");
    assert_eq!(
        carried.author().to_string(),
        principal_string(dir.path()),
        "the author is the device principal"
    );
    assert_eq!(carried.body_type(), message_attestation::MESSAGE_BODY_TYPE);
    assert_eq!(carried.issued_at(), T0);
    let message = pb::Message::decode(carried.body()).expect("decode the payload Message");
    assert_eq!(message.body, "hello there");
    assert_eq!(message.to.len(), 2);
    let mid = message.message_id.clone();
    assert!(mid.starts_with("m-"), "{mid}");
    assert_eq!(
        message.authored_at,
        Some(identity_crypto::Timestamp {
            seconds: T0,
            nanos: 0,
        })
    );
    assert!(reply["message_id"].is_string());
    assert_eq!(reply["message_id"], message.message_id);
}

#[test]
fn the_signed_bytes_match_the_existing_client_signing_path() {
    let dir = DeviceOnlyDir::new(T0, 91 * 86400);
    let deliverer = principal_string(dir.path());
    let (server, _op, _log, _clock) = server(dir.path(), &deliverer, T0);
    let (signed, _reply) = sign_one(&server, &[ROOM], "same body");

    let carried = identity_crypto::verify_carried_message(&signed, &deliverer).expect("verify");
    let op_message = pb::Message::decode(carried.body()).expect("decode the op's payload Message");

    // The same message, signed the way the existing client path does: a
    // session minted from the device keys with a one-hour span, the
    // delegation from the key file, `sign_message`.
    let keys = identity_keyfile::DeviceKeys::load(dir.path()).expect("device keys");
    let session = identity_crypto::mint_session(
        &keys.device,
        &keys.principal_id.genesis().clone(),
        T0,
        T0 + 3600,
    )
    .expect("mint session");
    let mut client_message = op_message.clone();
    client_message.message_id = format!("m-{}", "0".repeat(32));
    let client_signed = message_attestation::sign_message(
        &session,
        keys.delegation.clone(),
        &deliverer,
        T0,
        &client_message,
    )
    .expect("client-path sign");
    let client_carried = identity_crypto::verify_carried_message(&client_signed, &deliverer)
        .expect("verify the client-path message");

    assert_eq!(carried.body_type(), client_carried.body_type());
    assert_eq!(carried.issued_at(), client_carried.issued_at());
    assert_eq!(carried.nonce().len(), client_carried.nonce().len());
    assert_eq!(carried.body(), client_carried.body(), "payload bytes");
    // The chain shape is the same self-rooted device chain; the signatures
    // differ because the sessions differ.
    assert_eq!(
        std::mem::discriminant(
            signed
                .signer
                .as_ref()
                .expect("signer")
                .chain
                .as_ref()
                .expect("chain")
        ),
        std::mem::discriminant(
            client_signed
                .signer
                .as_ref()
                .expect("signer")
                .chain
                .as_ref()
                .expect("chain")
        )
    );
    assert_ne!(signed.signature, client_signed.signature);
}

fn refusal_code(reply: &serde_json::Value) -> String {
    assert_eq!(reply["ok"], false, "expected a refusal: {reply}");
    reply["code"].as_str().expect("code").to_string()
}

#[test]
fn refusals_are_coded_and_never_echo_the_body() {
    let dir = DeviceOnlyDir::new(T0, 91 * 86400);
    let deliverer = principal_string(dir.path());
    let (server, _op, log, _clock) = server(dir.path(), &deliverer, T0);

    let cases: Vec<(String, &str)> = vec![
        // empty to
        (
            format!("{{\"op\":\"sign_message\",\"to\":[],\"body\":{BODY_MARK:?}}}"),
            "identity.request_signer.bad_request",
        ),
        // empty body
        (
            sign_request(&[ROOM], ""),
            "identity.request_signer.bad_request",
        ),
        // unparseable target
        (
            sign_request(&["bogus-target"], BODY_MARK),
            "identity.request_signer.bad_request",
        ),
        // bad reply_to
        (
            "{\"op\":\"sign_message\",\"to\":[\"room:r1\"],\"body\":\"x\",\"reply_to\":\"bad id!\",\"references\":[],\"mentions\":[]}".to_string(),
            "identity.request_signer.bad_request",
        ),
        // bad reference id
        (
            "{\"op\":\"sign_message\",\"to\":[\"room:r1\"],\"body\":\"x\",\"reply_to\":null,\"references\":[\"also bad!\"],\"mentions\":[]}".to_string(),
            "identity.request_signer.bad_request",
        ),
        // non-canonical mention
        (
            "{\"op\":\"sign_message\",\"to\":[\"room:r1\"],\"body\":\"x\",\"reply_to\":null,\"references\":[],\"mentions\":[\"not-a-principal\"]}".to_string(),
            "identity.request_signer.bad_request",
        ),
        // caller-set audience / message_id / authored_at are unknown fields
        (
            "{\"op\":\"sign_message\",\"to\":[\"room:r1\"],\"body\":\"x\",\"audience\":\"someone\",\"message_id\":\"m-1\",\"authored_at\":{\"seconds\":1,\"nanos\":0}}".to_string(),
            "identity.request_signer.bad_request",
        ),
    ];
    for (request, expected_code) in &cases {
        let reply = exchange(&server, request);
        assert_eq!(&refusal_code(&reply), expected_code, "reply: {reply}");
        assert!(
            !reply.to_string().contains(BODY_MARK),
            "the body leaked into the reply: {reply}"
        );
        assert!(!log.contains(BODY_MARK), "the body leaked into the log");
    }
}

#[test]
fn oversize_body_is_refused() {
    let dir = DeviceOnlyDir::new(T0, 91 * 86400);
    let deliverer = principal_string(dir.path());
    let (server, _op, log, _clock) = server(dir.path(), &deliverer, T0);
    let body = "x".repeat(message_attestation::MAX_BODY_BYTES + 1);
    let reply = exchange(&server, &sign_request(&[ROOM], &body));
    assert_eq!(
        refusal_code(&reply),
        "identity.request_signer.bad_request",
        "reply: {reply}"
    );
    assert!(!log.contains(&body[..32]), "the body leaked into the log");
}

#[test]
fn too_many_targets_is_refused() {
    let dir = DeviceOnlyDir::new(T0, 91 * 86400);
    let deliverer = principal_string(dir.path());
    let message = toml::from_str::<message_attestation_signer::MessageConfig>(&format!(
        "deliverer = {deliverer:?}\nmax_targets = 2\n"
    ))
    .expect("message config");
    let clock = TestClock::new(T0);
    let op = message_attestation_signer::MessageOp::new(dir.path(), &message, clock.clone())
        .expect("build MessageOp");
    let log = LogSink::new();
    let config = identity_request_signer::Config::parse(&format!(
        "{}server_id = {SERVER:?}\n",
        config_text(dir.path(), &dir.path().join("t.sock"))
    ))
    .expect("config");
    let mut server =
        identity_request_signer::Server::new(config, clock.clone(), log.sink()).expect("server");
    server
        .register_op(Box::new(op.clone()))
        .expect("register op");
    let reply = exchange(&server, &sign_request(&["room:a", "room:b", "room:c"], "x"));
    assert_eq!(
        refusal_code(&reply),
        "identity.request_signer.bad_request",
        "reply: {reply}"
    );
}

#[test]
fn duplicate_targets_are_refused() {
    let dir = DeviceOnlyDir::new(T0, 91 * 86400);
    let deliverer = principal_string(dir.path());
    let (server, _op, _log, _clock) = server(dir.path(), &deliverer, T0);
    let reply = exchange(&server, &sign_request(&[ROOM, ROOM], "x"));
    assert_eq!(
        refusal_code(&reply),
        "identity.request_signer.bad_request",
        "reply: {reply}"
    );
}

#[test]
fn an_expired_delegation_refuses_signing() {
    // A delegation that already ran out at T0+100; sign at T0+200.
    let dir = DeviceOnlyDir::new(T0, 100);
    let deliverer = principal_string(dir.path());
    let (server, _op, _log, _clock) = server(dir.path(), &deliverer, T0 + 200);
    let reply = exchange(&server, &sign_request(&[ROOM], "x"));
    assert_eq!(
        refusal_code(&reply),
        "identity.request_signer.delegation_expired",
        "reply: {reply}"
    );
}

#[test]
fn the_session_is_reminted_at_sixty_percent() {
    let dir = DeviceOnlyDir::new(T0, 91 * 86400);
    let deliverer = principal_string(dir.path());
    let (server, op, _log, clock) = server(dir.path(), &deliverer, T0);
    let _ = sign_one(&server, &[ROOM], "one");
    let _ = sign_one(&server, &[ROOM], "two");
    assert_eq!(op.mint_count(), 1, "two signs inside the window mint once");

    clock.advance(2000);
    let _ = sign_one(&server, &[ROOM], "three");
    assert_eq!(op.mint_count(), 1, "T0+2000 is still under 60%");

    clock.advance(200);
    let _ = sign_one(&server, &[ROOM], "four");
    assert_eq!(op.mint_count(), 2, "T0+2200 is past 60%: re-minted");
}

#[test]
fn plain_info_still_works_through_the_same_server() {
    let dir = DeviceOnlyDir::new(T0, 91 * 86400);
    let deliverer = principal_string(dir.path());
    let (server, _op, _log, _clock) = server(dir.path(), &deliverer, T0);
    let reply = exchange(&server, "{\"op\":\"info\"}");
    assert_eq!(reply["ok"], true, "info reply: {reply}");
    assert_eq!(reply["principal"], deliverer);
}

#[test]
fn sign_request_registered_next_to_it_still_works() {
    let dir = DeviceOnlyDir::new(T0, 91 * 86400);
    let deliverer = principal_string(dir.path());
    let (server, _op, _log, _clock) = server(dir.path(), &deliverer, T0);
    let reply = exchange(
        &server,
        &format!(
            "{{\"op\":\"sign_request\",\"method_path\":{PATH:?},\"body_type\":{BODY_TYPE:?},\"body_b64\":{:?},\"audience\":{SERVER:?}}}",
            encode_b64(BODY)
        ),
    );
    assert_eq!(reply["ok"], true, "sign_request reply: {reply}");
    assert!(reply["header_b64"].is_string());
}
