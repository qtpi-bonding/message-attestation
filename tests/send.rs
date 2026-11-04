mod common;

use common::*;
use identity_crypto::{pb, PrincipalId};
use message_attestation::send::{send_bytes, send_via_command, SendCommand, SEND_OUTPUT_CAP};
use message_attestation::{
    run_send_message, AttestationError, ComposedReply, ReplySigner, SendMessageResult,
};
use prost::Message as _;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

fn temp_dir(name: &str) -> PathBuf {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("message-attestation-send-{name}-{}-{id}", std::process::id()));
    fs::create_dir_all(&dir).expect("create test directory");
    dir
}

fn sh(script: &str, args: &[&str], timeout_ms: u64) -> SendCommand {
    let mut argv = vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()];
    argv.extend(args.iter().map(|s| s.to_string()));
    SendCommand { argv, env: vec![("PATH".into(), std::env::var("PATH").unwrap())], timeout: Duration::from_millis(timeout_ms) }
}

struct Setup {
    signer: ReplySigner,
    deliverer: PrincipalId,
}

fn setup() -> Setup {
    let a = author(T0);
    Setup {
        signer: ReplySigner::Keyed { session: Arc::new(a.session), device_delegation: a.delegation },
        deliverer: deliverer(T0).id,
    }
}

fn input(body: &str) -> Value {
    json!({"to": ["room:r1"], "body": body})
}

fn composed(s: &Setup, body: &str) -> ComposedReply {
    let draft = message_attestation::parse_tool_input(&input(body)).unwrap();
    message_attestation::compose_reply(&s.signer, &s.deliverer, T0, draft).unwrap()
}

#[test]
fn command_receives_the_signed_bytes() {
    let s = setup();
    let reply = composed(&s, "hi");
    let dir = temp_dir("bytes");
    let file = dir.join("out.bin");
    let cmd = sh(r#"cat > "$0""#, &[file.to_str().unwrap()], 5000);
    send_via_command(&cmd, &reply).unwrap();
    let got = pb::SignedMessage::decode(fs::read(&file).unwrap().as_slice()).unwrap();
    assert_eq!(got, reply.signed);
    assert_eq!(send_bytes(&reply.signed), fs::read(&file).unwrap());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn stdout_is_returned_and_parsed() {
    let s = setup();
    let cmd = sh(r#"cat >/dev/null; printf '{"ok":1}'"#, &[], 5000);
    let r = run_send_message(&input("hi"), &s.signer, &s.deliverer, T0, &cmd);
    match &r {
        SendMessageResult::Sent { message_id, output } => {
            assert!(message_id.starts_with("m-"));
            assert_eq!(output["ok"], 1);
        }
        other => panic!("{other:?}"),
    }
    let j = r.to_json();
    assert_eq!(j["status"], "sent");
    assert_eq!(j["output"]["ok"], 1);
    assert!(!r.is_error());
}

#[test]
fn nonzero_exit_is_send_failed_with_stderr() {
    let s = setup();
    let cmd = sh("cat >/dev/null; echo nope >&2; exit 3", &[], 5000);
    match send_via_command(&cmd, &composed(&s, "hi")).unwrap_err() {
        AttestationError::SendFailed { status, stderr } => {
            assert_eq!(status, Some(3));
            assert_eq!(stderr, "nope\n");
        }
        e => panic!("{e:?}"),
    }
}

#[test]
fn command_that_ignores_stdin_and_fails() {
    let s = setup();
    let cmd = sh("exit 4", &[], 5000);
    let reply = composed(&s, &"a".repeat(65536));
    match send_via_command(&cmd, &reply).unwrap_err() {
        AttestationError::SendFailed { status, .. } => assert_eq!(status, Some(4)),
        e => panic!("{e:?}"),
    }
}

#[test]
fn hung_command_with_unread_large_stdin_times_out() {
    let s = setup();
    let cmd = sh("exec sleep 30", &[], 300);
    let reply = composed(&s, &"a".repeat(65536));
    let t = Instant::now();
    assert!(matches!(send_via_command(&cmd, &reply).unwrap_err(), AttestationError::SendTimeout { .. }));
    assert!(t.elapsed() < Duration::from_secs(3));
}

#[test]
fn hung_grandchild_holding_pipes_times_out() {
    let s = setup();
    let cmd = sh("sleep 30 & wait", &[], 300);
    let t = Instant::now();
    assert!(matches!(send_via_command(&cmd, &composed(&s, "hi")).unwrap_err(), AttestationError::SendTimeout { .. }));
    assert!(t.elapsed() < Duration::from_secs(3));
}

#[test]
fn output_is_capped() {
    let s = setup();
    let cmd = sh("cat >/dev/null; head -c 1000000 /dev/zero | tr '\\0' a", &[], 5000);
    let out = send_via_command(&cmd, &composed(&s, "hi")).unwrap();
    assert_eq!(out.stdout.len(), SEND_OUTPUT_CAP);
}

#[test]
fn child_env_is_exactly_the_given_pairs() {
    let s = setup();
    let mut cmd = sh("cat >/dev/null; env", &[], 5000);
    cmd.env.push(("X".into(), "1".into()));
    let out = send_via_command(&cmd, &composed(&s, "hi")).unwrap().stdout;
    assert!(out.lines().any(|l| l == "X=1"), "{out}");
    assert!(!out.contains("HOME="), "{out}");
}

#[test]
fn missing_binary_and_empty_argv_are_send_errors() {
    let s = setup();
    let reply = composed(&s, "hi");
    let mut cmd = sh("", &[], 1000);
    cmd.argv = vec!["/nonexistent/definitely-not-here".into()];
    assert!(matches!(send_via_command(&cmd, &reply).unwrap_err(), AttestationError::Send(_)));
    cmd.argv = vec![];
    assert!(matches!(send_via_command(&cmd, &reply).unwrap_err(), AttestationError::Send(_)));
}

#[test]
fn failed_send_keeps_the_id_and_can_be_resent() {
    let s = setup();
    let failing = sh("cat >/dev/null; echo refused >&2; exit 1", &[], 5000);
    match run_send_message(&input("hi"), &s.signer, &s.deliverer, T0, &failing) {
        SendMessageResult::Failed { message_id: Some(id), error } => {
            assert!(id.starts_with("m-"));
            assert_eq!(error, "refused");
        }
        other => panic!("{other:?}"),
    }
    let reply = composed(&s, "hi");
    let id = reply.message_id.clone();
    let signed = reply.signed.clone();
    assert!(send_via_command(&failing, &reply).is_err());
    let ok = sh("cat >/dev/null", &[], 5000);
    send_via_command(&ok, &reply).unwrap();
    send_via_command(&ok, &reply).unwrap();
    assert_eq!(id, reply.message_id);
    assert_eq!(signed, reply.signed);
}

#[test]
fn model_result_caps_error_text() {
    let s = setup();
    let line = "x".repeat(1600);
    let script = format!("cat >/dev/null; echo {line} >&2; echo {line} >&2; echo {line} >&2; exit 1");
    let r = run_send_message(&input("hi"), &s.signer, &s.deliverer, T0, &sh(&script, &[], 5000));
    assert!(r.is_error());
    let j = r.to_json();
    assert_eq!(j["status"], "failed");
    assert!(j["message_id"].as_str().unwrap().starts_with("m-"));
    let e = j["error"].as_str().unwrap();
    assert!(!e.contains('\n'));
    assert!(e.len() <= 1024 && e.len() > 1000, "{}", e.len());
}

#[test]
fn timeout_result_says_so() {
    let s = setup();
    let r = run_send_message(&input("hi"), &s.signer, &s.deliverer, T0, &sh("exec sleep 30", &[], 300));
    assert_eq!(r.to_json()["error"], "send timed out");
}

#[test]
fn parse_failure_has_no_id() {
    let s = setup();
    let cmd = sh("cat >/dev/null", &[], 5000);
    let bad = json!({"to": ["room:r1"], "body": "x", "audience": "p256:aa"});
    let r = run_send_message(&bad, &s.signer, &s.deliverer, T0, &cmd);
    assert!(matches!(r, SendMessageResult::Failed { message_id: None, .. }));
    let j = r.to_json();
    assert_eq!(j["status"], "failed");
    assert!(j.get("message_id").is_none_or(Value::is_null));
    assert!(r.is_error());
}

#[test]
fn hosted_signer_works_through_the_entry_point() {
    let h = hosted_author(T0);
    let signer = ReplySigner::Hosted { session: Arc::new(h.session) };
    let cmd = sh("cat >/dev/null", &[], 5000);
    let r = run_send_message(&input("hi"), &signer, &deliverer(T0).id, T0, &cmd);
    assert!(matches!(r, SendMessageResult::Sent { .. }), "{r:?}");
}

#[test]
fn escaped_descendant_holding_pipes_does_not_block() {
    let s = setup();
    let script = r#"cat >/dev/null; perl -MPOSIX -e 'exit 0 if fork; POSIX::setsid(); exec "sleep", "30"'"#;
    let cmd = sh(script, &[], 5000);
    let t = Instant::now();
    send_via_command(&cmd, &composed(&s, "hi")).unwrap();
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
}

#[test]
fn error_line_skips_leading_blanks_and_carriage_return() {
    let s = setup();
    let cmd = sh("cat >/dev/null; printf '\\n\\nbad target\\r\\nmore\\n' >&2; exit 1", &[], 5000);
    let r = run_send_message(&input("hi"), &s.signer, &s.deliverer, T0, &cmd);
    assert_eq!(r.to_json()["error"], "bad target");
}
