use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use identity_crypto::pb;
use prost::Message as _;
use wait_timeout::ChildExt;

use crate::error::AttestationError;
use crate::reply::ComposedReply;

pub const SEND_OUTPUT_CAP: usize = 64 * 1024;

/// The command a signed message is piped to. `env` is the child's whole
/// environment: `env_clear()`, then exactly these pairs.
#[derive(Clone, Debug)]
pub struct SendCommand {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub timeout: Duration,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SendOutcome {
    pub stdout: String,
}

/// The bytes a send command receives on stdin, for hosts that spawn themselves.
pub fn send_bytes(signed: &pb::SignedMessage) -> Vec<u8> {
    signed.encode_to_vec()
}

fn read_capped(mut r: impl Read) -> String {
    let mut kept = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = SEND_OUTPUT_CAP - kept.len();
                kept.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
    String::from_utf8_lossy(&kept).into_owned()
}

/// Runs `cmd` with the signed message on stdin. Exit 0 is `Ok`. On timeout the
/// whole process group is killed. A `ComposedReply` may be sent again, which
/// is the way to retry without a new message id.
///
/// Blocking by design: tokio hosts call it inside `spawn_blocking`.
pub fn send_via_command(cmd: &SendCommand, reply: &ComposedReply) -> Result<SendOutcome, AttestationError> {
    let (program, args) = cmd.argv.split_first().ok_or_else(|| AttestationError::Send("empty argv".into()))?;
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .envs(cmd.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| AttestationError::Send(format!("spawn {program}: {e}")))?;
    let pgid = child.id() as libc::pid_t;

    let mut stdin = child.stdin.take().expect("piped stdin");
    let bytes = send_bytes(&reply.signed);
    let writer = thread::spawn(move || {
        let _ = stdin.write_all(&bytes);
    });
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let out_reader = thread::spawn(move || read_capped(stdout));
    let err_reader = thread::spawn(move || read_capped(stderr));

    let waited = child.wait_timeout(cmd.timeout);
    let status = match waited {
        Ok(Some(status)) => Some(status),
        Ok(None) | Err(_) => None,
    };
    // Reaching here with a live group (timeout, or a leftover grandchild
    // still holding the pipes) needs a group kill so the readers finish.
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = writer.join();
    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();

    match status {
        None => Err(AttestationError::SendTimeout { secs: cmd.timeout.as_secs().max(1) }),
        Some(s) if s.success() => Ok(SendOutcome { stdout }),
        Some(s) => Err(AttestationError::SendFailed { status: s.code(), stderr }),
    }
}
