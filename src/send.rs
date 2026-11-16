use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use identity_crypto::pb;
use prost::Message as _;
use wait_timeout::ChildExt;

use crate::error::AttestationError;
use crate::reply::ComposedReply;

pub const SEND_OUTPUT_CAP: usize = 64 * 1024;

/// How long to wait for the pipe threads once the child is gone.
const IO_GRACE: Duration = Duration::from_secs(1);

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

fn read_capped(mut r: impl Read, kept: &Mutex<Vec<u8>>) {
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let mut kept = kept.lock().unwrap_or_else(|e| e.into_inner());
                let room = SEND_OUTPUT_CAP - kept.len();
                kept.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
}

fn spawn_reader(
    pipe: impl Read + Send + 'static,
    buf: Arc<Mutex<Vec<u8>>>,
    done: mpsc::Sender<()>,
) {
    thread::spawn(move || {
        read_capped(pipe, &buf);
        let _ = done.send(());
    });
}

fn captured(kept: &Mutex<Vec<u8>>) -> String {
    String::from_utf8_lossy(&kept.lock().unwrap_or_else(|e| e.into_inner())).into_owned()
}

/// Runs `cmd` with the signed message on stdin. Exit 0 is `Ok`. On timeout the
/// whole process group is killed. A `ComposedReply` may be sent again, which
/// is the way to retry without a new message id.
///
/// Blocking by design: tokio hosts call it inside `spawn_blocking`.
pub fn send_via_command(
    cmd: &SendCommand,
    reply: &ComposedReply,
) -> Result<SendOutcome, AttestationError> {
    let (program, args) = cmd
        .argv
        .split_first()
        .ok_or_else(|| AttestationError::Send("empty argv".into()))?;
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .envs(cmd.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| AttestationError::Send(Box::new(e)))?;
    let pgid = child_group(&child);

    let (done_tx, done_rx) = mpsc::channel::<()>();
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| stdio_not_piped(&mut child))?;
    let bytes = send_bytes(&reply.signed);
    let tx = done_tx.clone();
    thread::spawn(move || {
        let _ = stdin.write_all(&bytes);
        let _ = tx.send(());
    });
    let stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| stdio_not_piped(&mut child))?;
    let stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| stdio_not_piped(&mut child))?;
    let out_buf = Arc::new(Mutex::new(Vec::new()));
    let err_buf = Arc::new(Mutex::new(Vec::new()));
    spawn_reader(stdout_pipe, out_buf.clone(), done_tx.clone());
    spawn_reader(stderr_pipe, err_buf.clone(), done_tx.clone());
    drop(done_tx);

    let status = match child.wait_timeout(cmd.timeout) {
        Ok(Some(status)) => Some(status),
        Ok(None) | Err(_) => None,
    };
    kill_group(pgid);
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    // A descendant that left the group may still hold the pipes. Give the
    // threads a bounded time, then abandon them and keep what was captured.
    let deadline = Instant::now() + IO_GRACE;
    for _ in 0..3 {
        let left = deadline.saturating_duration_since(Instant::now());
        if done_rx.recv_timeout(left).is_err() {
            break;
        }
    }
    let stdout = captured(&out_buf);
    let stderr = captured(&err_buf);

    match status {
        None => Err(AttestationError::SendTimeout {
            secs: cmd.timeout.as_secs().max(1),
        }),
        Some(s) if s.success() => Ok(SendOutcome { stdout }),
        Some(s) => Err(AttestationError::SendFailed {
            status: s.code(),
            stderr,
        }),
    }
}

/// The process group the child leads (spawned with `process_group(0)`).
fn child_group(child: &std::process::Child) -> Option<rustix::process::Pid> {
    rustix::process::Pid::from_raw(child.id() as i32)
}

/// SIGKILLs the whole group; a group that is already gone is not an error.
fn kill_group(pgid: Option<rustix::process::Pid>) {
    if let Some(pgid) = pgid {
        let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
    }
}

fn stdio_not_piped(child: &mut std::process::Child) -> AttestationError {
    kill_group(child_group(child));
    let _ = child.kill();
    let _ = child.wait();
    AttestationError::Send("child stdio was not piped".into())
}
