//! The real binary starts from a 0600 config for a device-only temp dir and
//! serves `info`, `sign_request` and `sign_message` over its socket.

mod common;

use common::*;
use prost::Message as _;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Kill-on-drop guard: a panic in any assertion or the socket wait still
/// kills the child binary.
struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn the_binary_starts_and_serves_sign_message_over_its_socket() {
    // The session TMPDIR sits under a very long path; a unix socket path is
    // capped far below it, so bind the socket from a short `/tmp` path.
    std::env::set_var("TMPDIR", "/tmp");
    // The binary reads the real system clock, so the identity must be
    // initialised at (roughly) the same wall-clock time or the delegation
    // looks expired to it.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the system clock is after the epoch")
        .as_secs() as i64;
    let dir = DeviceOnlyDir::new(now, 91 * 86400);
    let deliverer = principal_string(dir.path());
    let socket = dir.path().join("run.sock");
    let config_dir = tempfile::TempDir::new().expect("config temp dir");
    let config_path: PathBuf = config_dir.path().join("signer.toml");
    let text = format!(
        "{}server_id = {:?}\n[message]\ndeliverer = {:?}\n",
        config_text(dir.path(), &socket),
        SERVER,
        deliverer
    );
    std::fs::write(&config_path, text).expect("write config");
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
        .expect("make the config 0600");

    let child = std::process::Command::new(env!("CARGO_BIN_EXE_message-attestation-signer"))
        .arg("--config")
        .arg(&config_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn the binary");
    let mut child = ChildGuard(child);

    // Wait up to 5 s for the socket to appear.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut connected: Option<UnixStream> = None;
    while Instant::now() < deadline {
        match UnixStream::connect(&socket) {
            Ok(stream) => {
                connected = Some(stream);
                break;
            }
            Err(_) => {
                if matches!(child.0.try_wait(), Ok(Some(_))) {
                    panic!("the binary exited before its socket appeared");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    assert!(connected.is_some(), "the socket appeared within 5 s");
    let path = socket;
    let exchange = |request: &str| -> serde_json::Value {
        // The server handles one line per connection.
        let mut stream = UnixStream::connect(&path).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set timeout");
        stream.write_all(request.as_bytes()).expect("write request");
        stream.write_all(b"\n").expect("write newline");
        let mut line = String::new();
        BufReader::new(stream.try_clone().expect("clone stream"))
            .read_line(&mut line)
            .expect("read reply");
        serde_json::from_str(&line).expect("the reply is JSON")
    };

    let info = exchange("{\"op\":\"info\"}");
    assert_eq!(info["ok"], true, "info reply: {info}");
    assert_eq!(info["principal"], deliverer);

    let request = format!(
        "{{\"op\":\"sign_message\",\"to\":[{ROOM:?},{deliverer:?}],\"body\":\"over the socket\",\"reply_to\":null,\"references\":[],\"mentions\":[]}}"
    );
    let reply = exchange(&request);
    assert_eq!(reply["ok"], true, "sign_message reply: {reply}");
    let signed_bytes = decode_b64(reply["signed_b64"].as_str().expect("signed_b64"));
    let signed =
        identity_crypto::pb::SignedMessage::decode(signed_bytes.as_slice()).expect("decode");
    let carried = identity_crypto::verify_carried_message(&signed, &deliverer)
        .expect("the socket-signed message verifies against the deliverer");
    assert_eq!(carried.body_type(), message_attestation::MESSAGE_BODY_TYPE);
    assert_eq!(
        carried.author().to_string(),
        deliverer,
        "the author is the device principal"
    );

    // Never leave the child running: the guard kills it on drop.
    drop(child);
}
