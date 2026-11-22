//! Thin front end: parse args, load config, start the server with both ops.

use std::sync::Arc;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path: Option<String> = None;
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--config" => {
                config_path = iter.next().cloned();
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let path = match config_path {
        Some(p) => std::path::PathBuf::from(p),
        None => {
            eprintln!("usage: message-attestation-signer --config PATH");
            std::process::exit(2);
        }
    };
    let (config, message_config) = match message_attestation_signer::load_config(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", coded_error::CodedError::code(&e));
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let identity_dir = config.identity_dir.clone();
    let clock: Arc<dyn identity_request_auth::Clock> = Arc::new(identity_request_auth::SystemClock);
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|line| eprintln!("{line}"));
    let message_op = match message_attestation_signer::MessageOp::new(
        &identity_dir,
        &message_config,
        Arc::clone(&clock),
    ) {
        Ok(op) => op,
        Err(e) => {
            log(&format!(
                "start refused: {}",
                coded_error::CodedError::code(&e)
            ));
            std::process::exit(1);
        }
    };
    let mut server = match identity_request_signer::Server::new(config, clock, log.clone()) {
        Ok(s) => s,
        Err(e) => {
            log(&format!(
                "start refused: {}",
                coded_error::CodedError::code(&e)
            ));
            std::process::exit(1);
        }
    };
    for op in [
        Box::new(identity_request_signer::SignRequestOp::new())
            as Box<dyn identity_request_signer::Op>,
        Box::new(message_op) as Box<dyn identity_request_signer::Op>,
    ] {
        if let Err(e) = server.register_op(op) {
            log(&format!(
                "start refused: {}",
                coded_error::CodedError::code(&e)
            ));
            std::process::exit(1);
        }
    }
    let bound = match server.bind() {
        Ok(b) => b,
        Err(e) => {
            log(&format!(
                "start refused: {}",
                coded_error::CodedError::code(&e)
            ));
            std::process::exit(1);
        }
    };
    let running = bound.spawn();
    std::thread::park();
    running.stop();
}
