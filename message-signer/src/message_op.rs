//! The `sign_message` op: parses the tool input, mints/refreshes the message
//! session and signs with `compose_reply`.

use crate::config::MessageConfig;
use crate::error::MessageSignerError;
use identity_request_auth::Clock;
use identity_request_signer::SignerError;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// A minted message session lasts this long.
pub const SESSION_TTL_SECONDS: i64 = 3600;
/// A session is re-minted once this much of its life has passed (60%).
pub const SESSION_REMINT_AFTER_SECONDS: i64 = 2160;

/// The cached session, when it was minted, and the delegation used.
struct CachedSession {
    minted_at: i64,
    session: Arc<identity_crypto::SessionCredential>,
    delegation: identity_crypto::pb::KeyDelegation,
}

struct Inner {
    message: MessageConfig,
    deliverer: identity_crypto::PrincipalId,
    clock: Arc<dyn Clock>,
    /// Only the device key (to mint sessions) and the principal genesis are
    /// used from the keys; the delegation always comes from
    /// `ctx.device.delegation()` at op time.
    keys: identity_keyfile::DeviceKeys,
    session: Mutex<Option<CachedSession>>,
    /// How many sessions were minted; for tests.
    minted: AtomicUsize,
}

/// The registered op. Cheap to clone; clones share the mint counter.
#[derive(Clone)]
pub struct MessageOp {
    inner: Arc<Inner>,
}

impl MessageOp {
    /// Validates the message config, then loads the device-only keys from
    /// `identity_dir` (`identity_keyfile::DeviceKeys::load`; a fixed error on
    /// failure). Starts with an empty session cache.
    pub fn new(
        identity_dir: &Path,
        message: &MessageConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<MessageOp, MessageSignerError> {
        message.validate()?;
        let keys = identity_keyfile::DeviceKeys::load(identity_dir).map_err(|_| {
            MessageSignerError::Keys(String::from("the device keys could not be loaded"))
        })?;
        let deliverer =
            identity_crypto::PrincipalId::parse_canonical(&message.deliverer).map_err(|_| {
                MessageSignerError::ConfigInvalid(String::from(
                    "the deliverer is not a canonical principal id",
                ))
            })?;
        Ok(MessageOp {
            inner: Arc::new(Inner {
                message: message.clone(),
                deliverer,
                clock,
                keys,
                session: Mutex::new(None),
                minted: AtomicUsize::new(0),
            }),
        })
    }

    /// How many sessions were minted so far; for tests.
    pub fn mint_count(&self) -> usize {
        self.inner.minted.load(Ordering::SeqCst)
    }

    /// Returns a session and the delegation it was minted with, re-minting
    /// when none is cached, the cache is past 60% of its life, or the
    /// delegation from the device state no longer matches the cached one.
    fn session_for(
        &self,
        ctx: &identity_request_signer::OpContext,
        now: i64,
    ) -> Result<
        (
            Arc<identity_crypto::SessionCredential>,
            identity_crypto::pb::KeyDelegation,
        ),
        SignerError,
    > {
        let mut cache = self
            .inner
            .session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // The delegation the op will sign with, taken from the server's
        // device state (re-read from the file there, so a renewed delegation
        // is picked up without a restart).
        let delegation = ctx.device.delegation();
        if let Some(cached) = cache.as_ref() {
            // A clock stepped back below the mint time leaves the cached
            // session not yet valid (`now < not_before`), so re-mint rather
            // than hand out a session the signer would refuse.
            let cache_valid = now >= cached.minted_at
                && now < cached.minted_at + SESSION_REMINT_AFTER_SECONDS
                && cached.delegation == delegation;
            if cache_valid {
                return Ok((Arc::clone(&cached.session), delegation));
            }
        }
        // No start-time fallback: the delegation is always the current one.
        let session = identity_crypto::mint_session(
            &self.inner.keys.device,
            &self.inner.keys.principal_id.genesis().clone(),
            now,
            now + SESSION_TTL_SECONDS,
        )
        .map_err(|_| SignerError::Internal(String::from("the session could not be minted")))?;
        let session = Arc::new(session);
        *cache = Some(CachedSession {
            minted_at: now,
            session: Arc::clone(&session),
            delegation: delegation.clone(),
        });
        self.inner.minted.fetch_add(1, Ordering::SeqCst);
        Ok((session, delegation))
    }
}

impl identity_request_signer::Op for MessageOp {
    fn name(&self) -> &str {
        "sign_message"
    }

    fn run(
        &self,
        ctx: &identity_request_signer::OpContext,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, SignerError> {
        ctx.device.ensure_valid()?;
        // Strip the "op" field, refuse everything else parse_tool_input rejects.
        let input: serde_json::Map<String, serde_json::Value> = request
            .as_object()
            .ok_or_else(|| {
                SignerError::BadRequest(String::from("the request must be a JSON object"))
            })?
            .iter()
            .filter(|(key, _)| key.as_str() != "op")
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let draft = message_attestation::parse_tool_input(&serde_json::Value::Object(input))
            .map_err(map_attestation_error)?;
        if draft.to.len() > self.inner.message.max_targets() {
            return Err(SignerError::BadRequest(String::from(
                "too many targets for one message",
            )));
        }
        let mut seen: Vec<&identity_crypto::pb::Target> = Vec::with_capacity(draft.to.len());
        if draft.to.iter().any(|target| {
            if seen.contains(&target) {
                true
            } else {
                seen.push(target);
                false
            }
        }) {
            return Err(SignerError::BadRequest(String::from(
                "duplicate targets are not allowed",
            )));
        }
        let now = self.inner.clock.now().seconds;
        let (session, delegation) = self.session_for(ctx, now)?;
        let reply = message_attestation::compose_reply(
            &message_attestation::ReplySigner::Keyed {
                session,
                device_delegation: delegation,
            },
            &self.inner.deliverer,
            now,
            draft,
        )
        .map_err(map_attestation_error)?;
        use base64::Engine;
        use prost::Message as _;
        let signed_b64 =
            base64::engine::general_purpose::STANDARD.encode(reply.signed.encode_to_vec());
        Ok(serde_json::json!({
            "message_id": reply.message_id,
            "signed_b64": signed_b64,
        }))
    }
}

/// Maps attestation failures into signer refusals. Only the field/reason
/// Display of `InvalidMessage` is passed through; every other caller-fault
/// variant gets a fixed message so nothing about the request body or the keys
/// can leak. Only randomness and sign failures stay `Internal`.
fn map_attestation_error(err: message_attestation::AttestationError) -> SignerError {
    match err {
        message_attestation::AttestationError::InvalidMessage { field, reason } => {
            SignerError::BadRequest(
                message_attestation::AttestationError::InvalidMessage { field, reason }.to_string(),
            )
        }
        // The caller's fault: a target string that is neither `room:<id>` nor
        // a canonical principal id. A fixed shape, so the offending text in
        // the variant (which quotes the request) is never echoed.
        message_attestation::AttestationError::TargetInvalid(_) => {
            SignerError::BadRequest(String::from("invalid message to: not a target"))
        }
        message_attestation::AttestationError::SessionExpired { .. } => SignerError::Expired,
        message_attestation::AttestationError::Randomness(_) => {
            SignerError::Internal(String::from("the message could not be signed"))
        }
        message_attestation::AttestationError::Sign(_) => {
            SignerError::Internal(String::from("the message could not be signed"))
        }
        _ => SignerError::Internal(String::from("the message could not be signed")),
    }
}
