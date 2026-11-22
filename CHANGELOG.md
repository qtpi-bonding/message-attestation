# Changelog

## Unreleased

- New workspace member `message-attestation-signer` (lib + bin): signs room messages over a local unix socket, on the shared `identity-request-signer` server. Adds the `sign_message` op next to `sign_request` and `info`; reads a `[message]` section (`deliverer`, `max_targets`) from the signer config. The deliverer is configured, not discovered. The identity-crypto and identity-keyfile pins move to 1fdf2ab.
- `parse_tool_input` refuses a whitespace-only body (`invalid_message` with `field: "body"`, `reason: "empty"`) and keeps a body's surrounding whitespace exactly as typed.
- The message-attestation-signer uses two error-code namespaces. Start-up and config errors (the `--config` load and the start-up refusals, on stderr) are `message.signer.*` (`config_invalid`, `service_principal_missing`, `keys`). Replies over the socket carry the shared server's `identity.request_signer.*` codes: `bad_request` with a `field` and a `reason`, `delegation_expired`, and `internal`. `message.attestation.*` codes are not used in socket replies: the op maps every attestation refusal into one of the server codes before it reaches the wire.

## 0.6.0

- New `parse_target(text)` and `parse_targets(texts)`, exported at the crate root. They are the one copy of the `--to` text rules, moved from multimatrix-client. `room:<id>` names a room (the id is kept as typed); `p256:<130 hex>` names a principal; anything else is an error. `parse_targets` also rejects an empty list, more than `MAX_TARGETS` entries, a target that fails `validate_target`, and a duplicate.
- New variant `AttestationError::TargetInvalid(String)`, code `message.attestation.target_invalid`, class Logical, gRPC `InvalidArgument`.
- `parse_tool_input` now uses `parse_target`. A `to` entry that is not `room:` or `p256:` now fails with `target_invalid` instead of `invalid_message`.

## 0.5.0

Breaking release. Every item below can fail a consumer's build or change its behaviour.

### API

- `AttestationError` derives `coded_error::CodedError` (namespace `message.attestation`; `code()` is `message.attestation.<code>`, `class()` is Logical, Infrastructure or Transient). Only the last code segment equals the old per-consumer `reason()` strings, so anything matching a full code string must change. Codes: `unknown_deliverer, deliverer_device, bad_signature, message_signature, not_a_recipient, wrong_recipient, wrong_audience, replay, stale, session_expired, invalid_message, invalid_delivery_id, invalid_via, wrong_body_type, decode, transcript, not_object, no_recipients, empty_messages, invalid_name, stray_name, too_many_messages, invalid_recipient_device, store, sign, encode, own_devices_missing, unknown_render_version, send, send_failed, randomness, send_timeout`. The full table is in the README.
- New variants: `TooManyMessages { count, max }`, `InvalidRecipientDevice { index }`, `Randomness(Source)`. The enum is `#[non_exhaustive]`.
- Error sources are boxed (`Source = Box<dyn Error + Send + Sync>`) and exposed through `std::error::Error::source()`: `Store`, `Sign`, `Decode`, `Encode`, `Transcript`, `DelivererDevice` and `Send` now carry a boxed source instead of a `String` or a concrete type (a pattern `DelivererDevice(_)` still matches). `Sign` wraps `identity_crypto::SignerError`, so `Cancelled` can be downcast. `Sign`, `Decode`, `Encode`, `Transcript`, `DelivererDevice` and `Send` keep the cause in their Display (`sign: {0}`, `decode: {0}`, `encode: {0}`, `transcript: {0}`, `deliverer device: {0}`, `send: {0}`), as in 0.4.1. `Store` displays `store failed`; the path is in the source (it may hold a path, so it is never put in the text).
- All public items are exported from the crate root only; the modules (`error`, `locate`, `message`, `names`, `render`, `replay`, `reply`, `send`, `sign`, `tool`, `verify`) are private. `message_attestation::replay::..` style paths no longer resolve.
- `sign_message(&SessionCredential, KeyDelegation, &str audience, issued_at_unix, &Message)`: the delegation is required (by value, as in 0.4.1; an earlier draft of this 0.5.0 text had `Option<KeyDelegation>`, which is NOT the shipped shape) and the audience is a `&str`. Argument order is `(session, delegation, audience, issued_at, message)`. A recipient's carried-message verifier refuses a chain without a device delegation, so `None` could only produce messages every receiver refuses.
- `sign_delivery` takes `device: &dyn identity_crypto::Signer` instead of a concrete key.
- `ReplayStore::record` takes five arguments: `(scope, key_id, seq, attested_at_unix: i64, forget_before_unix: Option<i64>)`.
- `new_message_id()` is fallible: `Result<String, AttestationError>` (`Randomness`).
- `send_message_tool()` schema has no `maxLength` on `body`; the 65536-byte limit (`MAX_BODY_BYTES`) is enforced by `parse_tool_input` and stated in the description.
- `send_via_command` no longer panics when the child's stdio is not piped: it kills the process group and returns `Send`.
- New public constant `MAX_MESSAGES` = 256 (messages and names per Delivery); `sign_delivery` and `verify_delivery` refuse more with `TooManyMessages`.
- Verification now refuses, ahead of per-message work: more than 256 messages or names, a `via` list whose length differs from `messages` (`InvalidVia`), and a recipient device that is not a public key (`InvalidRecipientDevice { index }`). `sign_delivery` also checks the delegation's `not_after`.

### Replay store

- New public `ReplayStateError` (`#[non_exhaustive]`, `std::error::Error`, exported at the crate root): the typed `source()` of `AttestationError::Store` for a refused state file. Variants: `OldLayout` (bare number or no `attested_at`), `StateNotObject`, `ScopeNotObject`, `InvalidSequence`, `InvalidAttestedAt`. Classify with `error.source().and_then(|s| s.downcast_ref::<ReplayStateError>())`. `Store` still displays `store failed`; its code and class are unchanged.
- File layout changed to `{"<scope>":{"<key>":{"sequence":N,"attested_at":T}}}`. The old layout (a bare number per key) is not read: it fails closed with `Store` whose source is `ReplayStateError::OldLayout`. Live files need a one-time rewrite (wrap each number as `{"sequence":N,"attested_at":<migration time>}`; migration time only delays forgetting). There is no dual read.
- `FileReplayStore::open` requires parent directory `0700`, state file `0600` and lock file `0600`, all owned by the effective user. It creates the parent `0700` and the files `0600`, but a loose, foreign-owned, symlinked or non-regular path is refused, never tightened. Existing deployments must `chmod` before upgrading.
- The state file is read with a 1 MiB cap (`REPLAY_STATE_MAX_BYTES`); a file larger than that, or a write that would exceed it, is `Store(TooLarge)`.
- Forgetting: `confirm` drops, in the same write, entries of the same scope whose stored time is older than `now_unix - max_age_secs`. This is safe only for an honest deliverer and a stable policy: `now_unix` never steps back, `max_age_secs` never grows or becomes `None` later, and the deliverer's `attested_at` stays within `max_age` of its sequence order. The store keeps no clock floor.

### Build

- Unix only: the crate fails to compile elsewhere.
- New dependencies: `coded-error` (pinned by full rev) and `identity-keyfile` (same repository and rev as `identity-crypto`); `rustix` (safe process-group kill; `fs` feature as a dev-dependency for tests).
- The crate contains no `unsafe` and sets `unsafe_code = "forbid"` in `[lints.rust]`. The replay lock's handle check and effective-uid lookup are `identity_keyfile::private_fs::check_private_file_handle` (which uses `effective_uid` internally); this crate no longer carries its own copies.
- `scripts/check.sh` is the full gate (fmt, clippy, tests with default and all features, `--no-default-features` check).
- README: removed the "Pinned dependency" section (the pin lives in `Cargo.toml`).
