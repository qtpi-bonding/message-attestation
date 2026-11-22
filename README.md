# message-attestation

Signs and verifies author-signed Messages inside a deliverer-signed Delivery carried in ACP `_meta`, and renders them as text an agent reads. It **authenticates, never authorizes**: what to do with a message (or on rejection) is the consumer's policy.

The wire types are `identity_crypto::pb::{Message, SignedMessage, Delivery}`; this crate is named differently on purpose. P-256 only. Pure and synchronous: no tokio, no clock (the caller passes `now_unix`), no key storage (a signer passes its own credentials). Only `FileReplayStore` does I/O. Unix only: the crate refuses to compile on other targets (`compile_error!`), because the replay store relies on file modes, ownership and `O_NOFOLLOW`.

Everything is exported from the crate root (`message_attestation::{..}`); the modules are private.

## Message rules

`validate_message` (run by both signing and verifying) checks, in field order:

- `message_id`: 1 to `MAX_ID_LEN` (128) bytes, each in `[A-Za-z0-9._:-]` (`is_valid_id`).
- `to`: at least one and at most `MAX_TARGETS` (64) targets. Each target is set; a room id follows the id charset; a recipient id is a canonical principal id (`validate_target`).
- `reply_to` (if set) and every `references` entry follow the id charset.
- Every `mentions` entry is a canonical principal id.
- `authored_at` is present.

A Message is carried as a `SignedMessage` whose body type is `MESSAGE_BODY_TYPE` (`type.googleapis.com/identitycrypto.v1.Message`), whose nonce is `message_nonce(message_id)`, and whose audience is the deliverer's principal id (the author signs for the deliverer, which re-signs the batch for the recipient).

## Signing

- `sign_message(&session, delegation: KeyDelegation, audience: &str, issued_at_unix, &message)` signs with a `SessionCredential`. The root-to-device delegation is required and carried in the chain; a recipient's carried-message verifier refuses a chain without a device, so there is no way to sign without one.
- `sign_hosted_message(&hosted_session, audience: &str, issued_at_unix, &message)` is the same for a `HostedSessionCredential`.
- `sign_delivery(device: &dyn Signer, &device_delegation, UnsignedDelivery { delivery_id, recipient_id, recipient_devices, sequence, attested_at, messages, names })` signs with the deliverer's DEVICE key only; `device_delegation` (root to that device) is carried as `signer_device` and must delegate exactly this device. Each `OutgoingMessage` is `{ message: SignedMessage, via: Vec<Target> }`. Empty `messages` is `EmptyMessages`, empty `recipient_devices` is `NoRecipients`, a bad `delivery_id` is `InvalidDeliveryId`, an empty or invalid `via` is `InvalidVia { index }`. More than `MAX_MESSAGES` (256) messages, or more than `MAX_MESSAGES` names, is `TooManyMessages { count, max }`. The result is self-verified before it is returned. `names` are `ResolvedPrincipal`s (a registry-bound name); they are sorted by id and written to field 10 of the Delivery, and a name for a principal that authors no message is `StrayName { principal }`. The authors are not re-verified, except to find who wrote each message when `names` is non-empty: the deliverer has done that against its own directory.

## Reply tool

One `send_message` tool for every harness. The model supplies who the message is for and what it says; the harness signs it and pipes the bytes to a configured send command. **The harness signs, never the model**: the model never sees a key, and it cannot supply the audience, the message id, or a timestamp (`authored_at` and `issued_at` are both `now_unix`).

Contract (`send_message_tool()` returns a `ToolDefinition { name, description, input_schema }`):

- name: `SEND_MESSAGE_TOOL` = `"send_message"`.
- description: sends a message as yourself; `to` lists rooms (`room:<id>`) and agents or people (`p256:<hex>`), at most 64; to reply, pass the message's id as `reply_to`; `mentions` are `p256:` ids; the result is the new message's id.
- schema: an object with `to` (array of strings, 1 to 64), `body` (string, at least 1 character), optional `reply_to` (string), `references` and `mentions` (arrays of strings). Required: `to`, `body`. `additionalProperties` is false. The schema carries no `maxLength` on `body`: `MAX_BODY_BYTES` (65536 UTF-8 bytes) is what `parse_tool_input` enforces, and the description states it.

`parse_tool_input` turns the JSON into a `ReplyDraft`. `room:<id>` becomes a room target with the prefix stripped; `p256:<hex>` becomes a recipient target keeping the full string; anything else is refused. An unknown field (`message_id`, `audience`, `To`) is `InvalidMessage { field: "input", .. }` and nothing is signed. The id, target and mention rules are not repeated here: signing runs `validate_message`.

`ReplySigner` is `Keyed { session: Arc<SessionCredential>, device_delegation }` or `Hosted { session: Arc<HostedSessionCredential> }`. It is owned and `Clone`, so a host keeps one per agent. `compose_reply(&signer, &deliverer, now_unix, draft)` checks the signer is inside its validity window at `now_unix` (the session certificate and, when keyed, the device delegation; `identity_crypto::SKEW_SECONDS` of skew is allowed on the lower bounds), else `SessionExpired` and nothing is signed. It checks the body size, mints the id (`new_message_id() -> Result<String, AttestationError>`: `m-` plus 32 lowercase hex characters of OS randomness; it is fallible, and a failure of the OS source is `Randomness`) and signs with `audience = deliverer`. The audience is the deliverer principal the harness is configured with, never anything from the model.

`run_send_message(&input, &signer, &deliverer, now_unix, &cmd)` is parse, compose, send and result in one call. It never panics: every failure is `SendMessageResult::Failed`. The result has `to_json()` (`{"message_id", "status": "sent"|"failed", "output"?, "error"?}`) and `is_error()`. The model-visible `error` is the first non-blank line of the command's stderr, with `\r` stripped, at most 1024 bytes; the full stderr stays in the Rust error (`SendFailed`). A failure after composing still carries the `message_id`.

`send_via_command(&SendCommand { argv, env, timeout }, &composed)` runs the command with the `SignedMessage` protobuf bytes (`send_bytes`) on stdin. If the child's stdin, stdout or stderr is not piped the call is `Send(..)` (the process group is killed); it never panics. The child gets a cleared environment (`env_clear()`, then exactly `env`) and its own process group. Exit 0 is `Ok(SendOutcome { stdout })`; a non-zero exit is `SendFailed { status, stderr }`; a timeout is `SendTimeout`. After the child exits or times out, its whole process group is killed. The pipe threads then get a 1 s grace and are abandoned, keeping what was captured, so a descendant that left the group cannot hold the call open. Stdout and stderr are each capped at `SEND_OUTPUT_CAP` (64 KiB).

`send_via_command` blocks. A tokio host calls `run_send_message` or `send_via_command` inside `spawn_blocking`. To retry, resend the same `ComposedReply`: the message id stays the same and no new one is minted.

Wiring:

- gait handles `send_message` in its spine. It calls `parse_tool_input` and `compose_reply`, then spawns the command itself under its own process group with `send_bytes` on stdin. Its flags are `--send-command`, a repeated `--send-arg`, and `--send-audience <deliverer principal>`.
- structmuxd exposes it as an MCP tool for Claude Code: `send_message_tool()` for the definition, `run_send_message` for the call, `to_json()` as the content and `is_error()` as `isError`.
- Neither host nor this crate knows the transport. Concordium's command is `multimatrix submit-message --signed-file - --submit-server-addr <addr>`.

## Entry point

The Delivery lives in the ACP `_meta` object under the key `DEFAULT_META_KEY` = `"message-attestation/v2"`. `locate` and `attach` take that object itself (the value of `params._meta` in `session/prompt`), not the JSON-RPC request. The crate never walks `params`.

The lookup is top level only: a copy nested anywhere else under `_meta` is ignored. An absent key, or a `_meta` that is absent (`Null`), is `None`, not an error. A value at the key that is not a JSON object is `NotObject`. The value is proto3-JSON of `pb::Delivery`, decoded and written by identity-crypto's generated serde (unknown fields rejected). `attach` is the only writer and `locate` is its inverse; nobody hand-builds the JSON.

## Verify rule

```rust
let policy = DeliveryPolicy {
    trusted: &trusted,            // &[PrincipalId]: deliverer principals
    self_id: &self_id,            // this recipient; also the replay scope
    own_devices: &own_devices,    // empty is OwnDevicesMissing
    max_age_secs: None,           // freshness is off unless set
    now_unix,                     // required
};
match verify_delivery_meta(&meta, DEFAULT_META_KEY, &policy, &replay)? {
    None => { /* no Delivery in _meta: your policy */ }
    Some(Verified { delivery, pending }) => {
        // drop messages you have seen (MessageKey), render the rest, then:
        confirm(&replay, pending)?;
    }
}
```

`verify_delivery` takes an already decoded `pb::Delivery`; `verify_delivery_meta` is `locate` followed by it. The delivery steps, in order, each a rejection on failure:

1. `messages` is non-empty (`EmptyMessages`).
2. `signer_device` and its `principal_genesis` are present (`Transcript`); the deliverer principal is derived from the genesis.
3. The deliverer is in `trusted` (`UnknownDeliverer`).
4. `signer_device` is a valid root-to-device delegation for that deliverer at `now_unix` (`DelivererDevice`).
5. The delivery signature verifies under that device over `delivery_transcript` (`BadSignature`).
6. `delivery_id` follows the id charset (`InvalidDeliveryId`).
7. `recipient_id` equals `self_id` (`WrongRecipient`).
8. `own_devices` is non-empty (`OwnDevicesMissing`) and one of them is in `recipient_devices` (`NotARecipient`).
9. Age, only when `max_age_secs` is set: `attested_at` may lead `now_unix` by up to `identity_crypto::SKEW_SECONDS` (30 s); otherwise its age must be at most `max_age_secs` (`Stale`).
10. Replay: `sequence` must exceed the stored value for (scope = `self_id`, deliverer principal) (`Replay { principal, last, got }`). Nothing is recorded yet.

Then, for each message in signed order:

- The author chain verifies against audience = the deliverer principal (`verify_carried_message`; `WrongAudience { index }` or `MessageSignature { index, .. }`). This checks integrity with no clock and no registry: every signature links to the next and the certificate, delegations and message agree. It does not ask whether the author's session was current, so a message redelivered after its author's session expired still verifies; whether the author is acceptable is the Delivery signature plus your own seen-set record.
- The body type is `MESSAGE_BODY_TYPE` (`WrongBodyType { index }`), the body decodes, and `validate_message` passes (`InvalidMessage`).
- `via` for that message is non-empty and every entry is also in the message's `to` (`InvalidVia { index }`).

Every decode, signature or store error is a rejection; nothing returns `Ok` by default. The result exposes accessors only: `VerifiedDelivery::{delivery_id, recipient_id, deliverer, deliverer_device, sequence, attested_at_unix, messages}` and `VerifiedMessage::{author, message, via, key, view}`.

## Trusted deliverers

`trusted` is a list of deliverer principal ids, not keys. A deliverer proves a device by the carried `signer_device` delegation, which is checked at `now_unix`; a new or rotated deliverer device needs no change here. A deliverer's root rotation changes its principal, so it means updating the list.

## Replay

Scope is the recipient's own id (`self_id`); the key within it is the deliverer principal. Replay is two-phase: `verify_*` checks the sequence against the store but records nothing, so verifying twice succeeds. `confirm(&store, pending)` records it (atomic compare-and-advance) and returns `Replay` if the sequence was already advanced. **Confirm at the same point you record your own idempotency state.**

`MemoryReplayStore` is for tests and short-lived consumers.

A state file that is refused (the old bare-number layout, or a malformed entry) is `Store` whose `source()` is the public, `#[non_exhaustive]` `ReplayStateError`: `OldLayout` (bare number or no `attested_at`), `StateNotObject`, `ScopeNotObject`, `InvalidSequence`, `InvalidAttestedAt`. Classify with `err.source().and_then(|s| s.downcast_ref::<ReplayStateError>())`; `Store` still displays `store failed`.

```rust
pub trait ReplayStore: Send + Sync {
    fn last_seen(&self, scope: &str, key_id: &str) -> Result<Option<u64>, AttestationError>;
    fn record(&self, scope: &str, key_id: &str, seq: u64, attested_at_unix: i64,
              forget_before_unix: Option<i64>) -> Result<bool, AttestationError>;
}
```

`record` has five arguments. It returns `Ok(false)` when `seq <= last` (nothing is forgotten or written). Otherwise it stores the sequence with time `max(old, attested_at_unix)`, and when `forget_before_unix` is `Some(t)` removes, in the same write, every other entry of the same scope whose stored time is strictly `< t`. `confirm` passes `now_unix - max_age_secs` (and `None` when `max_age_secs` is `None`, so nothing is ever forgotten then).

**Forgetting rule and its assumption.** An entry older than `max_age_secs` guards nothing, because the freshness check refuses any delivery that old before the replay check runs. This holds only for an honest deliverer and a stable policy: `now_unix` must never step backwards (nor differ between processes sharing a store), `max_age_secs` must never grow or become `None` later, and a deliverer's `attested_at` must stay within `max_age` of its sequence order. Otherwise a forgotten deliverer's old delivery can look fresh again and be accepted a second time. The store keeps no clock floor; the consumer owns this.

**`FileReplayStore::open(path)`** persists

```json
{"<scope>": {"<key>": {"sequence": 7, "attested_at": 1760000000}}}
```

(temp file, fsync, rename, directory fsync) and holds an advisory lock on the sidecar `<path>.lock` across read-modify-write, so several processes can share one file. Needs rustc 1.89 (`File::lock`). It fails closed on a corrupt file, on a bare-number entry (the old layout) or an entry without `sequence` or `attested_at` (`Store`); there is no dual read, so live files need a one-time rewrite. Modes are required, never repaired:

| path | required mode | notes |
| --- | --- | --- |
| parent directory | `0700` | created `0700` if missing; only the leaf is checked, at `open` |
| `<path>` (state) | `0600` | written `0600`; refused if any group/other bit is set |
| `<path>.lock` | `0600` | created `0600`; opened `O_NOFOLLOW`, checked on the handle before locking |

All three must be owned by the effective user. A loose, foreign-owned, symlinked or non-regular file is a `Store` error (the source is a `identity_keyfile::KeyfileError`: `InsecureDir`, `InsecureFile`, `WrongOwner`, `NotAFile`); the library never `chmod`s. The state file is read with a cap of `REPLAY_STATE_MAX_BYTES` (1 MiB, `TooLarge` beyond it) and a write that would exceed the cap is refused, so a full store refuses new keys instead of bricking itself. A missing state file is an empty store.

## Errors

`AttestationError` is `#[non_exhaustive]` and derives `coded_error::CodedError` with namespace `message.attestation`: `error.code()` is `message.attestation.<code>`, and `class()` is `Logical`, `Infrastructure` or `Transient`. Sources are boxed (`Source = Box<dyn Error + Send + Sync>`) and reachable through `std::error::Error::source()`; for example `Sign` wraps an `identity_crypto::SignerError`, so a UI can downcast `Cancelled`. `Sign`, `Decode`, `Encode`, `Transcript`, `DelivererDevice` and `Send` display their cause (`sign: {cause}`, `decode: ..`, `encode: ..`, `transcript: ..`, `deliverer device: ..`, `send: ..`), as before 0.5.0, and still expose it through `source()`. Only `Store` is pathless: it displays `store failed` with the path-bearing cause in `source()`. `Randomness` displays the fixed text `no OS randomness`.

| variant | code | class |
| --- | --- | --- |
| `Replay { principal, last, got }` | `replay` | Logical |
| `Store(Source)` | `store` | Infrastructure |
| `InvalidMessage { field, reason }` | `invalid_message` | Logical |
| `Sign(Source)` | `sign` | Infrastructure |
| `NotObject` | `not_object` | Logical |
| `Decode(Source)` | `decode` | Logical |
| `Encode(Source)` | `encode` | Infrastructure |
| `EmptyMessages` | `empty_messages` | Logical |
| `NoRecipients` | `no_recipients` | Logical |
| `Transcript(Source)` | `transcript` | Logical |
| `InvalidDeliveryId` | `invalid_delivery_id` | Logical |
| `InvalidVia { index }` | `invalid_via` | Logical |
| `UnknownDeliverer(String)` | `unknown_deliverer` | Logical |
| `DelivererDevice(Source)` | `deliverer_device` | Logical |
| `WrongRecipient` | `wrong_recipient` | Logical |
| `WrongAudience { index }` | `wrong_audience` | Logical |
| `MessageSignature { index, reason }` | `message_signature` | Logical |
| `WrongBodyType { index }` | `wrong_body_type` | Logical |
| `BadSignature` | `bad_signature` | Logical |
| `OwnDevicesMissing` | `own_devices_missing` | Infrastructure |
| `NotARecipient` | `not_a_recipient` | Logical |
| `Stale { age, max }` | `stale` | Logical |
| `UnknownRenderVersion(u32)` | `unknown_render_version` | Infrastructure |
| `SessionExpired { not_after, now }` | `session_expired` | Logical |
| `Send(Source)` | `send` | Infrastructure |
| `SendFailed { status, stderr }` | `send_failed` | Infrastructure |
| `SendTimeout { secs }` | `send_timeout` | Transient |
| `InvalidName { reason }` | `invalid_name` | Logical |
| `StrayName { principal }` | `stray_name` | Logical |
| `TooManyMessages { count, max }` | `too_many_messages` | Logical |
| `InvalidRecipientDevice { index }` | `invalid_recipient_device` | Logical |
| `Randomness(Source)` | `randomness` | Infrastructure |
| `TargetInvalid(String)` | `target_invalid` | Logical |

Verification also refuses, before any per-message work: more than `MAX_MESSAGES` messages or names (`TooManyMessages`), a `via` list whose length differs from `messages` (`InvalidVia`), and a recipient device that is not a public key (`InvalidRecipientDevice { index }`).

## Seen messages

`VerifiedMessage::key()` returns a `MessageKey { author: PrincipalId, message_id }`, the one spelling of a message's identity. The crate keeps no seen set: it needs durable storage and a retention policy that belong to the consumer, and a Message is legitimately redelivered inside a new Delivery with a fresh sequence. Drop already-seen keys before rendering.

## Rendering

`render(&verified_delivery, &self_id, trust, &RenderOptions)` renders every message in signed order, joined by `"\n"`. `render_message(&view, self_id, trust, version, &RenderOptions)` renders one `MessageView` (from `VerifiedMessage::view()` or a caller's own log) at a stated version; an unknown version is `UnknownRenderVersion(v)`. `RENDER_VERSION` is `2`: store it with each logged message and re-render with the stored version. `render_message` validates the view by the same Message rules and refuses with `InvalidMessage`.

Version 2 attribute order is `id, from, from-name?, owner?, to, via, reply-to?, references?, mentions?, mentions-you?, trust`. `from-name` appears iff the view has an `author_name`; `owner="true"` appears iff `RenderOptions.owner` is the author's id, and is the only authority marker. With neither, version 2 is byte-identical to version 1. Version 1 still renders as before, but a view with a name or options with an owner is refused (`InvalidMessage { field: "render_version", reason: "needs 2" }`).

One message is:

```
<incoming-message id="..." from="..." [from-name="..."] [owner="true"] to="..." via="..." [reply-to="..."] [references="..."] [mentions="..." [mentions-you="true"]] trust="verified|relayed|unverified">body</incoming-message>
```

`from` is the author principal. `to` and `via` are comma-space joined targets: a room is `room:<id>`, a recipient equal to `self_id` is `you`, any other recipient is its principal id. `references` and `mentions` are comma-space joined; `mentions-you` appears only when `self_id` is among the mentions. `Trust` is `Verified`, `Relayed` or `Unverified`.

Attribute values escape:

| char | output |
| --- | --- |
| `&` | `&amp;` |
| `<` | `&lt;` |
| `>` | `&gt;` |
| `"` | `&quot;` |
| `'` | `&#39;` |
| LF | `&#10;` |
| CR | `&#13;` |

The body escapes only:

| char | output |
| --- | --- |
| `&` | `&amp;` |
| `<` | `&lt;` |
| `>` | `&gt;` |

Quotes and newlines in a body are kept. A body cannot contain a `<`, so it cannot close the element or open a forged tag; `trust=` therefore occurs only inside the opening tag.

## Speaker names

`RegisteredName::parse` accepts 1 to `MAX_NAME_LEN` (64) bytes of `[A-Za-z0-9 ._-]` with no leading or trailing space and no double space; anything else is `InvalidName { reason }`, never repaired. The rule is enforced at `parse`, at `verify_delivery` (`VerifiedMessage::author_name()`, `VerifiedDelivery::names()`) and at `render_message`. This guards against injection, not impersonation: lookalike names are allowed, so only `owner="true"` marks authority. `sign_delivery` takes only `ResolvedPrincipal`s; `ResolvedPrincipal::from_registry` exists only with the `resolver` Cargo feature, which only the registry-owning deliverer should enable.

## Shared vectors

`vectors/delivery.json` is generated by `vectors/gen.py` (`cryptography==44.0.2`, independent of the Rust code). Run it from `vectors/` with `.venv/bin/python -I gen.py` (create it with `python3 -m venv vectors/.venv && vectors/.venv/bin/pip install -r vectors/requirements.txt`); it writes `vectors/delivery.json` next to itself. The file is `{"cases": [...]}`; each case has `name`, `trusted` (principal ids), `self_id`, `own_devices` (hex public keys), `meta`, `prior_sequences` (`{scope, key, last}`), `now_unix`, `max_age_secs`, `render_owner` (a principal id or null, passed as `RenderOptions.owner`), `transcript_hex` (the signed delivery transcript, or null when `meta` is hand-built or the transcript itself is refused) and `expected`: `{"ok": {"messages": [{author, message_id, author_name?}], "render": ...}}`, `{"none": true}` or `{"error": "<AttestationError variant>"}`. A consumer loads the file and asserts every case; see `tests/vectors.rs`. A mismatch is decided against the schema, never by regenerating the file to match Rust.
