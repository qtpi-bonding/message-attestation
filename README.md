# message-attestation

Signs and verifies author-signed Messages inside a deliverer-signed Delivery carried in ACP `_meta`, and renders them as text an agent reads. It **authenticates, never authorizes**: what to do with a message (or on rejection) is the consumer's policy.

The wire types are `identity_crypto::pb::{Message, SignedMessage, Delivery}`; this crate is named differently on purpose. P-256 only. Pure and synchronous: no tokio, no clock (the caller passes `now_unix`), no key storage (a signer passes its own credentials). Only `FileReplayStore` does I/O.

## Pinned dependency

`identity-crypto` 0.9.0, pinned to rev `feb5d585a77c6ba45eedc16fd08c2bd7feeff782`.

## Message rules

`validate_message` (run by both signing and verifying) checks, in field order:

- `message_id`: 1 to `MAX_ID_LEN` (128) bytes, each in `[A-Za-z0-9._:-]` (`is_valid_id`).
- `to`: at least one and at most `MAX_TARGETS` (64) targets. Each target is set; a room id follows the id charset; a recipient id is a canonical principal id (`validate_target`).
- `reply_to` (if set) and every `references` entry follow the id charset.
- Every `mentions` entry is a canonical principal id.
- `authored_at` is present.

A Message is carried as a `SignedMessage` whose body type is `MESSAGE_BODY_TYPE` (`type.googleapis.com/identitycrypto.v1.Message`), whose nonce is `message_nonce(message_id)`, and whose audience is the deliverer's principal id (the author signs for the deliverer, which re-signs the batch for the recipient).

## Signing

- `sign_message(&session, device_delegation, &audience, issued_at_unix, &message)` signs with a `SessionCredential`. `device_delegation` (root to device) is taken by value and carried; a recipient refuses a `SelfRooted` chain without it.
- `sign_hosted_message(&hosted_session, &audience, issued_at_unix, &message)` is the same for a `HostedSessionCredential`.
- `sign_delivery(&device, &device_delegation, UnsignedDelivery { delivery_id, recipient_id, recipient_devices, sequence, attested_at, messages })` signs with the deliverer's DEVICE key only; `device_delegation` (root to that device) is carried as `signer_device` and must delegate exactly this device. Each `OutgoingMessage` is `{ message: SignedMessage, via: Vec<Target> }`. Empty `messages` is `EmptyMessages`, empty `recipient_devices` is `NoRecipients`, a bad `delivery_id` is `InvalidDeliveryId`, an empty or invalid `via` is `InvalidVia { index }`. The result is self-verified before it is returned. The authors are not re-verified: the deliverer has done that against its own directory.

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

`MemoryReplayStore` is for tests and short-lived consumers. `FileReplayStore::open(path)` persists `{scope: {key: last}}` JSON (temp file, fsync, rename, directory fsync), fails closed on a corrupt file, and holds an advisory lock on the sidecar `<path>.lock` across read-modify-write, so several processes can share one file. Needs rustc 1.89 (`File::lock`). The `ReplayStore` trait is `last_seen(scope, key)` and `record(scope, key, seq)`.

## Seen messages

`VerifiedMessage::key()` returns a `MessageKey { author: PrincipalId, message_id }`, the one spelling of a message's identity. The crate keeps no seen set: it needs durable storage and a retention policy that belong to the consumer, and a Message is legitimately redelivered inside a new Delivery with a fresh sequence. Drop already-seen keys before rendering.

## Rendering

`render(&verified_delivery, &self_id, trust)` renders every message in signed order, joined by `"\n"`. `render_message(&view, self_id, trust, version)` renders one `MessageView` (from `VerifiedMessage::view()` or a caller's own log) at a stated version; an unknown version is `UnknownRenderVersion(v)`. `RENDER_VERSION` is `1`: store it with each logged message and re-render with the stored version. `render_message` validates the view by the same Message rules and refuses with `InvalidMessage`.

One message is:

```
<incoming-message id="..." from="..." to="..." via="..." [reply-to="..."] [references="..."] [mentions="..." [mentions-you="true"]] trust="verified|relayed|unverified">body</incoming-message>
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

## Shared vectors

`vectors/delivery.json` is generated by `vectors/gen.py` (`cryptography==44.0.2`, independent of the Rust code). Run it with `.venv/bin/python -I vectors/gen.py`; it writes `vectors/delivery.json` next to itself. The file is `{"cases": [...]}`; each case has `name`, `trusted` (principal ids), `self_id`, `own_devices` (hex public keys), `meta`, `prior_sequences` (`{scope, key, last}`), `now_unix`, `max_age_secs`, `transcript_hex` (the signed delivery transcript, or null when `meta` is hand-built) and `expected`: `{"ok": {"messages": [{author, message_id}], "render": ...}}`, `{"none": true}` or `{"error": "<AttestationError variant>"}`. A consumer loads the file and asserts every case; see `tests/vectors.rs`. A mismatch is decided against the schema, never by regenerating the file to match Rust.
