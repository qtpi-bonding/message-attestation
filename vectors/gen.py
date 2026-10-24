"""Independent DeliveryAttestation vectors.

Copy-adapted from identity-crypto/vectors/gen.py (its u32/u64/i64/i32/text/var/key
helpers, the delivery_attestation layout, and the deterministic P-256 signer).
The signed transcript is encoded here without any protobuf or Rust code. Each
case's attestation is written into `meta` as its proto3-JSON object (the pbjson
form the Rust crate decodes), computed from the same field values as the transcript.
"""
import base64
import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

HERE = Path(__file__).resolve().parent
META_KEY = "message-attestation/v1"
SCHEME_NAME = "KEY_SCHEME_ECDSA_P256"  # pbjson writes the enum by name


class VectorError(Exception):
    def __init__(self, variant, field=None):
        super().__init__(variant, field)
        self.variant, self.field = variant, field


def private(i):
    return ec.derive_private_key(i, ec.SECP256R1())


def raw_pub(i):
    return private(i).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


# ---- transcript (the signed bytes; must match identity-crypto's delivery_attestation) ----


def var(b):
    return struct.pack(">I", len(b)) + b


def text(s):
    return var(s.encode("utf-8"))


def u64(v):
    return struct.pack(">Q", int(v))


def i64(v):
    return struct.pack(">q", int(v))


def i32(v):
    return struct.pack(">i", int(v))


def u32(v):
    return struct.pack(">I", int(v))


def key_transcript(i):
    """KEY := scheme u8 ‖ len(bytes) ‖ SEC1 uncompressed point."""
    return b"\x03" + u32(65) + raw_pub(i)


def cert_body(c):
    mode = int(c["mode"])
    if mode not in (0, 1):
        raise VectorError("InvalidField", "mode")
    p = key_transcript(c["principal"])
    host, subject = c["host"], c["subject"]
    if mode == 0:
        if host is not None:
            raise VectorError("InvalidField", "host_genesis")
        if subject is not None:
            raise VectorError("InvalidField", "subject")
        host_b, subject_b = b"\x00", b"\x00"
    else:
        if host is None:
            raise VectorError("MissingField", "host_genesis")
        host_b = b"\x01" + key_transcript(host)
        if not subject:
            raise VectorError("InvalidField", "subject")
        subject_b = b"\x01" + text(subject)
    device, session = key_transcript(c["device"]), key_transcript(c["session"])
    if device == session:
        raise VectorError("NotDistinct", "device, session")
    return bytes([mode]) + p + host_b + subject_b + device + session + i64(c["not_before"]) + i64(c["not_after"])


def delivery_attestation_transcript(a):
    out = b"identitycrypto.delivery-attestation.v1\x00" + u32(len(a["recipients"]))
    for r in a["recipients"]:
        out += key_transcript(r)
    out += text(a["key_id"]) + u64(a["sequence"])
    out += i64(a["seconds"]) + i32(a["nanos"]) + u32(len(a["messages"]))
    for m in a["messages"]:
        out += text(m["message_id"]) + text(m["room_id"])
        if m["author"] is None:
            raise VectorError("MissingField", "messages.author_genesis")
        out += key_transcript(m["author"]) + text(m["body_text"])
        if m["cert"] is None:
            raise VectorError("MissingField", "messages.delegation_cert")
        sig = bytes.fromhex(m["cert"]["signature"])
        out += cert_body(m["cert"]) + var(sig)
    return out


def sign(a, signer):
    der = private(signer).sign(
        delivery_attestation_transcript(a), ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
    )
    r, s = decode_dss_signature(der)
    a["signature"] = r.to_bytes(32, "big") + s.to_bytes(32, "big")


# ---- proto3-JSON (pbjson): what goes in `_meta`. Defaults are omitted, as pbjson does. ----


def b64(b):
    return base64.b64encode(b).decode("ascii")


def rfc3339(seconds, nanos):
    """RFC 3339 with Z, 0/3/6/9 fractional digits (chrono AutoSi, as the crate writes it)."""
    stamp = datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    if nanos == 0:
        frac = ""
    elif nanos % 1_000_000 == 0:
        frac = f".{nanos // 1_000_000:03d}"
    elif nanos % 1_000 == 0:
        frac = f".{nanos // 1_000:06d}"
    else:
        frac = f".{nanos:09d}"
    return stamp + frac + "Z"


def pb_key(i):
    return {"scheme": SCHEME_NAME, "key": b64(raw_pub(i))}


def pb_cert(c):
    out = {
        "principalGenesis": pb_key(c["principal"]),
        "device": pb_key(c["device"]),
        "session": pb_key(c["session"]),
        "notBeforeUnixSeconds": str(c["not_before"]),
        "notAfterUnixSeconds": str(c["not_after"]),
        "signature": b64(bytes.fromhex(c["signature"])),
    }
    if int(c["mode"]) != 0:
        out["mode"] = int(c["mode"])
    if c["host"] is not None:
        out["hostGenesis"] = pb_key(c["host"])
    if c["subject"] is not None:
        out["subject"] = c["subject"]
    return out


def pb_message(m):
    out = {"messageId": m["message_id"], "roomId": m["room_id"], "bodyText": m["body_text"]}
    if m["author"] is not None:
        out["authorGenesis"] = pb_key(m["author"])
    if m["cert"] is not None:
        out["delegationCert"] = pb_cert(m["cert"])
    return {k: v for k, v in out.items() if v != ""}


def pb_attestation(a):
    out = {
        "keyId": a["key_id"],
        "batchSequence": str(a["sequence"]),
        "attestedAt": rfc3339(a["seconds"], a["nanos"]),
        "messages": [pb_message(m) for m in a["messages"]],
        "signature": b64(a["signature"]),
        "recipientDevices": [pb_key(r) for r in a["recipients"]],
    }
    return {k: v for k, v in out.items() if v not in ("", "0", [], None)}


# ---- cases ----

DEFAULT_CERT = {"principal": 2, "mode": 0, "device": 3, "session": 4, "host": None, "subject": None,
                "not_before": 1699990000, "not_after": 1700010000, "signature": "ab" * 64}
MODE1_CERT = {"principal": 2, "mode": 1, "device": 3, "session": 4, "host": 5,
              "subject": "agent/one", "not_before": 1699990000, "not_after": 1700010000,
              "signature": "ab" * 64}


def msg(author=2, body="hello", cert=DEFAULT_CERT):
    return {"message_id": "m-1", "room_id": "room-1", "body_text": body, "author": author, "cert": cert}


def base(messages=None, sequence=7, key_id="delivery-1", seconds=1700000000):
    return {"key_id": key_id, "sequence": sequence, "seconds": seconds, "nanos": 123,
            "recipients": [15, 16], "messages": messages if messages is not None else [msg()]}


def expected_ok(a):
    messages = [{"message_id": m["message_id"], "room_id": m["room_id"], "body_text": m["body_text"],
                 "author_genesis_hex": raw_pub(m["author"]).hex()} for m in a["messages"]]
    return {"ok": {"key_id": a["key_id"], "batch_sequence": a["sequence"],
                   "attested_at_unix": a["seconds"], "messages": messages}}


def make_case(name, a, error=None, trusted=None, own=None, now=None, max_age=None, prior=None, scope="vector"):
    if trusted is None:
        trusted = {"delivery-1": raw_pub(10).hex()}
    if own is None:
        own = [raw_pub(15).hex()]
    if error == "Transcript":
        # The independent encoder must refuse these too; the vector carries no transcript.
        try:
            delivery_attestation_transcript(a)
        except VectorError:
            pass
        else:
            raise AssertionError(f"{name}: transcript must reject")
        transcript_hex = None
    else:
        transcript_hex = delivery_attestation_transcript(a).hex() if a["messages"] else None
    return {"name": name, "trusted": trusted, "own_devices": own,
            "meta": {META_KEY: pb_attestation(a)},
            "prior_sequences": prior or [], "scope": scope, "now_unix": now,
            "max_age_secs": max_age, "transcript_hex": transcript_hex,
            "expected": {"error": error} if error else expected_ok(a)}


def main():
    cases = []
    genuine = base([msg()]); sign(genuine, 10)
    cases.append(make_case("genuine", genuine))

    tampered = dict(genuine); tampered["messages"] = [msg(body="tampered")]; tampered["signature"] = genuine["signature"]
    cases.append(make_case("tampered body", tampered, error="BadSignature"))

    wrong = dict(genuine); wrong["key_id"] = "unknown"; wrong["signature"] = genuine["signature"]
    cases.append(make_case("wrong key id", wrong, error="UnknownKeyId"))

    cases.append(make_case("not a recipient", genuine, own=[raw_pub(99).hex()], error="NotARecipient"))

    cases.append(make_case("replay", genuine, error="Replay",
                           prior=[{"scope": "vector", "key_id": "delivery-1", "last": 7}]))

    cases.append(make_case("stale without a window", genuine, now=1700001000))
    cases.append(make_case("stale with a window", genuine, now=1700001000, max_age=10, error="Stale"))

    nested = make_case("nested meta key", genuine)
    nested["meta"] = {"x": {META_KEY: pb_attestation(genuine)}}
    nested["expected"] = {"none": True}
    nested["transcript_hex"] = None
    cases.append(nested)

    empty = base([], sequence=8); sign(empty, 10)
    cases.append(make_case("empty messages", empty, error="EmptyMessages"))

    delegated = base([msg(2, cert=MODE1_CERT)], sequence=9); sign(delegated, 10)
    cases.append(make_case("delegated with mode 1 cert", delegated))

    untrusted = base([msg()], key_id="other-key"); sign(untrusted, 11)
    cases.append(make_case("untrusted signing key", untrusted, trusted={"other-key": raw_pub(10).hex()},
                           error="BadSignature"))

    # Missing fields cannot be signed (the transcript refuses them), so the signature is arbitrary.
    no_author = base([msg(author=None)]); no_author["signature"] = b"\x11" * 64
    cases.append(make_case("author missing", no_author, error="Transcript"))

    no_cert = base([msg(cert=None)]); no_cert["signature"] = b"\x11" * 64
    cases.append(make_case("delegation cert missing", no_cert, error="Transcript"))

    defaults = base([msg()], sequence=0, key_id=""); sign(defaults, 10)
    cases.append(make_case("all defaults", defaults, trusted={"": raw_pub(10).hex()}))

    Path(HERE / "attestation.json").write_text(json.dumps({"cases": cases}, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
