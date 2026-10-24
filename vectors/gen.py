"""Independent DeliveryAttestation vectors.

Copy-adapted from identity-crypto/vectors/gen.py (its tag/u32/u64/i64/i32/text/var/key/
cert_body helpers, delivery_attestation layout, and deterministic P-256 signer).
The protobuf encoder below is deliberately independent and uses no protobuf library.
"""
import base64
import json
import struct
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

HERE = Path(__file__).resolve().parent
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

def private(i):
    return ec.derive_private_key(i, ec.SECP256R1())

def raw_pub(i):
    return private(i).public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

def varint(n):
    n = n & ((1 << 64) - 1)
    out = bytearray()
    while n > 127:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)

def field(number, value):
    return varint(number << 3 | 2) + varint(len(value)) + value

def scalar(number, value):
    if value:
        return varint(number << 3) + varint(value)
    return b""

def sint64(value):
    return varint(value)

def key_message(i):
    return scalar(1, 3) + field(2, raw_pub(i))

def cert_body(cert):
    out = struct.pack(">B", cert["mode"]) + key_transcript(cert["principal"])
    if cert["mode"] == 0:
        out += b"\0\0"
    else:
        out += b"\1" + key_transcript(cert["host"])
        subject = cert["subject"].encode()
        out += b"\1" + struct.pack(">I", len(subject)) + subject
    out += key_transcript(cert["device"]) + key_transcript(cert["session"])
    out += struct.pack(">q", cert["not_before"]) + struct.pack(">q", cert["not_after"])
    return out

def key_transcript(i):
    return b"\x03" + struct.pack(">I", 65) + raw_pub(i)

def cert_message(cert):
    out = scalar(4, cert["not_before"]) + scalar(5, cert["not_after"])
    out += field(6, bytes.fromhex(cert["signature"]))
    out += field(7, key_message(cert["principal"])) + scalar(8, cert["mode"])
    out += field(9, key_message(cert["device"])) + field(10, key_message(cert["session"]))
    if cert["mode"] == 1:
        out += field(11, key_message(cert["host"])) + field(12, cert["subject"].encode())
    return out

def timestamp(seconds, nanos=0):
    return scalar(1, seconds) + scalar(2, nanos)

def message_wire(m):
    out = field(1, m["message_id"].encode()) + field(2, m["room_id"].encode())
    out += field(4, m["body_text"].encode()) + scalar(5, m["outcome"])
    if m.get("cert") is not None:
        out += field(6, cert_message(m["cert"]))
    if m.get("author") is not None:
        out += field(7, key_message(m["author"]))
    return out

def wire(a):
    out = field(2, a["key_id"].encode()) + scalar(3, a["sequence"])
    out += field(4, timestamp(a["seconds"], a.get("nanos", 0)))
    for m in a["messages"]:
        out += field(5, message_wire(m))
    out += field(6, a["signature"])
    for recipient in a["recipients"]:
        out += field(7, key_message(recipient))
    return out

def transcript(a):
    out = b"identitycrypto.delivery-attestation.v1\0" + struct.pack(">I", len(a["recipients"]))
    for r in a["recipients"]:
        out += key_transcript(r)
    out += struct.pack(">I", len(a["key_id"].encode())) + a["key_id"].encode()
    out += struct.pack(">Q", a["sequence"])
    out += struct.pack(">q", a["seconds"]) + struct.pack(">i", a.get("nanos", 0))
    out += struct.pack(">I", len(a["messages"]))
    for m in a["messages"]:
        out += struct.pack(">I", len(m["message_id"].encode())) + m["message_id"].encode()
        out += struct.pack(">I", len(m["room_id"].encode())) + m["room_id"].encode()
        author = m.get("author")
        out += b"\0" if author is None else b"\1" + key_transcript(author)
        body = m["body_text"].encode()
        out += struct.pack(">I", len(body)) + body + struct.pack(">i", m["outcome"])
        cert = m.get("cert")
        if cert is None:
            out += b"\0"
        else:
            sig = bytes.fromhex(cert["signature"])
            out += b"\1" + cert_body(cert) + struct.pack(">I", len(sig)) + sig
    return out

def sign(a, signer):
    der = private(signer).sign(transcript(a), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    a["signature"] = r.to_bytes(32, "big") + s.to_bytes(32, "big")

def msg(outcome=1, author=2, body="hello", cert=None):
    return {"message_id": "m-1", "room_id": "room-1", "body_text": body,
            "outcome": outcome, "author": author, "cert": cert}

def base(messages=None, sequence=7, key_id="delivery-1", seconds=1700000000):
    return {"key_id": key_id, "sequence": sequence, "seconds": seconds, "nanos": 123,
            "recipients": [15, 16], "messages": messages if messages is not None else [msg()]}

def expected(a, error=None):
    if error:
        return {"error": error}
    messages = []
    for m in a["messages"]:
        messages.append({"message_id": m["message_id"], "room_id": m["room_id"],
                         "body_text": m["body_text"],
                         "author_genesis_hex": None if m.get("author") is None else raw_pub(m["author"]).hex(),
                         "outcome": m["outcome"], "has_cert": m.get("cert") is not None})
    return {"ok": {"key_id": a["key_id"], "batch_sequence": a["sequence"],
                    "attested_at_unix": a["seconds"], "raw_b64": base64.b64encode(wire(a)).decode(),
                    "messages": messages}}

def make_case(name, a, trusted=None, own=None, now=None, max_age=None, prior=None, scope="vector"):
    if trusted is None:
        trusted = {"delivery-1": raw_pub(10).hex()}
    if own is None:
        own = [raw_pub(15).hex()]
    return {"name": name, "trusted": trusted, "own_devices": own,
            "meta": {"message-attestation/v1": base64.b64encode(wire(a)).decode()},
            "prior_sequences": prior or [], "scope": scope, "now_unix": now,
            "max_age_secs": max_age, "transcript_hex": transcript(a).hex() if a["messages"] else None,
            "expected": expected(a)}

def main():
    cert = {"principal": 2, "mode": 1, "device": 3, "session": 4, "host": 5,
            "subject": "agent/one", "not_before": 1699990000, "not_after": 1700010000,
            "signature": "ab" * 64}
    cases = []
    genuine = base([msg()]); sign(genuine, 10)
    cases.append(make_case("genuine", genuine))
    tampered = dict(genuine); tampered["messages"] = [msg(body="tampered")]; tampered["signature"] = genuine["signature"]
    cases.append(make_case("tampered body", tampered, own=[raw_pub(15).hex()]))
    cases[-1]["expected"] = {"error": "BadSignature"}
    wrong = dict(genuine); wrong["key_id"] = "unknown"; wrong["signature"] = genuine["signature"]
    cases.append(make_case("wrong key id", wrong, trusted={"delivery-1": raw_pub(10).hex()}))
    cases[-1]["expected"] = {"error": "UnknownKeyId"}
    cases.append(make_case("not a recipient", genuine, own=[raw_pub(99).hex()]))
    cases[-1]["expected"] = {"error": "NotARecipient"}
    cases.append(make_case("replay", genuine, prior=[{"scope": "vector", "key_id": "delivery-1", "last": 7}]))
    cases[-1]["expected"] = {"error": "Replay"}
    cases.append(make_case("stale without a window", genuine, now=1700001000))
    cases.append(make_case("stale with a window", genuine, now=1700001000, max_age=10))
    cases[-1]["expected"] = {"error": "Stale"}
    nested = make_case("nested meta key", genuine)
    nested["meta"] = {"x": {"message-attestation/v1": base64.b64encode(wire(genuine)).decode()}}
    nested["expected"] = {"none": True}
    nested["transcript_hex"] = None
    cases.append(nested)
    empty = base([], sequence=8); sign(empty, 10)
    cases.append(make_case("empty messages", empty, own=[raw_pub(15).hex()]))
    cases[-1]["expected"] = {"error": "EmptyMessages"}
    system = base([msg(3, author=None)]); sign(system, 10)
    cases.append(make_case("SYSTEM outcome", system))
    delegated = base([msg(2, author=2, cert=cert)], sequence=9); sign(delegated, 10)
    cases.append(make_case("DELEGATED_KEY with cert", delegated))
    untrusted = base([msg()], key_id="other-key"); sign(untrusted, 11)
    cases.append(make_case("untrusted signing key", untrusted, trusted={"other-key": raw_pub(10).hex()}))
    cases[-1]["expected"] = {"error": "BadSignature"}
    Path(HERE / "attestation.json").write_text(json.dumps({"cases": cases}, indent=2, sort_keys=True) + "\n")

if __name__ == "__main__":
    main()
