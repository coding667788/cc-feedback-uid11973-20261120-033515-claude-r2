"""Canonical JSON, hashing and signing helpers.

All byte-identical outputs in the system (content hashes, HMAC signatures,
CLI JSON) go through :func:`canonical_dumps` so that key ordering and unicode
escaping are fully deterministic across machines and reruns.
"""

import hashlib
import hmac
import json


def canonical_dumps(obj):
    """Serialize *obj* to canonical UTF-8 JSON bytes.

    Keys are sorted, no ASCII escaping, no insignificant whitespace,
    ``ensure_ascii=False`` and ``allow_nan=False`` for strict interchange.
    """
    return json.dumps(
        obj,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def pretty_dumps(obj):
    """Stable human-readable JSON (newline-terminated)."""
    return (
        json.dumps(
            obj,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )


def content_hash(payload):
    """SHA-256 hex digest of the canonical serialization of *payload*."""
    return hashlib.sha256(canonical_dumps(payload)).hexdigest()


def sign(key_hex, message_bytes):
    """HMAC-SHA256 hex signature of *message_bytes* with a hex-encoded key."""
    mac = hmac.new(bytes.fromhex(key_hex), message_bytes, hashlib.sha256)
    return mac.hexdigest()


def verify_signature(key_hex, message_bytes, signature_hex):
    expected = sign(key_hex, message_bytes)
    return hmac.compare_digest(expected, signature_hex)


def event_message(event):
    """The exact bytes covered by an event's HMAC signature."""
    return canonical_dumps(event["payload"])
