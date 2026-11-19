"""SQLite persistence: schema, source registry and transaction bookkeeping.

The database stores only immutable committed facts:

* ``events``          - every accepted credential/correction event;
* ``authority_lists`` - every accepted area authority-list version;
* ``batches``         - one row per successfully committed input batch.

Derived validity segments are *not* stored: they are replayed from the
immutable event stream on each query (see :mod:`idadj.replay`), so there is
no derived state that could drift from the event log.
"""

import json
import os
import sqlite3

from .encoding import content_hash, verify_signature
from .errors import AdjError, BAD_SIGNATURE, UNKNOWN_SOURCE

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS batches (
    batch_id        TEXT PRIMARY KEY,
    txn             INTEGER NOT NULL,
    committed_json  TEXT NOT NULL,
    content_hash    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sources (
    source_id   TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    secret_key  TEXT NOT NULL,
    created_txn INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    event_id     TEXT PRIMARY KEY,
    source       TEXT NOT NULL,
    source_seq   INTEGER NOT NULL,
    person       TEXT NOT NULL,
    valid_from   TEXT NOT NULL,
    valid_to     TEXT,
    conclusion   TEXT NOT NULL,
    kind         TEXT NOT NULL,
    replaces     TEXT,
    payload_hash TEXT NOT NULL,
    txn          INTEGER NOT NULL,
    payload_json TEXT NOT NULL,
    UNIQUE(source, source_seq)
);
CREATE INDEX IF NOT EXISTS idx_events_person ON events(person);
CREATE INDEX IF NOT EXISTS idx_events_txn ON events(txn);
CREATE TABLE IF NOT EXISTS authority_lists (
    area        TEXT NOT NULL,
    valid_from  TEXT NOT NULL,
    valid_to    TEXT,
    source_list TEXT NOT NULL,
    txn         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_area ON authority_lists(area);
CREATE INDEX IF NOT EXISTS idx_auth_txn ON authority_lists(txn);
"""


def connect(db_path):
    """Open (and if needed create) the adjudications database."""
    fresh = not os.path.exists(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    if fresh:
        conn.execute(
            "INSERT INTO meta(key, value) VALUES ('next_txn', '1')"
        )
        conn.commit()
    return conn


def next_txn(conn):
    row = conn.execute("SELECT value FROM meta WHERE key='next_txn'").fetchone()
    return int(row["value"])


def advance_txn(conn):
    txn = next_txn(conn)
    conn.execute(
        "UPDATE meta SET value=? WHERE key='next_txn'", (str(txn + 1),)
    )
    return txn


# --------------------------------------------------------------------------- #
# Source registry
# --------------------------------------------------------------------------- #

def load_registry(path):
    """Load the department source registry JSON.

    Structure::

        {"sources": [{"source_id", "name", "secret_key"}, ...]}
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or not isinstance(data.get("sources"), list):
        raise AdjError("bad_format", "registry must have a 'sources' array")
    registry = {}
    for entry in data["sources"]:
        for field in ("source_id", "name", "secret_key"):
            if field not in entry:
                raise AdjError(
                    "bad_format", f"registry entry missing {field}"
                )
        registry[entry["source_id"]] = {
            "source_id": entry["source_id"],
            "name": entry["name"],
            "secret_key": entry["secret_key"],
        }
    if not registry:
        raise AdjError("bad_format", "registry contains no sources")
    return registry


def ensure_registry_loaded(conn, registry):
    """Mirror the external registry into the database (idempotent).

    The DB copy lets ``verify`` cross-check signatures offline. Keys are
    only inserted when first seen; existing rows are never overwritten.
    """
    txn = next_txn(conn)
    for source_id, entry in sorted(registry.items()):
        conn.execute(
            "INSERT OR IGNORE INTO sources(source_id, name, secret_key, created_txn)"
            " VALUES (?, ?, ?, ?)",
            (source_id, entry["name"], entry["secret_key"], txn),
        )
    conn.commit()


def verify_event_signature(registry, event):
    """Authenticate an event against its purported source's secret key."""
    source = event["source"]
    entry = registry.get(source)
    if entry is None:
        raise AdjError(
            UNKNOWN_SOURCE,
            f"source {source!r} is not registered",
            event_id=event["event_id"],
            source=source,
            source_seq=event["source_seq"],
        )
    message = json.dumps(
        event["payload"],
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if not verify_signature(entry["secret_key"], message, event["signature"]):
        raise AdjError(
            BAD_SIGNATURE,
            "HMAC signature does not verify against the registered key",
            event_id=event["event_id"],
            source=source,
            source_seq=event["source_seq"],
        )
    if content_hash(event["payload"]) != event["payload_hash"]:
        raise AdjError(
            "bad_hash",
            "payload_hash does not match the canonical payload",
            event_id=event["event_id"],
            source=source,
            source_seq=event["source_seq"],
        )
