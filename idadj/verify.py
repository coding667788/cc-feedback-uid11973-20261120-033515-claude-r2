"""verify command: offline integrity verification.

Two modes:

* ``verify --db ... --registry ...`` re-checks the committed store: hashes,
  HMAC signatures, sequence continuity per source and full replay of every
  person's event stream.
* ``verify --batch path.json --registry ...`` dry-runs all ingest
  validations without touching the database, so a batch can be checked
  before it is published.
"""

import hashlib
import hmac
import json

from .encoding import content_hash, canonical_dumps
from .errors import (
    BAD_HASH,
    SEQ_GAP,
    AdjError,
)
from .ingest import load_batch, validate_batch
from .replay import replay
from .storage import verify_event_signature


def _hmac(secret_key, payload):
    return hmac.new(
        bytes.fromhex(secret_key),
        canonical_dumps(payload),
        hashlib.sha256,
    ).hexdigest()


def verify_store(conn, registry):
    checks = []

    # 1. Per-event hash and signature verification.
    rows = conn.execute(
        "SELECT event_id, source, source_seq, payload_hash, payload_json, txn"
        " FROM events ORDER BY source, source_seq"
    ).fetchall()
    for row in rows:
        payload = json.loads(row["payload_json"])
        if content_hash(payload) != row["payload_hash"]:
            checks.append(
                {
                    "name": "payload_hash",
                    "ok": False,
                    "event_id": row["event_id"],
                    "code": BAD_HASH,
                }
            )
            continue
        try:
            verify_event_signature(
                registry,
                {
                    "event_id": row["event_id"],
                    "source": row["source"],
                    "source_seq": row["source_seq"],
                    "payload": payload,
                    "payload_hash": row["payload_hash"],
                    "signature": _hmac(
                        registry[row["source"]]["secret_key"], payload
                    ),
                },
            )
        except AdjError as exc:
            checks.append(
                {
                    "name": "signature",
                    "ok": False,
                    "event_id": row["event_id"],
                    "code": exc.code,
                    "message": exc.message,
                }
            )
        else:
            checks.append(
                {"name": "hash_and_signature", "ok": True, "event_id": row["event_id"]}
            )

    # 2. Gapless per-source sequences.
    sources = conn.execute(
        "SELECT DISTINCT source FROM events ORDER BY source"
    ).fetchall()
    for (source,) in sources:
        seqs = [
            r["source_seq"]
            for r in conn.execute(
                "SELECT source_seq FROM events WHERE source = ? ORDER BY source_seq",
                (source,),
            ).fetchall()
        ]
        ok = seqs == list(range(1, len(seqs) + 1))
        checks.append(
            {
                "name": "sequence_continuity",
                "ok": ok,
                "source": source,
                **({} if ok else {"code": SEQ_GAP, "sequences": seqs}),
            }
        )

    # 3. Full replay of every person's stream (lineage/correction integrity).
    persons = [
        r["person"]
        for r in conn.execute(
            "SELECT DISTINCT person FROM events ORDER BY person"
        ).fetchall()
    ]
    for person in persons:
        evs = [
            dict(r)
            for r in conn.execute(
                "SELECT event_id, source, source_seq, person, valid_from, valid_to,"
                " conclusion, kind, replaces, txn FROM events"
                " WHERE person = ? ORDER BY source, source_seq",
                (person,),
            ).fetchall()
        ]
        try:
            segments = replay(evs)
        except AdjError as exc:
            checks.append(
                {
                    "name": "replay",
                    "ok": False,
                    "person": person,
                    "code": exc.code,
                    "message": exc.message,
                }
            )
        else:
            checks.append(
                {
                    "name": "replay",
                    "ok": True,
                    "person": person,
                    "segments": len(segments),
                }
            )

    # 4. Transaction bookkeeping.
    used_txns = [
        r["txn"]
        for r in conn.execute("SELECT DISTINCT txn FROM batches ORDER BY txn").fetchall()
    ]
    max_txn = max(used_txns, default=0)
    checks.append(
        {
            "name": "transaction_continuity",
            "ok": used_txns == list(range(1, max_txn + 1)),
            "committed_batches": len(used_txns),
        }
    )

    ok = all(c["ok"] for c in checks)
    return {"command": "verify", "scope": "store", "ok": ok, "checks": checks}


def verify_batch(conn, registry, path):
    batch = load_batch(path)
    new_events, authority_rows, errors = validate_batch(conn, registry, batch)
    return {
        "command": "verify",
        "scope": "batch",
        "batch_id": batch.get("batch_id"),
        "ok": not errors,
        "would_commit_events": len(new_events),
        "would_commit_authority_versions": len(authority_rows),
        "errors": errors,
    }
