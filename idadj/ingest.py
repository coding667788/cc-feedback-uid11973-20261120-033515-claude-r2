"""Ingest command: whole-batch validation and atomic commit.

A batch is either committed entirely (exactly one new system transaction
number is minted) or rejected entirely with the full deterministic list of
validation errors. Nothing partial is ever visible to queries.
"""

import json
from datetime import date

from .encoding import canonical_dumps, content_hash
from .errors import (
    AdjError,
    AUTHORITY_OVERLAP,
    BAD_CONCLUSION,
    BAD_DATE,
    BAD_FORMAT,
    BAD_INTERVAL,
    BATCH_ID_CONFLICT,
    CROSS_SOURCE_REFERENCE,
    DANGLING_REFERENCE,
    EVENT_CONFLICT,
    PARALLEL_REWRITE,
    SEQ_DUPLICATE,
    SEQ_GAP,
    SOURCE_IMPERSONATION,
    UNKNOWN_SOURCE,
)
from .replay import replay
from .storage import advance_txn, next_txn, verify_event_signature

CONCLUSIONS = ("grant", "revoke")
KINDS = ("grant", "revoke", "correction")
PAYLOAD_FIELDS = (
    "event_id",
    "source",
    "source_seq",
    "person",
    "valid_from",
    "valid_to",
    "conclusion",
    "kind",
    "replaces",
)


def _is_iso_date(value):
    if not isinstance(value, str):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def load_batch(path):
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        return json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdjError(BAD_FORMAT, f"cannot read batch JSON: {exc}") from exc


def _err(code, message, **kw):
    return AdjError(code, message, **kw).to_dict()


def validate_batch(conn, registry, batch):
    """Return ``(new_events, authority_rows, errors)``.

    ``errors`` is an empty list exactly when the batch may be committed.
    """
    errors = []

    if not isinstance(batch, dict):
        return [], [], [_err(BAD_FORMAT, "batch root must be a JSON object")]
    batch_id = batch.get("batch_id")
    if not isinstance(batch_id, str) or not batch_id:
        errors.append(_err(BAD_FORMAT, "batch.batch_id must be a non-empty string"))
    events_in = batch.get("events", [])
    lists_in = batch.get("authority_lists", [])
    if not isinstance(events_in, list):
        errors.append(_err(BAD_FORMAT, "batch.events must be a list"))
        events_in = []
    if not isinstance(lists_in, list):
        errors.append(_err(BAD_FORMAT, "batch.authority_lists must be a list"))
        lists_in = []

    if batch_id:
        row = conn.execute(
            "SELECT 1 FROM batches WHERE batch_id = ?", (batch_id,)
        ).fetchone()
        if row is not None:
            errors.append(
                _err(BATCH_ID_CONFLICT, f"batch_id {batch_id!r} already committed")
            )

    authority_rows, auth_errors = _validate_authority(conn, registry, lists_in)
    errors.extend(auth_errors)

    new_events, event_errors = _validate_events(conn, registry, events_in)
    errors.extend(event_errors)

    if not errors:
        lineage_errors = _validate_lineage(conn, new_events)
        errors.extend(lineage_errors)

    return new_events, authority_rows, errors


def _validate_authority(conn, registry, lists_in):
    rows, errors = [], []
    seen_ranges = {}  # area -> list of (from, to) within this batch
    seen_identical = set()
    for idx, entry in enumerate(lists_in):
        if not isinstance(entry, dict):
            errors.append(_err(BAD_FORMAT, f"authority_lists[{idx}] must be an object"))
            continue
        area = entry.get("area")
        valid_from = entry.get("valid_from")
        valid_to = entry.get("valid_to")
        sources = entry.get("sources")
        if not isinstance(area, str) or not area:
            errors.append(_err(BAD_FORMAT, f"authority_lists[{idx}].area invalid"))
            continue
        if not _is_iso_date(valid_from):
            errors.append(
                _err(BAD_DATE, f"authority_lists[{idx}].valid_from invalid date")
            )
            continue
        if valid_to is not None and not _is_iso_date(valid_to):
            errors.append(
                _err(BAD_DATE, f"authority_lists[{idx}].valid_to invalid date")
            )
            continue
        if valid_to is not None and not valid_from < valid_to:
            errors.append(
                _err(BAD_INTERVAL, f"authority_lists[{idx}] needs valid_from < valid_to")
            )
            continue
        if not isinstance(sources, list) or not sources or not all(
            isinstance(s, str) and s for s in sources
        ):
            errors.append(
                _err(BAD_FORMAT, f"authority_lists[{idx}].sources must be a non-empty list")
            )
            continue
        for source in sources:
            if source not in registry:
                errors.append(
                    _err(
                        UNKNOWN_SOURCE,
                        f"authority_lists[{idx}] names unregistered source {source!r}",
                        source=source,
                    )
                )
        deduped = sorted(set(sources))
        key = (area, valid_from, valid_to, tuple(deduped))
        if key in seen_identical:
            continue
        for prev_from, prev_to in seen_ranges.setdefault(area, []):
            if _half_open_overlap(valid_from, valid_to, prev_from, prev_to):
                errors.append(
                    _err(
                        AUTHORITY_OVERLAP,
                        f"two authority versions for {area!r} overlap inside the batch",
                    )
                )
                break
        else:
            seen_ranges[area].append((valid_from, valid_to))
            seen_identical.add(key)
            rows.append(
                {
                    "area": area,
                    "valid_from": valid_from,
                    "valid_to": valid_to,
                    "source_list": json.dumps(deduped, sort_keys=True),
                }
            )
    return rows, errors


def _half_open_overlap(a_lo, a_hi, b_lo, b_hi):
    if a_hi is not None and b_lo >= a_hi:
        return False
    if b_hi is not None and a_lo >= b_hi:
        return False
    return True


def _validate_events(conn, registry, events_in):
    errors = []
    new_events = []
    in_batch_ids = {}       # event_id -> canonical payload (first occurrence)
    in_batch_pairs = set()  # (source, source_seq)
    per_source_seqs = {}    # source -> list of new seqs in this batch
    db_ids = {
        row["event_id"]: row["payload_hash"]
        for row in conn.execute(
            "SELECT event_id, payload_hash FROM events"
        ).fetchall()
    }
    db_pairs = {
        (row["source"], row["source_seq"]): row["event_id"]
        for row in conn.execute(
            "SELECT event_id, source, source_seq FROM events"
        ).fetchall()
    }

    for raw in events_in:
        ev_errs, event = _check_one_event(registry, raw)
        errors.extend(ev_errs)
        if event is None:
            continue
        eid = event["event_id"]
        pair = (event["source"], event["source_seq"])

        if eid in in_batch_ids:
            if in_batch_ids[eid] != canonical_dumps(event["payload"]):
                errors.append(
                    _err(
                        EVENT_CONFLICT,
                        f"event {eid!r} appears twice in the batch with different content",
                        event_id=eid,
                        source=event["source"],
                        source_seq=event["source_seq"],
                    )
                )
            # Same ID + same content: record only once.
            continue
        in_batch_ids[eid] = canonical_dumps(event["payload"])

        if eid in db_ids:
            if db_ids[eid] != event["payload_hash"]:
                errors.append(
                    _err(
                        EVENT_CONFLICT,
                        f"event {eid!r} already committed with different content",
                        event_id=eid,
                        source=event["source"],
                        source_seq=event["source_seq"],
                    )
                )
            # Same ID + same content: idempotent replay, not inserted again.
            continue

        if pair in in_batch_pairs:
            errors.append(
                _err(
                    SEQ_DUPLICATE,
                    f"source {event['source']} reuses sequence {event['source_seq']}"
                    " inside the batch",
                    event_id=eid,
                    source=event["source"],
                    source_seq=event["source_seq"],
                )
                )
            continue
        if pair in db_pairs:
            errors.append(
                _err(
                    SEQ_DUPLICATE,
                    f"source {event['source']} sequence {event['source_seq']}"
                    f" already used by committed event {db_pairs[pair]!r}",
                    event_id=eid,
                    source=event["source"],
                    source_seq=event["source_seq"],
                )
            )
            continue

        in_batch_pairs.add(pair)
        per_source_seqs.setdefault(event["source"], []).append(event["source_seq"])
        new_events.append(event)

    # Per-source sequence-gap checks against the committed stream.
    for source, seqs in sorted(per_source_seqs.items()):
        seqs_sorted = sorted(seqs)
        for prev, cur in zip(seqs_sorted, seqs_sorted[1:]):
            if cur != prev + 1:
                errors.append(
                    _err(
                        SEQ_GAP,
                        f"source {source} has a sequence gap inside the batch"
                        f" ({prev} -> {cur})",
                        source=source,
                        source_seq=cur,
                    )
                )
        max_db = conn.execute(
            "SELECT MAX(source_seq) AS m FROM events WHERE source = ?", (source,)
        ).fetchone()["m"]
        if max_db is not None and seqs_sorted and seqs_sorted[0] != max_db + 1:
            errors.append(
                _err(
                    SEQ_GAP,
                    f"source {source} batch starts at {seqs_sorted[0]} but the"
                    f" committed stream ends at {max_db}",
                    source=source,
                    source_seq=seqs_sorted[0],
                )
            )
    return new_events, errors


def _check_one_event(registry, raw):
    """Validate envelope + payload of one event; return (errors, event)."""
    errors = []
    if not isinstance(raw, dict):
        return [_err(BAD_FORMAT, "each event must be a JSON object")], None
    event_id = raw.get("event_id")
    source = raw.get("source")
    source_seq = raw.get("source_seq")
    payload = raw.get("payload")
    payload_hash = raw.get("payload_hash")
    signature = raw.get("signature")

    for field, value in (
        ("event_id", event_id),
        ("source", source),
    ):
        if not isinstance(value, str) or not value:
            errors.append(_err(BAD_FORMAT, f"event.{field} must be a non-empty string"))
    if not isinstance(source_seq, int) or isinstance(source_seq, bool) or source_seq < 1:
        errors.append(_err(BAD_FORMAT, "event.source_seq must be a positive integer"))
    if not isinstance(payload, dict):
        errors.append(_err(BAD_FORMAT, "event.payload must be an object"))
        return errors, None
    missing = [f for f in PAYLOAD_FIELDS if f not in payload]
    if missing:
        errors.append(
            _err(BAD_FORMAT, f"payload missing fields: {', '.join(sorted(missing))}")
        )
        return errors, None

    # Envelope/payload consistency. A forged source claim is impersonation.
    if isinstance(source, str) and payload.get("source") != source:
        errors.append(
            _err(
                SOURCE_IMPERSONATION,
                f"envelope source {source!r} does not match payload source "
                f"{payload.get('source')!r}",
                event_id=event_id if isinstance(event_id, str) else None,
                source=source if isinstance(source, str) else None,
            )
        )
    if payload.get("event_id") != event_id:
        errors.append(
            _err(BAD_FORMAT, "envelope event_id does not match payload",
                 event_id=event_id if isinstance(event_id, str) else None)
        )
    if payload.get("source_seq") != source_seq:
        errors.append(
            _err(BAD_FORMAT, "envelope source_seq does not match payload",
                 event_id=event_id if isinstance(event_id, str) else None,
                 source=source if isinstance(source, str) else None)
        )

    valid_from = payload.get("valid_from")
    valid_to = payload.get("valid_to")
    if not _is_iso_date(valid_from):
        errors.append(_err(BAD_DATE, "payload.valid_from invalid ISO date",
                           event_id=event_id if isinstance(event_id, str) else None))
    elif valid_to is not None:
        if not _is_iso_date(valid_to):
            errors.append(_err(BAD_DATE, "payload.valid_to invalid ISO date",
                               event_id=event_id if isinstance(event_id, str) else None))
        elif not valid_from < valid_to:
            errors.append(_err(BAD_INTERVAL, "payload needs valid_from < valid_to",
                               event_id=event_id if isinstance(event_id, str) else None))

    kind = payload.get("kind")
    conclusion = payload.get("conclusion")
    if kind not in KINDS:
        errors.append(_err(BAD_FORMAT, f"kind must be one of {KINDS}",
                           event_id=event_id if isinstance(event_id, str) else None))
    if conclusion not in CONCLUSIONS:
        errors.append(_err(BAD_CONCLUSION, f"conclusion must be one of {CONCLUSIONS}",
                           event_id=event_id if isinstance(event_id, str) else None))
    replaces = payload.get("replaces")
    if kind == "correction":
        if not isinstance(replaces, str) or not replaces:
            errors.append(_err(BAD_FORMAT, "correction requires a non-null 'replaces'",
                               event_id=event_id if isinstance(event_id, str) else None))
        # A correction's replacement range must itself be finite.
        if valid_to is None:
            errors.append(_err(BAD_INTERVAL, "correction range must have a valid_to",
                               event_id=event_id if isinstance(event_id, str) else None))
    elif replaces is not None:
        errors.append(_err(BAD_FORMAT, f"{kind} events must not carry 'replaces'",
                           event_id=event_id if isinstance(event_id, str) else None))
    if not isinstance(payload.get("person"), str) or not payload.get("person"):
        errors.append(_err(BAD_FORMAT, "payload.person must be a non-empty string",
                           event_id=event_id if isinstance(event_id, str) else None))

    if not isinstance(payload_hash, str) or not payload_hash:
        errors.append(_err(BAD_FORMAT, "event.payload_hash must be a string",
                           event_id=event_id if isinstance(event_id, str) else None))
    elif content_hash(payload) != payload_hash:
        errors.append(_err("bad_hash", "payload_hash mismatch",
                           event_id=event_id if isinstance(event_id, str) else None,
                           source=source if isinstance(source, str) else None))
    if not isinstance(signature, str) or not signature:
        errors.append(_err(BAD_FORMAT, "event.signature must be a string",
                           event_id=event_id if isinstance(event_id, str) else None))
    elif isinstance(source, str) and source in registry:
        try:
            verify_event_signature(
                registry,
                {
                    "event_id": event_id,
                    "source": source,
                    "source_seq": source_seq,
                    "payload": payload,
                    "payload_hash": payload_hash,
                    "signature": signature,
                },
            )
        except AdjError as exc:
            errors.append(exc.to_dict())

    if errors:
        return errors, None
    return [], {
        "event_id": event_id,
        "source": source,
        "source_seq": source_seq,
        "payload": payload,
        "payload_hash": payload_hash,
        "signature": signature,
    }


def _validate_lineage(conn, new_events):
    """Replay committed + batch events to catch reference/lineage errors."""
    if not new_events:
        return []
    persons = {ev["payload"]["person"] for ev in new_events}
    placeholders = ",".join("?" for _ in persons)
    rows = conn.execute(
        f"SELECT event_id, source, source_seq, person, valid_from, valid_to,"
        f" conclusion, kind, replaces, txn FROM events"
        f" WHERE person IN ({placeholders}) ORDER BY source, source_seq",
        tuple(sorted(persons)),
    ).fetchall()
    combined = [dict(row) for row in rows]
    placeholder_txn = next_txn(conn)
    for ev in new_events:
        p = ev["payload"]
        combined.append(
            {
                "event_id": ev["event_id"],
                "source": ev["source"],
                "source_seq": ev["source_seq"],
                "person": p["person"],
                "valid_from": p["valid_from"],
                "valid_to": p["valid_to"],
                "conclusion": p["conclusion"],
                "kind": p["kind"],
                "replaces": p["replaces"],
                "txn": placeholder_txn,
            }
        )

    # Parallel rewrite: two corrections of this batch replacing the same
    # parent event.
    targets = {}
    for ev in new_events:
        p = ev["payload"]
        if p["kind"] == "correction":
            if p["replaces"] in targets:
                return [
                    _err(
                        PARALLEL_REWRITE,
                        f"events {targets[p['replaces']]!r} and {ev['event_id']!r}"
                        f" both rewrite segment {p['replaces']!r} in the same batch",
                        event_id=ev["event_id"],
                        source=ev["source"],
                        source_seq=ev["source_seq"],
                    )
                ]
            targets[p["replaces"]] = ev["event_id"]

    combined.sort(key=lambda e: (e["source"], e["source_seq"]))
    batch_ids = {ev["event_id"] for ev in new_events}
    try:
        replay(combined)
    except AdjError as exc:
        d = exc.to_dict()
        # A dangling target that the batch itself defines later is still
        # dangling: references may only point at earlier sequence numbers.
        if d.get("event_id") not in batch_ids and d["code"] == DANGLING_REFERENCE:
            return []
        return [d]
    return []


def commit_batch(conn, batch, new_events, authority_rows):
    """Atomically persist a validated batch under one new transaction number."""
    txn = advance_txn(conn)
    for ev in new_events:
        p = ev["payload"]
        conn.execute(
            "INSERT INTO events(event_id, source, source_seq, person, valid_from,"
            " valid_to, conclusion, kind, replaces, payload_hash, txn, payload_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ev["event_id"],
                ev["source"],
                ev["source_seq"],
                p["person"],
                p["valid_from"],
                p["valid_to"],
                p["conclusion"],
                p["kind"],
                p["replaces"],
                ev["payload_hash"],
                txn,
                canonical_dumps(ev["payload"]).decode("utf-8"),
            ),
        )
    for row in authority_rows:
        conn.execute(
            "INSERT INTO authority_lists(area, valid_from, valid_to, source_list, txn)"
            " VALUES (?, ?, ?, ?, ?)",
            (row["area"], row["valid_from"], row["valid_to"], row["source_list"], txn),
        )
    conn.execute(
        "INSERT INTO batches(batch_id, txn, committed_json, content_hash)"
        " VALUES (?, ?, ?, ?)",
        (
            batch["batch_id"],
            txn,
            canonical_dumps(batch).decode("utf-8"),
            content_hash(batch),
        ),
    )
    conn.commit()
    return txn


def ingest(conn, registry, batch):
    """Validate then commit; return a result dict for CLI output."""
    new_events, authority_rows, errors = validate_batch(conn, registry, batch)
    if errors:
        return {"status": "rejected", "errors": errors}
    txn = commit_batch(conn, batch, new_events, authority_rows)
    return {
        "status": "committed",
        "batch_id": batch["batch_id"],
        "txn": txn,
        "events_committed": len(new_events),
        "authority_versions_committed": len(authority_rows),
    }
