"""Replay the immutable event stream into current validity segments.

A *segment* is a half-open validity interval ``[lo, hi)`` (``hi is None``
means open-ended) currently "owned" by one event. A base event
(``grant``/``revoke``) initially owns its whole interval. A correction event
splits the segments owned by its target event inside its replacement range:
pieces outside the range keep the old owner (and therefore the old
conclusion), the piece inside it gets a new owner and the new conclusion.

Replay is pure: given the same event list it always yields identical
segments, which is what makes historical answers at old transaction numbers
byte-reproducible.
"""

import json

from .errors import (
    AdjError,
    CORRECTION_OUT_OF_COVERAGE,
    CROSS_SOURCE_REFERENCE,
    DANGLING_REFERENCE,
    STALE_REFERENCE,
)


def _overlaps(lo, hi, seg):
    """Whether half-open ``[lo, hi)`` (hi may be None) overlaps segment."""
    if not (seg["lo"] < hi):
        return False
    if seg["hi"] is None:
        return True
    return lo < seg["hi"]


def _contains(seg, day):
    if day < seg["lo"]:
        return False
    return seg["hi"] is None or day < seg["hi"]


def replay(events):
    """Replay *events* and return the resulting list of segments.

    *events* must be ordered by ``(source, source_seq)``. Each event is a
    dict with ``kind`` in ``grant|revoke|correction``. Lineage violations
    raise :class:`AdjError`; ``parallel_rewrite`` is checked separately by
    the ingest validator.
    """
    by_person = {}
    for ev in events:
        by_person.setdefault(ev["person"], []).append(ev)

    all_segments = []
    for person in sorted(by_person):
        segments = []
        known = {}  # event_id -> event, for reference resolution
        for ev in by_person[person]:
            known[ev["event_id"]] = ev
            if ev["kind"] in ("grant", "revoke"):
                segments.append(_new_segment(ev, ev["valid_from"], ev["valid_to"]))
                continue

            # correction --------------------------------------------------
            target = known.get(ev["replaces"])
            if target is None:
                raise AdjError(
                    DANGLING_REFERENCE,
                    f"correction {ev['event_id']} references unknown event "
                    f"{ev['replaces']!r}",
                    event_id=ev["event_id"],
                    source=ev["source"],
                    source_seq=ev["source_seq"],
                )
            if target["source"] != ev["source"]:
                raise AdjError(
                    CROSS_SOURCE_REFERENCE,
                    f"correction {ev['event_id']} targets event "
                    f"{ev['replaces']} of another source",
                    event_id=ev["event_id"],
                    source=ev["source"],
                    source_seq=ev["source_seq"],
                )
            if target["person"] != ev["person"]:
                raise AdjError(
                    STALE_REFERENCE,
                    f"correction {ev['event_id']} targets an event belonging "
                    f"to another person",
                    event_id=ev["event_id"],
                    source=ev["source"],
                    source_seq=ev["source_seq"],
                )

            lo, hi = ev["valid_from"], ev["valid_to"]
            _check_coverage(ev, lo, hi, segments)

            replaced = []
            for seg in segments:
                if seg["owner_event"] == ev["replaces"] and _overlaps(lo, hi, seg):
                    # Left piece outside the replacement range keeps owner.
                    if seg["lo"] < lo:
                        replaced.append(_inherit(seg, seg["lo"], lo))
                    # Middle piece is taken over by the correction.
                    mid_lo = max(seg["lo"], lo)
                    mid_hi = hi if seg["hi"] is None else min(seg["hi"], hi)
                    replaced.append(_new_segment(ev, mid_lo, mid_hi))
                    # Right piece outside the replacement range keeps owner.
                    if seg["hi"] is None:
                        replaced.append(_inherit(seg, hi, None))
                    elif seg["hi"] > hi:
                        replaced.append(_inherit(seg, hi, seg["hi"]))
                else:
                    replaced.append(seg)
            segments = replaced
        all_segments.extend(segments)
    return all_segments


def _check_coverage(ev, lo, hi, segments):
    """Every point of [lo, hi) must be a live piece owned by the target."""
    cursor = lo
    owners = [
        seg
        for seg in segments
        if _overlaps(lo, hi, seg)
    ]
    owners.sort(key=lambda s: (s["lo"], s["hi"] is None, s["hi"]))
    for seg in owners:
        if seg["lo"] > cursor:
            raise AdjError(
                CORRECTION_OUT_OF_COVERAGE,
                f"correction {ev['event_id']} replaces range starting at "
                f"{cursor} that no live segment covers",
                event_id=ev["event_id"],
                source=ev["source"],
                source_seq=ev["source_seq"],
            )
        if seg["owner_event"] != ev["replaces"]:
            raise AdjError(
                STALE_REFERENCE,
                f"correction {ev['event_id']} targets "
                f"{ev['replaces']!r}, but {seg['lo']}..{seg['hi']} is now "
                f"owned by {seg['owner_event']} (consecutive corrections must "
                f"point at the current version of the segment)",
                event_id=ev["event_id"],
                source=ev["source"],
                source_seq=ev["source_seq"],
            )
        if seg["hi"] is None:
            cursor = hi
            break
        cursor = max(cursor, seg["hi"])
        if cursor >= hi:
            break
    if cursor < hi:
        raise AdjError(
            CORRECTION_OUT_OF_COVERAGE,
            f"correction {ev['event_id']} replaces range ending at {hi} that "
            "no live segment covers",
            event_id=ev["event_id"],
            source=ev["source"],
            source_seq=ev["source_seq"],
        )


def _new_segment(ev, lo, hi):
    return {
        "lo": lo,
        "hi": hi,
        "owner_event": ev["event_id"],
        "source": ev["source"],
        "source_seq": ev["source_seq"],
        "conclusion": ev["conclusion"],
        "person": ev["person"],
        "txn": ev["txn"],
    }


def _inherit(seg, lo, hi):
    child = dict(seg)
    child["lo"], child["hi"] = lo, hi
    return child


def visible_events(conn, person, k):
    """Committed events for *person* visible at transaction *k*."""
    rows = conn.execute(
        "SELECT event_id, source, source_seq, person, valid_from, valid_to,"
        " conclusion, kind, replaces, txn FROM events"
        " WHERE person = ? AND txn <= ?"
        " ORDER BY source ASC, source_seq ASC",
        (person, k),
    ).fetchall()
    return [dict(row) for row in rows]


def segments_for_person(conn, person, k):
    return replay(visible_events(conn, person, k))


def conclusion_for_source(segments, source, day):
    """Pick the live segment of *source* covering *day*.

    Two base events of the same source may overlap; the event with the
    greatest source sequence wins (deterministic tie-break).
    """
    candidates = [
        seg
        for seg in segments
        if seg["source"] == source and _contains(seg, day)
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda s: (-s["source_seq"], s["owner_event"]))
    return candidates[0]


# --------------------------------------------------------------------------- #
# Versioned authority lists
# --------------------------------------------------------------------------- #

def visible_authority_rows(conn, area, k):
    rows = conn.execute(
        "SELECT area, valid_from, valid_to, source_list, txn"
        " FROM authority_lists WHERE area = ? AND txn <= ?"
        " ORDER BY valid_from ASC, txn ASC",
        (area, k),
    ).fetchall()
    return [dict(row) for row in rows]


def authority_on_day(rows, day):
    """Return the sorted source list governing *area* on business *day*.

    ``None`` means no published list covers that day (the area has no
    competent departments under the D/K constraints).
    """
    covering = [
        row
        for row in rows
        if row["valid_from"] <= day
        and (row["valid_to"] is None or day < row["valid_to"])
    ]
    if not covering:
        return None
    # Ingest rejects overlapping versions, so at most one row covers a day;
    # highest txn is a deterministic defensive tie-break.
    covering.sort(key=lambda r: r["txn"])
    return sorted(json.loads(covering[-1]["source_list"]))
