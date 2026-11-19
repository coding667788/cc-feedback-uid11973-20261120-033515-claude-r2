"""history command: minimal merged rectangles over the two time axes.

For every transaction sequence ``k`` the business-day state is rebuilt from
only the facts visible at ``k``; adjacent days with identical state and
adjacent ``k`` levels with identical state are merged. Every rectangle
boundary is attributed to the evidence (event IDs / authority-list txn)
that caused it, so any boundary can be explained.
"""

import json
from datetime import date, timedelta

from .replay import (
    authority_on_day,
    conclusion_for_source,
    segments_for_person,
    visible_authority_rows,
)
from .storage import next_txn


def _day_iter(lo, hi):
    cur = date.fromisoformat(lo)
    end = date.fromisoformat(hi)
    while cur < end:
        yield cur.isoformat()
        cur += timedelta(days=1)


def _label_for_day(conn, person, area, day, k):
    """Canonical, fully sorted state label for one (day, k) cell."""
    auth_rows = visible_authority_rows(conn, area, k)
    authorities = authority_on_day(auth_rows, day) or []
    segments = segments_for_person(conn, person, k)
    entries = []
    for source in authorities:
        seg = conclusion_for_source(segments, source, day)
        if seg is None:
            entries.append((source, "no_effective_conclusion", None))
        else:
            entries.append((source, seg["conclusion"], seg["owner_event"]))
    entries.sort()
    return {
        "authorities": authorities,
        "entries": entries,
        "auth_rows": auth_rows,
    }


def _decision_from_label(label):
    statuses = [e[1] for e in label["entries"]]
    if not label["authorities"]:
        return "insufficient_evidence"
    if "revoke" in statuses:
        return "deny"
    if statuses.count("grant") >= 2:
        return "allow"
    return "insufficient_evidence"


def history(conn, person, area, start, end, k_max=None):
    """Return minimal merged state rectangles over ``[start, end)`` days and
    transaction levels ``0..k_max`` (defaults to the latest transaction).
    """
    latest = next_txn(conn) - 1
    if k_max is None:
        k_max = latest
    days = list(_day_iter(start, end))

    # cell[k][day] = canonical label key; labels hold explanation detail.
    label_store = {}
    grid = {}
    for k in range(0, k_max + 1):
        grid[k] = {}
        for day in days:
            label = _label_for_day(conn, person, area, day, k)
            key = (
                tuple(label["authorities"]),
                tuple(label["entries"]),
            )
            grid[k][day] = key
            label_store.setdefault(
                key,
                {
                    "authorities": label["authorities"],
                    "entries": [
                        {"source": s, "status": st, "event_id": eid}
                        for (s, st, eid) in label["entries"]
                    ],
                    "decision": _decision_from_label(label),
                },
            )

    rectangles = _merge(grid, days, k_max, label_store)
    boundaries = _boundary_evidence(conn, person, area, start, end, k_max)
    return {
        "command": "history",
        "person": person,
        "area": area,
        "valid_range": [start, end],
        "knowledge_range": [0, k_max],
        "rectangles": rectangles,
        "boundaries": boundaries,
    }


def _merge(grid, days, k_max, label_store):
    """Merge adjacent equal cells into minimal (k, day-range) rectangles."""
    rectangles = []
    k = 0
    while k <= k_max:
        # Find the maximal run of consecutive k levels with identical rows.
        k_hi = k
        while k_hi + 1 <= k_max and grid[k_hi + 1] == grid[k]:
            k_hi += 1
        # Merge consecutive days sharing the same label within this k band.
        run_key, run_lo = None, None
        prev_day = None
        for day in days:
            key = grid[k][day]
            if key != run_key:
                if run_key is not None:
                    rectangles.append(
                        _rect(run_lo, prev_day, k, k_hi, label_store[run_key])
                    )
                run_key, run_lo = key, day
            prev_day = day
        if run_key is not None:
            rectangles.append(
                _rect(run_lo, prev_day, k, k_hi, label_store[run_key])
            )
        k = k_hi + 1

    # Merge adjacent rectangles (touching on either axis) with equal labels.
    merged = True
    while merged:
        merged = False
        for i in range(len(rectangles)):
            for j in range(i + 1, len(rectangles)):
                a, b = rectangles[i], rectangles[j]
                if a["label_key"] != b["label_key"]:
                    continue
                same_k = a["k_from"] == b["k_from"] and a["k_to"] == b["k_to"]
                same_d = a["valid_from"] == b["valid_from"] and a["valid_to"] == b["valid_to"]
                touch_d = same_k and (
                    a["valid_to"] == b["valid_from"] or b["valid_to"] == a["valid_from"]
                )
                touch_k = same_d and (a["k_to"] + 1 == b["k_from"] or b["k_to"] + 1 == a["k_from"])
                if touch_d or touch_k:
                    rectangles[i] = {
                        "valid_from": min(a["valid_from"], b["valid_from"]),
                        "valid_to": max(a["valid_to"], b["valid_to"]),
                        "k_from": min(a["k_from"], b["k_from"]),
                        "k_to": max(a["k_to"], b["k_to"]),
                        "label_key": a["label_key"],
                        "state": a["state"],
                    }
                    del rectangles[j]
                    merged = True
                    break
            if merged:
                break

    rectangles.sort(
        key=lambda r: (r["k_from"], r["valid_from"], r["k_to"], r["valid_to"])
    )
    for rect in rectangles:
        del rect["label_key"]
    return rectangles


def _rect(day_lo, day_hi, k_lo, k_hi, label):
    end = (date.fromisoformat(day_hi) + timedelta(days=1)).isoformat()
    return {
        "valid_from": day_lo,
        "valid_to": end,
        "k_from": k_lo,
        "k_to": k_hi,
        "label_key": (tuple(label["authorities"]), tuple(
            (e["source"], e["status"], e["event_id"]) for e in label["entries"]
        )),
        "state": {
            "decision": label["decision"],
            "authorities": label["authorities"],
            "sources": label["entries"],
        },
    }


def _boundary_evidence(conn, person, area, start, end, k_max):
    """Attribute every state change to the evidence visible at that txn."""
    boundaries = []

    # Transaction-axis boundaries: facts that entered visibility at each txn.
    for txn in range(1, k_max + 1):
        ev_rows = conn.execute(
            "SELECT event_id, kind, replaces, valid_from, valid_to, conclusion"
            " FROM events WHERE txn = ? AND person = ?"
            " ORDER BY event_id",
            (txn, person),
        ).fetchall()
        auth_rows = conn.execute(
            "SELECT valid_from, valid_to, source_list FROM authority_lists"
            " WHERE txn = ? AND area = ? ORDER BY valid_from",
            (txn, area),
        ).fetchall()
        causes = []
        for row in ev_rows:
            causes.append(
                {
                    "kind": "event",
                    "event_id": row["event_id"],
                    "event_kind": row["kind"],
                    "replaces": row["replaces"],
                    "valid_from": row["valid_from"],
                    "valid_to": row["valid_to"],
                    "conclusion": row["conclusion"],
                }
            )
        for row in auth_rows:
            causes.append(
                {
                    "kind": "authority_list",
                    "valid_from": row["valid_from"],
                    "valid_to": row["valid_to"],
                    "sources": sorted(json.loads(row["source_list"])),
                }
            )
        if causes:
            boundaries.append(
                {"axis": "knowledge_txn", "at": txn, "evidence": causes}
            )

    # Validity-axis boundaries: segment edges of every visible event.
    ev_rows = conn.execute(
        "SELECT DISTINCT event_id, valid_from, valid_to FROM events"
        " WHERE person = ? AND txn <= ? ORDER BY valid_from, event_id",
        (person, k_max),
    ).fetchall()
    seen = set()
    for row in ev_rows:
        for edge in (row["valid_from"], row["valid_to"]):
            if edge is None or not (start <= edge < end):
                continue
            key = ("valid_day", edge, row["event_id"])
            if key in seen:
                continue
            seen.add(key)
            boundaries.append(
                {
                    "axis": "valid_day",
                    "at": edge,
                    "evidence": [{"kind": "event", "event_id": row["event_id"]}],
                }
            )
    return boundaries
