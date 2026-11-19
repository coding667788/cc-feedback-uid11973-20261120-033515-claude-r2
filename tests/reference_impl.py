"""Independent reference implementation for cross-checking history.

This module deliberately imports nothing from the ``idadj`` package: it
re-implements the whole bitemporal semantics in the simplest possible way,
reading the original signed batch JSON files directly and rebuilding the
world day by day and transaction by transaction. The test suite compares
its output against the SQLite-backed implementation on small data.
"""

import json
from datetime import date, timedelta


def _load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _days(lo, hi):
    cur = date.fromisoformat(lo)
    end = date.fromisoformat(hi)
    while cur < end:
        yield cur.isoformat()
        cur += timedelta(days=1)


class ReferenceWorld:
    """Materializes every committed batch as one knowledge transaction."""

    def __init__(self, batch_paths):
        # txn -> {"events": [payload...], "lists": [entry...]}
        self.transactions = []
        for path in batch_paths:
            batch = _load_json(path)
            self.transactions.append(
                {
                    "batch_id": batch["batch_id"],
                    "events": [e["payload"] for e in batch.get("events", [])],
                    "lists": list(batch.get("authority_lists", [])),
                }
            )

    # -- authority list -------------------------------------------------- #
    def authorities(self, area, day, k):
        chosen = None
        for txn in self.transactions[:k]:
            for entry in txn["lists"]:
                if entry["area"] != area:
                    continue
                if not (entry["valid_from"] <= day and (
                    entry["valid_to"] is None or day < entry["valid_to"]
                )):
                    continue
                # later transaction wins on overlap
                if chosen is None or True:
                    chosen = entry
        return sorted(chosen["sources"]) if chosen else []

    # -- event stream replay, one person at a time ----------------------- #
    @staticmethod
    def _replay(events):
        """Return segments as [(lo, hi, owner_event_id, source, seq, conclusion)]."""
        segments = []
        known = {}
        for ev in events:
            known[ev["event_id"]] = ev
            if ev["kind"] in ("grant", "revoke"):
                segments.append(
                    [ev["valid_from"], ev["valid_to"], ev["event_id"],
                     ev["source"], ev["source_seq"], ev["conclusion"]]
                )
                continue
            lo, hi = ev["valid_from"], ev["valid_to"]
            target = known[ev["replaces"]]
            new_segments = []
            for seg in segments:
                seg_lo, seg_hi, owner, source, seq, conclusion = seg
                if owner != ev["replaces"]:
                    new_segments.append(seg)
                    continue
                overlap = seg_lo < hi and (seg_hi is None or lo < seg_hi)
                if not overlap:
                    new_segments.append(seg)
                    continue
                if seg_lo < lo:
                    new_segments.append([seg_lo, lo, owner, source, seq, conclusion])
                mid_lo = max(seg_lo, lo)
                mid_hi = hi if seg_hi is None else min(seg_hi, hi)
                new_segments.append(
                    [mid_lo, mid_hi, ev["event_id"], ev["source"],
                     ev["source_seq"], ev["conclusion"]]
                )
                if seg_hi is None:
                    new_segments.append([hi, None, owner, source, seq, conclusion])
                elif seg_hi > hi:
                    new_segments.append([hi, seg_hi, owner, source, seq, conclusion])
            segments = new_segments
        return segments

    def _visible_events(self, person, k):
        events = []
        for txn in self.transactions[:k]:
            for payload in txn["events"]:
                if payload["person"] == person:
                    events.append(payload)
        events.sort(key=lambda e: (e["source"], e["source_seq"]))
        return events

    def _segment_on(self, segments, source, day):
        hits = [
            seg for seg in segments
            if seg[3] == source
            and seg[0] <= day
            and (seg[1] is None or day < seg[1])
        ]
        if not hits:
            return None
        hits.sort(key=lambda seg: (-seg[4], seg[2]))
        return hits[0]

    def cell(self, person, area, day, k):
        """Canonical label of one (day, k) cell."""
        authorities = self.authorities(area, day, k)
        segments = self._replay(self._visible_events(person, k))
        entries = []
        for source in authorities:
            seg = self._segment_on(segments, source, day)
            if seg is None:
                entries.append((source, "no_effective_conclusion", None))
            else:
                entries.append((source, seg[5], seg[2]))
        entries.sort()
        return tuple(authorities), tuple(entries)

    def decision(self, label):
        authorities, entries = label
        statuses = [e[1] for e in entries]
        if not authorities:
            return "insufficient_evidence"
        if "revoke" in statuses:
            return "deny"
        if statuses.count("grant") >= 2:
            return "allow"
        return "insufficient_evidence"

    def history(self, person, area, start, end, k_max=None):
        """Minimal rectangles computed independently of the main package."""
        if k_max is None:
            k_max = len(self.transactions)
        days = list(_days(start, end))
        cells = {}
        for k in range(0, k_max + 1):
            for day in days:
                cells[(k, day)] = self.cell(person, area, day, k)

        rectangles = []
        k = 0
        while k <= k_max:
            k_hi = k
            while k_hi + 1 <= k_max and all(
                cells[(k_hi + 1, d)] == cells[(k, d)] for d in days
            ):
                k_hi += 1
            run_key, run_lo, prev = None, None, None
            for day in days:
                key = cells[(k, day)]
                if key != run_key:
                    if run_key is not None:
                        rectangles.append(
                            self._rect(run_lo, prev, k, k_hi, run_key)
                        )
                    run_key, run_lo = key, day
                prev = day
            if run_key is not None:
                rectangles.append(self._rect(run_lo, prev, k, k_hi, run_key))
            k = k_hi + 1

        # Merge equal neighbours across both axes.
        changed = True
        while changed:
            changed = False
            for i in range(len(rectangles)):
                for j in range(i + 1, len(rectangles)):
                    a, b = rectangles[i], rectangles[j]
                    if a["label"] != b["label"]:
                        continue
                    touch_d = (
                        a["k_from"] == b["k_from"] and a["k_to"] == b["k_to"]
                        and (a["valid_to"] == b["valid_from"]
                             or b["valid_to"] == a["valid_from"])
                    )
                    touch_k = (
                        a["valid_from"] == b["valid_from"]
                        and a["valid_to"] == b["valid_to"]
                        and (a["k_to"] + 1 == b["k_from"]
                             or b["k_to"] + 1 == a["k_from"])
                    )
                    if touch_d or touch_k:
                        rectangles[i] = {
                            "valid_from": min(a["valid_from"], b["valid_from"]),
                            "valid_to": max(a["valid_to"], b["valid_to"]),
                            "k_from": min(a["k_from"], b["k_from"]),
                            "k_to": max(a["k_to"], b["k_to"]),
                            "label": a["label"],
                        }
                        del rectangles[j]
                        changed = True
                        break
                if changed:
                    break

        rectangles.sort(
            key=lambda r: (r["k_from"], r["valid_from"], r["k_to"], r["valid_to"])
        )
        for rect in rectangles:
            authorities, entries = rect.pop("label")
            rect["state"] = {
                "decision": self.decision((authorities, entries)),
                "authorities": list(authorities),
                "sources": [
                    {"source": s, "status": st, "event_id": eid}
                    for (s, st, eid) in entries
                ],
            }
        return rectangles

    @staticmethod
    def _rect(day_lo, day_hi, k_lo, k_hi, label):
        valid_to = (
            date.fromisoformat(day_hi) + timedelta(days=1)
        ).isoformat()
        return {
            "valid_from": day_lo,
            "valid_to": valid_to,
            "k_from": k_lo,
            "k_to": k_hi,
            "label": label,
        }
