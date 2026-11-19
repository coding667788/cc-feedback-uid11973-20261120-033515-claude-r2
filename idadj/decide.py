"""decide command: dual-axis access adjudication with a stable explanation."""

from .errors import AdjError, NOT_FOUND
from .replay import (
    authority_on_day,
    conclusion_for_source,
    segments_for_person,
    visible_authority_rows,
)
from .storage import next_txn


def decide(conn, person, area, day, k):
    """Adjudicate whether *person* may use *area* on business *day* given
    only facts visible at transaction sequence *k*.
    """
    latest = next_txn(conn) - 1
    if k is None:
        k = latest
    if k < 0 or k > latest:
        raise AdjError(
            NOT_FOUND,
            f"knowledge sequence K={k} is out of range (0..{latest})",
        )

    auth_rows = visible_authority_rows(conn, area, k)
    authorities = authority_on_day(auth_rows, day)
    if authorities is None:
        authorities = []

    segments = segments_for_person(conn, person, k)
    statuses = []
    for source in authorities:
        seg = conclusion_for_source(segments, source, day)
        if seg is None:
            statuses.append({"source": source, "status": "no_effective_conclusion"})
        else:
            statuses.append(
                {
                    "source": source,
                    "status": seg["conclusion"],
                    "event_id": seg["owner_event"],
                    "valid_from": seg["lo"],
                    "valid_to": seg["hi"],
                    "known_txn": seg["txn"],
                }
            )

    revocations = sorted(
        (s for s in statuses if s["status"] == "revoke"),
        key=lambda s: s["source"],
    )
    grants = sorted(
        (s for s in statuses if s["status"] == "grant"),
        key=lambda s: s["source"],
    )

    result = {
        "command": "decide",
        "person": person,
        "area": area,
        "day": day,
        "knowledge_txn": k,
        "authorities": authorities,
        "statuses": statuses,
    }

    if authorities == []:
        result.update(
            decision="insufficient_evidence",
            reason="no_authority_list_for_day",
            explanation=[],
        )
    elif revocations:
        first = revocations[0]
        result.update(
            decision="deny",
            reason="revocation",
            explanation=[
                {
                    "source": first["source"],
                    "event_id": first["event_id"],
                    "conclusion": "revoke",
                    "valid_from": first["valid_from"],
                    "valid_to": first["valid_to"],
                    "known_txn": first["known_txn"],
                }
            ],
        )
    elif len(grants) >= 2:
        result.update(
            decision="allow",
            reason="two_authority_grants",
            explanation=[
                {
                    "source": g["source"],
                    "event_id": g["event_id"],
                    "conclusion": "grant",
                    "valid_from": g["valid_from"],
                    "valid_to": g["valid_to"],
                    "known_txn": g["known_txn"],
                }
                for g in grants[:2]
            ],
        )
    else:
        result.update(
            decision="insufficient_evidence",
            reason="fewer_than_two_grants",
            explanation=[
                {
                    "source": s["source"],
                    "status": s["status"],
                    **(
                        {"event_id": s["event_id"]} if "event_id" in s else {}
                    ),
                }
                for s in statuses
            ],
        )
    return result
