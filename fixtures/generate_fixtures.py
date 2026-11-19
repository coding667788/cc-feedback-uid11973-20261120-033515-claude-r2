"""Deterministic synthetic input generator.

Running this module rebuilds every input artifact under
``fixtures/generated/`` from scratch:

* ``registry.json``      - three HR departments with HMAC signing keys;
* ``batches/b0x_*.json`` - signed credential batches plus versioned area
                           authority lists, including one deliberately
                           invalid batch (never committed);
* ``manifest.json``      - index describing what each batch exercises.

Generated data lives in a dedicated subdirectory so regeneration never
touches source code. No randomness, no external systems, no real personal
data: all people, departments and dates are synthetic.
"""

import hashlib
import json
import os
import shutil

from idadj.encoding import canonical_dumps, content_hash, sign

FIXTURE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "fixtures",
    "generated",
)
BATCH_DIR = os.path.join(FIXTURE_DIR, "batches")

SOURCES = [
    ("S-HR1", "Human Resources Department One"),
    ("S-HR2", "Human Resources Department Two"),
    ("S-HR3", "Human Resources Department Three"),
]
AREA = "ZONE-A"
PERSON = "P-1001"


def _key_for(source_id):
    # Deterministic 32-byte hex key per source, derived from a fixed seed.
    digest = canonical_dumps(("idadj-fixture-key-v1", source_id))
    for _ in range(16):
        digest = hashlib.sha256(digest).hexdigest().encode("ascii")
    return digest.decode("ascii")


def build_registry():
    return {
        "version": 1,
        "sources": [
            {
                "source_id": sid,
                "name": name,
                "secret_key": _key_for(sid),
            }
            for sid, name in SOURCES
        ],
    }


class Signer:
    def __init__(self, registry):
        self.keys = {
            s["source_id"]: s["secret_key"] for s in registry["sources"]
        }

    def event(self, event_id, source, source_seq, person, valid_from,
              valid_to, conclusion, kind="grant", replaces=None):
        payload = {
            "event_id": event_id,
            "source": source,
            "source_seq": source_seq,
            "person": person,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "conclusion": conclusion,
            "kind": kind,
            "replaces": replaces,
        }
        message = canonical_dumps(payload)
        return {
            "event_id": event_id,
            "source": source,
            "source_seq": source_seq,
            "payload": payload,
            "payload_hash": content_hash(payload),
            "signature": sign(self.keys[source], message),
        }


def _auth(area, valid_from, valid_to, sources):
    return {
        "area": area,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "sources": sources,
    }


def build_batches(signer):
    # --- B01: baseline two-authority grants + initial authority list -----
    b01 = {
        "batch_id": "B01-baseline",
        "events": [
            signer.event("E-HR1-01", "S-HR1", 1, PERSON,
                         "2026-01-01", "2026-02-01", "grant"),
            signer.event("E-HR2-01", "S-HR2", 1, PERSON,
                         "2026-01-01", "2026-02-01", "grant"),
        ],
        "authority_lists": [
            _auth(AREA, "2026-01-01", None, ["S-HR1", "S-HR2"]),
        ],
    }

    # --- B02: correction rewriting only the middle 10 days of E-HR1-01 ---
    b02 = {
        "batch_id": "B02-middle-correction",
        "events": [
            signer.event(
                "E-HR1-02", "S-HR1", 2, PERSON,
                "2026-01-10", "2026-01-20", "revoke",
                kind="correction", replaces="E-HR1-01",
            ),
        ],
        "authority_lists": [],
    }

    # --- B03: late revocation, active one day [01-21, 01-22). That day is
    # outside B02's middle window, so the flip is visible on the final
    # decision, not only in one source's status. --------------------------
    b03 = {
        "batch_id": "B03-late-revocation",
        "events": [
            signer.event("E-HR2-02", "S-HR2", 2, PERSON,
                         "2026-01-21", "2026-01-22", "revoke"),
        ],
        "authority_lists": [],
    }

    # --- B04: third department starts granting, authority list extended --
    b04 = {
        "batch_id": "B04-third-source",
        "events": [
            signer.event("E-HR3-01", "S-HR3", 1, PERSON,
                         "2026-02-01", "2026-03-01", "grant"),
            signer.event("E-HR1-03", "S-HR1", 3, PERSON,
                         "2026-02-01", "2026-03-01", "grant"),
        ],
        "authority_lists": [
            _auth(AREA, "2026-02-01", None, ["S-HR1", "S-HR2", "S-HR3"]),
        ],
    }

    # --- B05: only S-HR1 grants in March; same-source double certificate
    # still counts as a single authority (no double sign) -----------------
    b05 = {
        "batch_id": "B05-single-authority",
        "events": [
            signer.event("E-HR1-04", "S-HR1", 4, PERSON,
                         "2026-03-01", "2026-03-15", "grant"),
            signer.event("E-HR1-05", "S-HR1", 5, PERSON,
                         "2026-03-15", "2026-04-01", "grant"),
        ],
        "authority_lists": [],
    }

    # --- B06: deliberately invalid batch. The fault sits in the second
    # half; neither events nor the authority list may persist. ------------
    b06 = {
        "batch_id": "B06-invalid-half",
        "events": [
            signer.event("E-HR3-02", "S-HR3", 2, PERSON,
                         "2026-03-01", "2026-03-10", "grant"),
            # dangling reference: E-NOPE-99 does not exist
            signer.event(
                "E-HR3-03", "S-HR3", 3, PERSON,
                "2026-03-05", "2026-03-08", "revoke",
                kind="correction", replaces="E-NOPE-99",
            ),
        ],
        "authority_lists": [
            _auth(AREA, "2026-03-01", None, ["S-HR1"]),
        ],
    }

    return [
        ("b01_baseline.json", b01),
        ("b02_middle_correction.json", b02),
        ("b03_late_revocation.json", b03),
        ("b04_third_source.json", b04),
        ("b05_single_authority.json", b05),
        ("b06_invalid_half.json", b06),
    ]


def write_outputs():
    if os.path.isdir(FIXTURE_DIR):
        shutil.rmtree(FIXTURE_DIR)
    os.makedirs(BATCH_DIR)

    registry = build_registry()
    with open(os.path.join(FIXTURE_DIR, "registry.json"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(registry, ensure_ascii=False, indent=2,
                            sort_keys=True) + "\n")

    signer = Signer(registry)
    manifest = {
        "fixture_version": 1,
        "area": AREA,
        "person": PERSON,
        "batches": [],
    }
    for name, batch in build_batches(signer):
        path = os.path.join(BATCH_DIR, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(batch, ensure_ascii=False, indent=2,
                                sort_keys=True) + "\n")
        manifest["batches"].append(
            {
                "file": f"batches/{name}",
                "batch_id": batch["batch_id"],
                "expect_commit": not name.startswith("b06"),
            }
        )
    with open(os.path.join(FIXTURE_DIR, "manifest.json"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(manifest, ensure_ascii=False, indent=2,
                            sort_keys=True) + "\n")
    return manifest


if __name__ == "__main__":
    m = write_outputs()
    print(f"wrote {len(m['batches'])} batches to {FIXTURE_DIR}")
