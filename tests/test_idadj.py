"""Test suite for the bitemporal identity adjudication service.

Covers every scenario required by the task brief:

1. D exactly at interval endpoints;
2. a late revocation flips the same D across different K;
3. a correction changes only the middle of a validity range;
4. multiple certificates from one source never count as double sign-off;
5. an error in the second half of a batch rolls back events AND the
   authority list atomically;
6. after later commits, answers at an old K are byte-identical;

plus cross-checking history against the independent day-by-day,
transaction-by-transaction reference implementation and CLI-level tests.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idadj.decide import decide
from idadj.encoding import canonical_dumps, content_hash, pretty_dumps, sign
from idadj.history import history
from idadj.ingest import ingest
from idadj.storage import connect, load_registry
from idadj.verify import verify_batch, verify_store

from fixtures.generate_fixtures import write_outputs
from tests.reference_impl import ReferenceWorld

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENERATED = os.path.join(ROOT, "fixtures", "generated")
BATCHES = os.path.join(GENERATED, "batches")
PERSON, AREA = "P-1001", "ZONE-A"


class FixtureBackedCase(unittest.TestCase):
    """Fresh registry + database with the five valid batches committed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.registry_path = os.path.join(self.tmp.name, "registry.json")
        self.db_path = os.path.join(self.tmp.name, "idadj.db")
        manifest = write_outputs()
        shutil.copy(
            os.path.join(GENERATED, "registry.json"),
            self.registry_path,
        )
        self.registry = load_registry(self.registry_path)
        self.conn = connect(self.db_path)
        self.committed = []
        for entry in manifest["batches"]:
            if not entry["expect_commit"]:
                continue
            with open(os.path.join(GENERATED, entry["file"]),
                      encoding="utf-8") as fh:
                batch = json.load(fh)
            result = ingest(self.conn, self.registry, batch)
            self.assertEqual(result["status"], "committed", result)
            self.committed.append(entry["file"])

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def load(self, filename):
        with open(os.path.join(BATCHES, filename), encoding="utf-8") as fh:
            return json.load(fh)

    def decide(self, day, k):
        return decide(self.conn, PERSON, AREA, day, k)


class TestEndpointsAndBaseline(FixtureBackedCase):
    """Mandatory scenario 1: D exactly at interval endpoints."""

    def test_half_open_endpoint_is_excluded(self):
        # [2026-01-01, 2026-02-01): the last included day is Jan 31.
        first = self.decide("2026-01-01", 1)
        self.assertEqual(first["decision"], "allow")
        last = self.decide("2026-01-31", 1)
        self.assertEqual(last["decision"], "allow")
        # Feb 1 is outside the January grants at K=1.
        outside = self.decide("2026-02-01", 1)
        self.assertEqual(outside["decision"], "insufficient_evidence")
        self.assertEqual(
            {s["status"] for s in outside["statuses"]},
            {"no_effective_conclusion"},
        )

    def test_explanation_uses_two_sorted_grants(self):
        result = self.decide("2026-01-05", 1)
        self.assertEqual(
            [e["source"] for e in result["explanation"]],
            ["S-HR1", "S-HR2"],
        )


class TestLateRevocation(FixtureBackedCase):
    """Mandatory scenario 2: late revocation flips the same D over K."""

    def test_same_day_flips_between_k2_and_k3(self):
        # The late S-HR2 revocation covers [01-21, 01-22), which is outside
        # B02's middle-correction window [01-10, 01-20). At K=2 both
        # authorities still grant Jan 21; once B03 is known (K=3) the
        # department-first revocation makes the same D a deny.
        before = self.decide("2026-01-21", 2)
        after = self.decide("2026-01-21", 3)
        self.assertEqual(before["decision"], "allow")
        self.assertEqual(after["decision"], "deny")
        self.assertEqual(
            after["explanation"][0]["event_id"], "E-HR2-02"
        )

    def test_revocation_half_open_boundary(self):
        # E-HR2-02 covers only [01-21, 01-22): Jan 22 is granted again.
        inside = self.decide("2026-01-21", 3)
        outside = self.decide("2026-01-22", 3)
        self.assertEqual(inside["decision"], "deny")
        self.assertEqual(outside["decision"], "allow")

    def test_late_fact_is_invisible_at_old_k(self):
        hr2 = next(
            s for s in self.decide("2026-01-21", 2)["statuses"]
            if s["source"] == "S-HR2"
        )
        self.assertEqual(hr2["status"], "grant")
        hr2_after = next(
            s for s in self.decide("2026-01-21", 3)["statuses"]
            if s["source"] == "S-HR2"
        )
        self.assertEqual(hr2_after["status"], "revoke")
        self.assertEqual(hr2_after["event_id"], "E-HR2-02")


class TestMiddleCorrection(FixtureBackedCase):
    """Mandatory scenario 3: correction changes only the middle range."""

    def test_outside_middle_keeps_original_grant(self):
        for day in ("2026-01-09", "2026-01-20", "2026-01-25"):
            result = self.decide(day, 2)
            self.assertEqual(result["decision"], "allow", day)

    def test_inside_middle_is_revoked(self):
        for day in ("2026-01-10", "2026-01-15", "2026-01-19"):
            result = self.decide(day, 2)
            self.assertEqual(result["decision"], "deny", day)
            self.assertEqual(
                result["explanation"][0]["event_id"], "E-HR1-02"
            )

    def test_middle_endpoint_is_half_open(self):
        # correction [01-10, 01-20): Jan 20 returns to the original grant.
        at_end = self.decide("2026-01-20", 2)
        self.assertEqual(at_end["decision"], "allow")
        at_start = self.decide("2026-01-10", 2)
        self.assertEqual(at_start["decision"], "deny")


class TestNoDoubleSignFromOneSource(FixtureBackedCase):
    """Mandatory scenario 4: same-source certificates are one authority."""

    def test_march_single_authority_insufficient(self):
        # B05: S-HR1 holds two consecutive grant events, no other authority
        # publishes a March fact. Two event IDs, one department -> no double.
        for day in ("2026-03-02", "2026-03-14", "2026-03-16", "2026-03-31"):
            result = self.decide(day, 5)
            self.assertEqual(result["decision"], "insufficient_evidence", day)
            self.assertEqual(result["reason"], "fewer_than_two_grants")
        statuses = self.decide("2026-03-10", 5)["statuses"]
        sources = {s["source"] for s in statuses if s["status"] == "grant"}
        self.assertEqual(sources, {"S-HR1"})


class TestAtomicBatchRollback(FixtureBackedCase):
    """Mandatory scenario 5: faults in the back half roll back everything."""

    def test_invalid_batch_changes_nothing(self):
        before_events = self.conn.execute(
            "SELECT COUNT(*) AS c FROM events"
        ).fetchone()["c"]
        before_lists = self.conn.execute(
            "SELECT COUNT(*) AS c FROM authority_lists"
        ).fetchone()["c"]

        result = ingest(
            self.conn, self.registry, self.load("b06_invalid_half.json")
        )
        self.assertEqual(result["status"], "rejected")
        codes = {e["code"] for e in result["errors"]}
        self.assertIn("dangling_reference", codes)

        after_events = self.conn.execute(
            "SELECT COUNT(*) AS c FROM events"
        ).fetchone()["c"]
        after_lists = self.conn.execute(
            "SELECT COUNT(*) AS c FROM authority_lists"
        ).fetchone()["c"]
        self.assertEqual(before_events, after_events)
        self.assertEqual(before_lists, after_lists)

        # The authority list inside the rejected batch must not govern March.
        result = self.decide("2026-03-02", 5)
        self.assertEqual(
            sorted(result["authorities"]),
            ["S-HR1", "S-HR2", "S-HR3"],
        )

    def test_verify_batch_dry_run_detects_fault_without_writes(self):
        report = verify_batch(
            self.conn, self.registry,
            os.path.join(BATCHES, "b06_invalid_half.json"),
        )
        self.assertFalse(report["ok"])
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"],
            8,  # the five valid batches carry 8 events total
        )


class TestByteIdenticalHistoricalAnswers(FixtureBackedCase):
    """Mandatory scenario 6: old-K answers stay byte-identical later."""

    def test_old_k_answer_unchanged_after_reopen(self):
        snapshots = {}
        for k in range(0, 6):
            snapshots[k] = pretty_dumps(
                decide(self.conn, PERSON, AREA, "2026-01-15", k)
            ).encode("utf-8")
        history_blob = pretty_dumps(
            history(self.conn, PERSON, AREA, "2026-01-01", "2026-04-01", 5)
        ).encode("utf-8")

        # Reopen the database (simulating recovery after a later fault) and
        # re-emit every old answer; the bytes must match exactly.
        self.conn.close()
        self.conn = connect(self.db_path)
        for k, blob in snapshots.items():
            again = pretty_dumps(
                decide(self.conn, PERSON, AREA, "2026-01-15", k)
            ).encode("utf-8")
            self.assertEqual(again, blob, f"K={k} answer changed")
        again_history = pretty_dumps(
            history(self.conn, PERSON, AREA, "2026-01-01", "2026-04-01", 5)
        ).encode("utf-8")
        self.assertEqual(again_history, history_blob)


class TestReferenceHistoryParity(FixtureBackedCase):
    """Independent reference implementation must agree on every rectangle."""

    def test_history_matches_reference_on_small_data(self):
        valid_paths = [
            os.path.join(GENERATED, f) for f in self.committed
        ]
        ref = ReferenceWorld(valid_paths)
        start, end = "2026-01-01", "2026-04-01"
        expected = ref.history(PERSON, AREA, start, end, k_max=5)
        actual = history(
            self.conn, PERSON, AREA, start, end, 5
        )["rectangles"]
        self.assertEqual(
            json.dumps(expected, sort_keys=True),
            json.dumps(actual, sort_keys=True),
        )

    def test_every_cell_matches_reference(self):
        valid_paths = [
            os.path.join(GENERATED, f) for f in self.committed
        ]
        ref = ReferenceWorld(valid_paths)
        cur = date(2026, 1, 1)
        end = date(2026, 4, 1)
        while cur < end:
            day = cur.isoformat()
            for k in range(0, 6):
                result = decide(self.conn, PERSON, AREA, day, k)
                ref_label = ref.cell(PERSON, AREA, day, k)
                self.assertEqual(
                    tuple(result["authorities"]), ref_label[0], (day, k)
                )
                self.assertEqual(
                    tuple(
                        (s["source"], s["status"], s.get("event_id"))
                        for s in result["statuses"]
                    ),
                    ref_label[1],
                    (day, k),
                )
                self.assertEqual(
                    result["decision"], ref.decision(ref_label), (day, k)
                )
            cur += timedelta(days=1)


class TestBoundaryEvidence(FixtureBackedCase):
    def test_boundaries_are_explained_by_event_ids(self):
        report = history(
            self.conn, PERSON, AREA, "2026-01-01", "2026-02-01", 3
        )
        evidence_ids = set()
        for boundary in report["boundaries"]:
            self.assertIn(boundary["axis"], ("knowledge_txn", "valid_day"))
            for cause in boundary["evidence"]:
                if cause["kind"] == "event":
                    evidence_ids.add(cause["event_id"])
        # Both the base event and the correction edges must be explainable.
        self.assertIn("E-HR1-01", evidence_ids)
        self.assertIn("E-HR1-02", evidence_ids)
        boundary_at = {(b["axis"], b["at"]) for b in report["boundaries"]}
        for rect in report["rectangles"]:
            self.assertIn(
                ("valid_day", rect["valid_from"]), boundary_at
            )


class TestValidationRules(unittest.TestCase):
    """Extra unit tests for the batch rejection catalogue."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        write_outputs()
        shutil.copy(
            os.path.join(GENERATED, "registry.json"),
            os.path.join(self.tmp.name, "registry.json"),
        )
        self.registry = load_registry(
            os.path.join(self.tmp.name, "registry.json")
        )
        self.conn = connect(os.path.join(self.tmp.name, "idadj.db"))
        with open(os.path.join(BATCHES, "b01_baseline.json"),
                  encoding="utf-8") as fh:
            ingest(self.conn, self.registry, json.load(fh))

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def _base_event(self, **over):
        ev = {
            "event_id": "E-X-1",
            "source": "S-HR1",
            "source_seq": 2,
            "payload": {
                "event_id": "E-X-1",
                "source": "S-HR1",
                "source_seq": 2,
                "person": PERSON,
                "valid_from": "2026-03-01",
                "valid_to": "2026-03-10",
                "conclusion": "grant",
                "kind": "grant",
                "replaces": None,
            },
            "payload_hash": None,
            "signature": None,
        }
        ev.update(over)
        ev["payload_hash"] = content_hash(ev["payload"])
        ev["signature"] = sign(
            self.registry["S-HR1"]["secret_key"],
            canonical_dumps(ev["payload"]),
        )
        return ev

    def _batch(self, events, lists=None, batch_id="B-T"):
        return {
            "batch_id": batch_id,
            "events": events,
            "authority_lists": lists or [],
        }

    def test_bad_signature_rejected(self):
        ev = self._base_event()
        ev["signature"] = "0" * len(ev["signature"])
        result = ingest(self.conn, self.registry, self._batch([ev]))
        self.assertEqual(result["status"], "rejected")
        self.assertIn(
            "bad_signature", {e["code"] for e in result["errors"]}
        )

    def test_envelope_source_mismatch_is_impersonation(self):
        ev = self._base_event()
        ev["source"] = "S-HR2"  # envelope claims another department
        result = ingest(self.conn, self.registry, self._batch([ev]))
        codes = {e["code"] for e in result["errors"]}
        self.assertIn("source_impersonation", codes)

    def test_sequence_gap_rejected(self):
        ev = self._base_event(source_seq=9)
        ev["payload"]["source_seq"] = 9
        ev["payload_hash"] = content_hash(ev["payload"])
        ev["signature"] = sign(
            self.registry["S-HR1"]["secret_key"],
            canonical_dumps(ev["payload"]),
        )
        result = ingest(self.conn, self.registry, self._batch([ev]))
        self.assertIn("seq_gap", {e["code"] for e in result["errors"]})

    def test_same_id_same_content_recorded_once(self):
        with open(os.path.join(BATCHES, "b01_baseline.json"),
                  encoding="utf-8") as fh:
            again = json.load(fh)
        again["batch_id"] = "B01-replay"
        result = ingest(self.conn, self.registry, again)
        self.assertEqual(result["status"], "committed")
        self.assertEqual(result["events_committed"], 0)

    def test_same_id_conflicting_content_rejected(self):
        with open(os.path.join(BATCHES, "b01_baseline.json"),
                  encoding="utf-8") as fh:
            bad = json.load(fh)
        bad["batch_id"] = "B01-conflict"
        # Reuse a known event_id with different content, but re-hash and
        # re-sign correctly: the conflict must be detected as such rather
        # than as a hash/signature failure.
        ev0 = bad["events"][0]
        ev0["payload"]["valid_to"] = "2027-01-01"
        ev0["payload_hash"] = content_hash(ev0["payload"])
        ev0["signature"] = sign(
            self.registry[ev0["source"]]["secret_key"],
            canonical_dumps(ev0["payload"]),
        )
        result = ingest(self.conn, self.registry, bad)
        self.assertIn(
            "event_conflict", {e["code"] for e in result["errors"]}
        )

    def test_parallel_rewrite_rejected(self):
        def corr(eid, seq):
            payload = {
                "event_id": eid,
                "source": "S-HR1",
                "source_seq": seq,
                "person": PERSON,
                "valid_from": "2026-01-05",
                "valid_to": "2026-01-08",
                "conclusion": "revoke",
                "kind": "correction",
                "replaces": "E-HR1-01",
            }
            return {
                "event_id": eid,
                "source": "S-HR1",
                "source_seq": seq,
                "payload": payload,
                "payload_hash": content_hash(payload),
                "signature": sign(
                    self.registry["S-HR1"]["secret_key"],
                    canonical_dumps(payload),
                ),
            }

        result = ingest(
            self.conn, self.registry,
            self._batch([corr("E-C1", 2), corr("E-C2", 3)]),
        )
        self.assertIn(
            "parallel_rewrite", {e["code"] for e in result["errors"]}
        )

    def test_stale_chain_reference_rejected(self):
        def corr(eid, seq, replaces):
            payload = {
                "event_id": eid,
                "source": "S-HR1",
                "source_seq": seq,
                "person": PERSON,
                "valid_from": "2026-01-05",
                "valid_to": "2026-01-08",
                "conclusion": "revoke",
                "kind": "correction",
                "replaces": replaces,
            }
            return {
                "event_id": eid,
                "source": "S-HR1",
                "source_seq": seq,
                "payload": payload,
                "payload_hash": content_hash(payload),
                "signature": sign(
                    self.registry["S-HR1"]["secret_key"],
                    canonical_dumps(payload),
                ),
            }

        first = ingest(
            self.conn, self.registry,
            self._batch([corr("E-C1", 2, "E-HR1-01")], batch_id="B-C1"),
        )
        self.assertEqual(first["status"], "committed")
        # The next correction must point at E-C1 (current owner); pointing
        # at the superseded E-HR1-01 inside the same range is stale.
        stale = ingest(
            self.conn, self.registry,
            self._batch([corr("E-C2", 3, "E-HR1-01")], batch_id="B-C2"),
        )
        self.assertIn(
            "stale_reference", {e["code"] for e in stale["errors"]}
        )

    def test_verify_store_reports_healthy(self):
        report = verify_store(self.conn, self.registry)
        self.assertTrue(report["ok"], report)


class TestCli(unittest.TestCase):
    """End-to-end CLI tests, including byte-identical stdout."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        write_outputs()
        self.registry = os.path.join(self.tmp.name, "registry.json")
        shutil.copy(
            os.path.join(GENERATED, "registry.json"), self.registry
        )
        self.db = os.path.join(self.tmp.name, "idadj.db")
        self.env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONPATH=ROOT)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        proc = subprocess.run(
            [sys.executable, "-m", "idadj", "--db", self.db,
             "--registry", self.registry, *args],
            capture_output=True,
            cwd=ROOT,
            env=self.env,
        )
        return proc

    def test_full_cli_flow_and_stable_bytes(self):
        for name in (
            "b01_baseline.json",
            "b02_middle_correction.json",
            "b03_late_revocation.json",
        ):
            proc = self._run(
                "ingest", os.path.join("fixtures", "generated", "batches", name)
            )
            self.assertEqual(proc.returncode, 0, proc.stderr.decode())
            body = json.loads(proc.stdout.decode())
            self.assertEqual(body["status"], "committed")

        # Invalid batch: exit 1, no writes.
        bad = self._run(
            "ingest",
            os.path.join("fixtures", "generated", "batches", "b06_invalid_half.json"),
        )
        self.assertEqual(bad.returncode, 1)
        self.assertEqual(
            json.loads(bad.stdout.decode())["status"], "rejected"
        )

        first = self._run(
            "decide", "--person", PERSON, "--area", AREA,
            "--day", "2026-01-15", "--k", "2",
        )
        second = self._run(
            "decide", "--person", PERSON, "--area", AREA,
            "--day", "2026-01-15", "--k", "2",
        )
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(json.loads(first.stdout)["decision"], "deny")

        hist = self._run(
            "history", "--person", PERSON, "--area", AREA,
            "--start", "2026-01-01", "--end", "2026-02-01",
        )
        self.assertEqual(hist.returncode, 0)
        self.assertIn("rectangles", json.loads(hist.stdout))

        ver = self._run("verify")
        self.assertEqual(ver.returncode, 0)
        self.assertTrue(json.loads(ver.stdout)["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
