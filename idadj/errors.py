"""Stable validation error codes used by ingest/verify and the CLI."""

# Structural / envelope errors
BAD_FORMAT = "bad_format"
BATCH_ID_CONFLICT = "batch_id_conflict"
BAD_DATE = "bad_date"
BAD_INTERVAL = "bad_interval"
BAD_CONCLUSION = "bad_conclusion"

# Identity / authenticity errors
UNKNOWN_SOURCE = "unknown_source"
SOURCE_IMPERSONATION = "source_impersonation"
BAD_SIGNATURE = "bad_signature"
BAD_HASH = "bad_hash"

# Sequence / reference / lineage errors
EVENT_CONFLICT = "event_conflict"
SEQ_GAP = "seq_gap"
SEQ_DUPLICATE = "seq_duplicate"
DANGLING_REFERENCE = "dangling_reference"
STALE_REFERENCE = "stale_reference"
PARALLEL_REWRITE = "parallel_rewrite"
CORRECTION_OUT_OF_COVERAGE = "correction_out_of_coverage"
CROSS_SOURCE_REFERENCE = "cross_source_reference"

# Authority list errors
AUTHORITY_OVERLAP = "authority_overlap"

# CLI / state errors
NOT_FOUND = "not_found"
USAGE = "usage"


class AdjError(Exception):
    """A single deterministic validation failure."""

    def __init__(self, code, message, event_id=None, source=None, source_seq=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.event_id = event_id
        self.source = source
        self.source_seq = source_seq

    def to_dict(self):
        d = {"code": self.code, "message": self.message}
        if self.event_id is not None:
            d["event_id"] = self.event_id
        if self.source is not None:
            d["source"] = self.source
        if self.source_seq is not None:
            d["source_seq"] = self.source_seq
        return d
