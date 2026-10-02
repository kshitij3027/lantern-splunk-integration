"""Synthetic findings only; no assessment or customer data."""

from copy import deepcopy


def finding(event_id="synthetic-001", **changes):
    record = {
        "event_id": event_id,
        "event_type": "indicator_match",
        "timestamp": "2026-01-10T12:00:00Z",
        "severity": 88,
        "host": {"host_id": "synthetic-host-01", "hostname": "endpoint.example.test", "os": "LINUX", "ip": "192.0.2.10", "agent_version": "1.0"},
        "rule": {"name": "Synthetic_Example_Rule", "namespace": "synthetic", "version": 1, "author": "test-fixture"},
        "file": {"path": "/tmp/synthetic/example.bin", "size": 100, "sha256": "a" * 64, "mtime": "2026-01-09T12:00:00Z", "owner": "test-user"},
        "collection": {"collection_id": "synthetic-collection-01", "job_name": "Synthetic test collection", "requested_by": "test-runner", "completed_at": "2026-01-10T13:00:00Z"},
        "matched_patterns": [{"pattern_id": "synthetic-pattern-01", "offset": 4}],
        "disposition": {"status": "UNREVIEWED", "analyst": None, "comment": None, "updated_at": None},
    }
    for path, value in changes.items():
        parts = path.split("__")
        obj = record
        for part in parts[:-1]:
            obj = obj[part]
        obj[parts[-1]] = deepcopy(value)
    return record


def reviewed(record=None, status="MALICIOUS", updated_at="2026-01-11T12:00:00Z", comment="Synthetic review"):
    record = deepcopy(record if record is not None else finding())
    record["disposition"] = {"status": status, "analyst": "test-analyst", "comment": comment, "updated_at": updated_at}
    return record
