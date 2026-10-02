"""Mapping semantics, provenance, and fidelity to original evidence."""

from copy import deepcopy
from datetime import datetime, timezone

import pytest

from lantern_splunk.mapping import map_record, severity_label
from lantern_splunk.validation import validate_document
from synthetic_validation import finding, reviewed


def map_one(record):
    return map_record(validate_document([record]).rows[0], "source-checksum", "synthetic_index")


@pytest.mark.parametrize("score,label", [(0, "informational"), (19, "informational"), (20, "low"), (39, "low"), (40, "medium"), (69, "medium"), (70, "high"), (89, "high"), (90, "critical"), (100, "critical")])
def test_severity_policy_boundaries(score, label):
    event = map_one(finding(severity=score))["event"]
    assert event["severity"] == label
    assert event["severity_id"] == score


@pytest.mark.parametrize("score", [True, False, -1, 101, 90.0, "90"])
def test_mapper_rejects_invalid_severity_even_when_called_directly(score):
    with pytest.raises(ValueError):
        severity_label(score)


def test_envelope_uses_detection_time_and_affected_host():
    row = validate_document([finding(timestamp="2026-01-10T04:00:00-08:00")]).rows[0]
    envelope = map_record(row, "checksum", "custom-index", "lantern:synthetic", "custom:sourcetype")
    assert envelope["time"] == datetime(2026, 1, 10, 12, tzinfo=timezone.utc).timestamp()
    assert envelope["host"] == "endpoint.example.test"
    assert envelope["source"] == "lantern:synthetic"
    assert envelope["sourcetype"] == "custom:sourcetype"
    assert envelope["index"] == "custom-index"
    assert "fields" not in envelope
    assert envelope["event"]["dest"] == envelope["host"]


@pytest.mark.parametrize("os,path,filename", [
    ("WINDOWS", r"C:\Users\Test User\Downloads\example.dll", "example.dll"),
    ("WINDOWS", r"\\synthetic-server\share\example.dll", "example.dll"),
    ("LINUX", "/opt/test/example.bin", "example.bin"),
    ("MACOS", "/Users/test/Library/example.plist", "example.plist"),
    ("LINUX", "/tmp/contains\\backslash.bin", "contains\\backslash.bin"),
])
def test_filename_follows_source_os_not_importer_os(os, path, filename):
    event = map_one(finding(host__os=os, file__path=path))["event"]
    assert event["file_name"] == filename
    assert event["file_path"] == event["lantern"]["file"]["path"] == path


@pytest.mark.parametrize("os", ["NEW_OS", [], None])
def test_unknown_or_malformed_optional_os_does_not_invent_filename(os):
    event = map_one(finding(host__os=os))["event"]
    assert event["file_name"] is None
    assert event["lantern"]["host"]["os"] == os
    assert event["quality_flags"]


def test_nulls_unknown_fields_and_pattern_pairing_survive_mapping():
    record = finding(matched_patterns=[{"pattern_id": "a", "offset": 3}, {"pattern_id": "b", "offset": 7}])
    record["future_context"] = {"example": None, "items": [3, "str", False]}
    original = deepcopy(record)
    event = map_one(record)["event"]
    assert record == original == event["lantern"]
    assert event["pattern_count"] == 2
    assert event["disposition_analyst"] is None
    assert event["disposition_comment"] is None
    assert event["disposition_updated_at"] is None
    assert event["lantern"]["matched_patterns"] == record["matched_patterns"]
    event["lantern"]["matched_patterns"][0]["offset"] = 999
    assert record == original


def test_coercion_changes_only_normalized_size_and_reports_its_reason():
    event = map_one(finding(file__size="00100", file__sha256="A" * 64))["event"]
    assert event["file_size"] == 100
    assert event["lantern"]["file"]["size"] == "00100"
    assert event["file_hash"] == "a" * 64
    assert event["lantern"]["file"]["sha256"] == "A" * 64
    assert event["quality_flags"] == ["file_size_coerced"]


def test_rule_severity_and_disposition_are_distinct_without_inventing_actions():
    event = map_one(reviewed(finding(severity=94), status="BENIGN", comment="Synthetic note mentioning host isolation"))["event"]
    assert event["severity"] == "critical"
    assert event["disposition_status"] == "BENIGN"
    assert event["signature"] == "Synthetic_Example_Rule"
    assert not ({"action", "blocked", "user", "signature_id", "mitre_technique"} & event.keys())
    assert event["file_owner"] == "test-user"
    assert event["collection_requested_by"] == "test-runner"
    assert event["disposition_analyst"] == "test-analyst"


def test_revision_order_is_independent_of_unchanged_detection_time():
    baseline = map_one(finding())
    newer = map_one(reviewed())
    assert baseline["time"] == newer["time"]
    assert baseline["event"]["disposition_rank"] == 0
    assert baseline["event"]["disposition_time"] == 0
    assert newer["event"]["disposition_rank"] == 1
    assert newer["event"]["disposition_time"] > newer["time"]
    assert baseline["event"]["immutable_fingerprint"] == newer["event"]["immutable_fingerprint"]
    assert baseline["event"]["event_version"] != newer["event"]["event_version"]


def test_provenance_and_versions_are_explicit_and_repeatable():
    row = validate_document([finding()]).rows[0]
    first = map_record(row, "checksum", "test-index")
    assert first == map_record(row, "checksum", "test-index")
    event = first["event"]
    assert event["id"] == row.event_id
    assert event["source_row"] == 1
    assert event["source_sha256"] == "checksum"
    assert event["mapping_version"] == "1"
    assert event["event_version"] == row.event_version
    assert event["immutable_fingerprint"] == row.immutable_fingerprint
    assert len(event["event_version"]) == 64


def test_mapper_refuses_quarantined_and_duplicate_rows():
    bad = validate_document([finding(timestamp=None)]).rows[0]
    duplicate = validate_document([finding(), finding()]).rows[1]
    for row in (bad, duplicate):
        with pytest.raises(ValueError, match="Only eligible"):
            map_record(row, "checksum", "index")


def test_invalid_optional_fields_are_not_promoted_to_normalized_meaning():
    event = map_one(finding(host__ip="not an IP", rule__version=True, file__owner={"unexpected": "object"}))["event"]
    assert event["dest_ip"] is None
    assert event["rule_version"] is None
    assert event["file_owner"] is None
    assert event["lantern"]["host"]["ip"] == "not an IP"
    assert event["lantern"]["rule"]["version"] is True
