"""Quality, identity and lifecycle cases that can otherwise lose evidence."""

import json
from copy import deepcopy
from datetime import datetime, timezone

import pytest

from lantern_splunk.validation import DocumentError, parse_timestamp, validate_document
from synthetic_validation import finding, reviewed


def validate_one(record):
    return validate_document([record]).rows[0]


def error_codes(row):
    return {issue.code for issue in row.issues if issue.level == "error"}


def test_clean_record_and_empty_snapshot_reconcile():
    result = validate_document([finding()], "source-checksum")
    assert result.summary == {"total": 1, "eligible": 1, "quarantined": 0, "duplicate": 0, "warning_rows": 0, "eligible_with_warnings": 0, "eligible_without_warnings": 1}
    assert result.rows[0].source_row == 1
    assert result.rows[0].issues == []
    assert result.to_dict()["source_sha256"] == "source-checksum"
    assert json.loads(json.dumps(result.to_dict()))["rows"][0]["record"] == finding()
    assert validate_document([]).summary["total"] == 0


@pytest.mark.parametrize("value", [{}, None, "[]", 42, True])
def test_wrong_document_shape_is_fatal(value):
    with pytest.raises(DocumentError):
        validate_document(value)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), {1, 2}, "\ud800"])
def test_non_json_or_non_utf8_values_fail_document_before_rows(value):
    with pytest.raises(DocumentError):
        validate_document([finding(), {"extra": value}])


@pytest.mark.parametrize("value", [None, [], "event", 5, False])
def test_non_object_row_is_accounted_for_without_blocking_other_rows(value):
    result = validate_document([value, finding()])
    assert result.summary["quarantined"] == 1
    assert result.summary["eligible"] == 1
    assert result.rows[0].record == value
    assert result.rows[1].source_row == 2
    assert "record_not_object" in error_codes(result.rows[0])


@pytest.mark.parametrize("value", [-1, 101, True, False, 90.0, "90", None])
def test_severity_rejects_outside_range_bool_or_coercion(value):
    assert "invalid_severity" in error_codes(validate_one(finding(severity=value)))


@pytest.mark.parametrize("path", ["event_id", "host__host_id", "host__hostname", "rule__name", "file__path", "collection__collection_id", "disposition__status"])
@pytest.mark.parametrize("value", [None, " ", 5, []])
def test_missing_minimum_identity_or_evidence_is_quarantined(path, value):
    row = validate_one(finding(**{path: value}))
    assert row.status == "quarantined"
    assert "required_string" in error_codes(row)


@pytest.mark.parametrize("field", ["host", "rule", "file", "collection", "disposition"])
def test_required_objects_cannot_be_missing_or_arrays(field):
    assert "required_object" in error_codes(validate_one(finding(**{field: []})))


def test_unknown_event_type_is_not_guessed():
    assert "unsupported_event_type" in error_codes(validate_one(finding(event_type="process_start")))


@pytest.mark.parametrize("value", [-1, True, 1.0, "-1", "+1", " 1", "1.0", "1e3", "1 KB", "١", None])
def test_invalid_size_does_not_get_rounded_or_guessed(value):
    assert "invalid_file_size" in error_codes(validate_one(finding(file__size=value)))


@pytest.mark.parametrize("value,expected", [(0, 0), (100, 100), ("0", 0), ("00100", 100)])
def test_lossless_size_conversion_preserves_source(value, expected):
    record = finding(file__size=value, matched_patterns=[])
    original = deepcopy(record)
    row = validate_one(record)
    assert row.status == "eligible"
    assert row.normalized["file_size"] == expected
    assert ("file_size_coerced" in row.quality_flags) == isinstance(value, str)
    assert record == original == row.record


@pytest.mark.parametrize("value", [None, "a" * 63, "a" * 65, "g" * 64, "sha256:" + "a" * 64])
def test_invalid_hash_is_quarantined(value):
    assert "invalid_sha256" in error_codes(validate_one(finding(file__sha256=value)))


@pytest.mark.parametrize("value", [None, "2026-01-10", "2026-01-10T12:00:00", "2026-02-30T12:00:00Z", "2026-01-10T25:00:00Z", "2026-01-10T12:00:00+01:99", "2026-01-10T12:00:00+24:00"])
def test_invalid_or_naive_timestamps_are_quarantined(value):
    assert "invalid_timestamp" in error_codes(validate_one(finding(timestamp=value)))


def test_offsets_and_fractional_seconds_are_converted_to_utc():
    assert parse_timestamp("2026-01-10T04:00:00-08:00") == parse_timestamp("2026-01-10T12:00:00Z")
    assert parse_timestamp("2026-01-10T17:30:00+05:30") == datetime(2026, 1, 10, 12, tzinfo=timezone.utc)
    assert parse_timestamp("2026-01-10T12:00:00.125Z").microsecond == 125000


@pytest.mark.parametrize("fraction,microseconds", [("", 0), (".1", 100000), (".12", 120000), (".123", 123000), (".1234", 123400), (".12345", 123450), (".123456", 123456)])
def test_supported_timestamp_precision_is_preserved(fraction, microseconds):
    assert parse_timestamp(f"2026-01-10T12:00:00{fraction}Z").microsecond == microseconds


@pytest.mark.parametrize("field", ["timestamp", "file__mtime", "collection__completed_at", "disposition__updated_at"])
@pytest.mark.parametrize("fraction", ["1234567", "123456700", "123456789123456789"])
def test_excess_timestamp_precision_is_explicitly_quarantined_in_every_time_field(field, fraction):
    record = reviewed()
    obj = record
    parts = field.split("__")
    for part in parts[:-1]:
        obj = obj[part]
    obj[parts[-1]] = f"2026-01-10T12:00:00.{fraction}Z"
    row = validate_one(record)
    assert row.status == "quarantined"
    issue = next(issue for issue in row.issues if issue.field == field.replace("__", ".") and issue.code == "invalid_timestamp")
    assert "six fractional-second digits" in issue.message
    assert "never rounded" in issue.message
    assert row.record == record


def test_submicrosecond_time_order_is_not_silently_collapsed():
    row = validate_one(finding(file__mtime="2026-01-10T12:00:00.1234567Z", timestamp="2026-01-10T12:00:00.1234568Z"))
    assert error_codes(row) == {"invalid_timestamp"}
    assert len(row.issues) == 2
    assert "timestamp" not in row.normalized
    assert "file_mtime" not in row.normalized


def test_microsecond_disposition_revisions_remain_distinct():
    rows = validate_document([reviewed(updated_at="2026-01-11T12:00:00.123456Z"), reviewed(status="BENIGN", updated_at="2026-01-11T12:00:00.123457Z")]).rows
    assert all(row.status == "eligible" for row in rows)
    assert rows[0].normalized["disposition_time"] < rows[1].normalized["disposition_time"]


@pytest.mark.parametrize("changes", [
    {"file__mtime": "2026-01-10T12:00:00Z"},
    {"file__mtime": "2026-01-10T12:00:01Z"},
    {"collection__completed_at": "2026-01-10T11:59:59Z"},
])
def test_source_time_order_is_enforced(changes):
    assert "invalid_time_order" in error_codes(validate_one(finding(**changes)))


def test_match_can_equal_collection_completion():
    assert validate_one(finding(collection__completed_at="2026-01-10T12:00:00Z")).status == "eligible"


@pytest.mark.parametrize("patterns,code", [
    (None, "invalid_patterns"),
    (["pattern"], "invalid_pattern"),
    ([{"pattern_id": "p", "offset": -1}], "invalid_pattern_offset"),
    ([{"pattern_id": "p", "offset": True}], "invalid_pattern_offset"),
    ([{"pattern_id": "p", "offset": 1.0}], "invalid_pattern_offset"),
    ([{"pattern_id": "", "offset": 1}], "required_string"),
])
def test_malformed_patterns_quarantine(patterns, code):
    assert code in error_codes(validate_one(finding(matched_patterns=patterns)))


def test_empty_and_out_of_bounds_patterns_warn_without_deleting_evidence():
    empty = validate_one(finding(matched_patterns=[]))
    assert empty.status == "eligible" and "empty_patterns" in empty.quality_flags
    record = finding(matched_patterns=[{"pattern_id": "p", "offset": 100}, {"pattern_id": "q", "offset": 101}])
    row = validate_one(record)
    assert row.status == "eligible"
    assert row.quality_flags == ["pattern_offset_out_of_bounds"]
    assert len(row.issues) == 2
    assert row.record["matched_patterns"] == record["matched_patterns"]


@pytest.mark.parametrize("field,value", [("analyst", "test"), ("comment", "review"), ("updated_at", "2026-01-11T12:00:00Z")])
def test_unreviewed_has_explicit_null_lifecycle_fields(field, value):
    record = finding(**{f"disposition__{field}": value})
    assert "invalid_unreviewed_disposition" in error_codes(validate_one(record))
    del record["disposition"][field]
    assert "invalid_unreviewed_disposition" in error_codes(validate_one(record))


@pytest.mark.parametrize("status", ["BENIGN", "MALICIOUS", "SUPPRESSED"])
def test_reviewed_requires_a_valid_revision_date_not_before_match(status):
    assert validate_one(reviewed(status=status)).status == "eligible"
    assert "invalid_timestamp" in error_codes(validate_one(reviewed(status=status, updated_at=None)))
    assert "invalid_disposition_time" in error_codes(validate_one(reviewed(status=status, updated_at="2026-01-01T00:00:00Z")))


def test_unknown_disposition_is_preserved_and_flagged_without_guessing():
    for record in (reviewed(status="TRIAGED"), finding(disposition__status="TRIAGED")):
        row = validate_one(record)
        assert row.status == "eligible"
        assert "unknown_disposition" in row.quality_flags
        assert row.record["disposition"]["status"] == "TRIAGED"


def test_optional_bad_context_warns_but_unknown_new_fields_are_preserved():
    record = finding(host__os=[], host__ip="not-ip", rule__version=True, file__owner=None)
    record["future_extension"] = {"nested": [None, "new-value"]}
    row = validate_one(record)
    assert row.status == "eligible"
    assert {"optional_context_invalid", "invalid_host_ip"} <= set(row.quality_flags)
    assert row.record == record


def test_exact_duplicate_rows_have_one_retained_version_and_reconcile():
    first = finding()
    second = json.loads(json.dumps(first, sort_keys=True))
    result = validate_document([first, finding("synthetic-002"), second])
    assert [row.status for row in result.rows] == ["eligible", "eligible", "duplicate"]
    assert result.rows[2].duplicate_of == 1
    assert result.summary["total"] == sum(result.summary[key] for key in ("eligible", "quarantined", "duplicate"))


@pytest.mark.parametrize("reverse", [False, True])
def test_all_immutable_conflict_members_quarantine_including_exact_copies(reverse):
    original = finding()
    changed = finding(file__path="/tmp/different-evidence.bin")
    records = [original, deepcopy(original), changed, finding("unrelated")]
    if reverse:
        records.reverse()
    rows = validate_document(records).rows
    conflicts = [row for row in rows if row.event_id == "synthetic-001"]
    assert len(conflicts) == 3
    assert all(row.status == "quarantined" and "immutable_id_conflict" in error_codes(row) for row in conflicts)
    assert next(row for row in rows if row.event_id == "unrelated").status == "eligible"


def test_newer_and_stale_disposition_versions_coexist_as_history():
    original = finding()
    newer = reviewed(original)
    result = validate_document([newer, original, reviewed(original, status="BENIGN", updated_at="2026-01-10T15:00:00Z")])
    assert all(row.status == "eligible" for row in result.rows)
    assert len({row.immutable_fingerprint for row in result.rows}) == 1
    assert len({row.event_version for row in result.rows}) == 3
    assert result.rows[0].normalized["disposition_time"] > result.rows[2].normalized["disposition_time"]
    assert result.rows[1].normalized["disposition_rank"] == 0


def test_tied_differing_revisions_quarantine_all_ties_without_hiding_baseline():
    result = validate_document([reviewed(), finding(), reviewed(status="BENIGN"), reviewed()])
    assert [row.status for row in result.rows] == ["quarantined", "eligible", "quarantined", "quarantined"]
    assert all("ambiguous_disposition_revision" in error_codes(result.rows[i]) for i in (0, 2, 3))


def test_shared_collection_conflict_marks_entire_group_not_just_outlier():
    result = validate_document([finding("a"), finding("b", collection__completed_at="2026-01-10T14:00:00Z"), finding("c"), finding("other", collection__collection_id="other-collection")])
    assert [row.status for row in result.rows] == ["quarantined"] * 3 + ["eligible"]
    assert all("collection_completion_conflict" in error_codes(row) for row in result.rows[:3])


def test_equivalent_collection_instants_with_different_offsets_are_consistent():
    rows = validate_document([finding("a"), finding("b", collection__completed_at="2026-01-10T05:00:00-08:00")]).rows
    assert all(row.status == "eligible" for row in rows)


def test_hash_size_conflict_warns_all_rows_and_does_not_merge_findings():
    result = validate_document([finding("a"), finding("b", file__size="200"), finding("c", file__sha256="A" * 64)])
    assert result.summary["eligible"] == 3
    assert result.summary["eligible_with_warnings"] == 3
    assert all("hash_size_conflict" in row.quality_flags for row in result.rows)


def test_hash_size_uses_normalized_numeric_value_without_false_conflict():
    rows = validate_document([finding("a"), finding("b", file__size="100")]).rows
    assert all("hash_size_conflict" not in row.quality_flags for row in rows)


def test_fingerprints_do_not_change_with_row_position_file_hash_or_key_order():
    original = finding()
    first = validate_document([original], "checksum-1").rows[0]
    second = validate_document([finding("other"), json.loads(json.dumps(original, sort_keys=True))], "checksum-2").rows[1]
    assert first.event_version == second.event_version
    assert first.immutable_fingerprint == second.immutable_fingerprint
    assert first.source_row != second.source_row


def test_validation_does_not_mutate_input_and_retains_independent_original():
    data = [finding(file__size="100")]
    before = deepcopy(data)
    result = validate_document(data)
    assert data == before
    data[0]["file"]["size"] = "999"
    assert result.rows[0].record == before[0]
