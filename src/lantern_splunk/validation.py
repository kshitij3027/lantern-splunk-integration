"""Validate an entire Lantern snapshot before allowing any delivery.

Validation never repairs the source record. Only an unambiguous decimal size
string is coerced, and that conversion lives in separate normalized metadata.
"""

import hashlib
import ipaddress
import json
import re
from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from .models import RowResult, ValidationResult

_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(?P<fraction>\d+))?(?:Z|[+-]\d{2}:\d{2})"
)
_SHA256 = re.compile(r"[a-fA-F0-9]{64}")
_DECIMAL = re.compile(r"[0-9]+")
KNOWN_DISPOSITIONS = frozenset({"UNREVIEWED", "BENIGN", "MALICIOUS", "SUPPRESSED"})


class DocumentError(ValueError):
    """The document cannot be processed safely as a Lantern JSON array."""


class TimestampPrecisionError(ValueError):
    """Source precision exceeds datetime's supported microsecond resolution."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def parse_timestamp(value: Any) -> datetime:
    """Accept ISO calendar timestamps with a zone and at most six fractional digits."""
    match = _TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("Expected an ISO 8601 timestamp with seconds and an explicit time zone")
    if len(match.group("fraction") or "") > 6:
        raise TimestampPrecisionError("At most six fractional-second digits are supported; timestamps are never rounded.")
    if not value.endswith("Z"):
        if int(value[-5:-3]) > 23 or int(value[-2:]) > 59:
            raise ValueError("Invalid time-zone offset")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _required_string(row: RowResult, obj: dict, key: str, path: str) -> bool:
    if not _nonempty(obj.get(key)):
        row.add_issue("required_string", "error", "A nonempty string is required.", path)
        return False
    return True


def _time(row: RowResult, value: Any, path: str, normalized_key: str) -> datetime | None:
    try:
        parsed = parse_timestamp(value)
        row.normalized[normalized_key] = parsed.timestamp()
        return parsed
    except TimestampPrecisionError as error:
        row.add_issue("invalid_timestamp", "error", str(error), path)
        return None
    except (ValueError, OverflowError):
        row.add_issue("invalid_timestamp", "error", "A valid timezone-aware ISO timestamp is required.", path)
        return None


def _optional_context(row: RowResult, objects: dict[str, dict]) -> None:
    # Missing or malformed supporting context must not hide an identifiable finding.
    fields = {
        "host": ("os", "ip", "agent_version"),
        "rule": ("namespace", "author"),
        "file": ("owner",),
        "collection": ("job_name", "requested_by"),
    }
    for obj_name, names in fields.items():
        if obj_name not in objects:
            continue
        obj = objects[obj_name]
        for name in names:
            if not _nonempty(obj.get(name)):
                row.add_issue("optional_context_invalid", "warning", "Supporting context is missing or is not a nonempty string.", f"{obj_name}.{name}")
    host = objects.get("host", {})
    if _nonempty(host.get("os")) and host["os"] not in {"LINUX", "MACOS", "WINDOWS"}:
        row.add_issue("unknown_host_os", "warning", "Unknown host OS; file name derivation is omitted.", "host.os")
    if _nonempty(host.get("ip")):
        try:
            ipaddress.ip_address(host["ip"])
        except ValueError:
            row.add_issue("invalid_host_ip", "warning", "Host IP is not a valid IP address; retained only in original evidence.", "host.ip")
    rule = objects.get("rule", {})
    if "rule" in objects and (type(rule.get("version")) is not int or rule["version"] < 0):
        row.add_issue("optional_context_invalid", "warning", "Rule version is missing or is not a nonnegative integer.", "rule.version")


def _validate_row(record: Any, number: int) -> RowResult:
    row = RowResult(source_row=number, record=deepcopy(record))
    row.event_version = fingerprint(record)
    if not isinstance(record, dict):
        row.add_issue("record_not_object", "error", "Each input row must be a JSON object.")
        return row
    row.immutable_fingerprint = fingerprint({key: value for key, value in record.items() if key != "disposition"})
    if _required_string(row, record, "event_id", "event_id"):
        row.event_id = record["event_id"]
    if record.get("event_type") != "indicator_match":
        row.add_issue("unsupported_event_type", "error", "Only indicator_match events are supported.", "event_type")
    severity = record.get("severity")
    if type(severity) is not int or not 0 <= severity <= 100:
        row.add_issue("invalid_severity", "error", "Severity must be an integer from 0 through 100; booleans are not integers here.", "severity")

    objects: dict[str, dict] = {}
    for field in ("host", "rule", "file", "collection", "disposition"):
        value = record.get(field)
        if isinstance(value, dict):
            objects[field] = value
        else:
            row.add_issue("required_object", "error", "A JSON object is required.", field)
    for obj_name, fields in {
        "host": ("host_id", "hostname"), "rule": ("name",),
        "file": ("path",), "collection": ("collection_id",), "disposition": ("status",),
    }.items():
        if obj_name in objects:
            for field in fields:
                _required_string(row, objects[obj_name], field, f"{obj_name}.{field}")

    matched = _time(row, record.get("timestamp"), "timestamp", "timestamp")
    if "file" in objects:
        file = objects["file"]
        size = file.get("size")
        if type(size) is int and size >= 0:
            row.normalized["file_size"] = size
        elif isinstance(size, str) and _DECIMAL.fullmatch(size):
            try:
                row.normalized["file_size"] = int(size)
                row.add_issue("file_size_coerced", "warning", "Decimal-integer string converted to an integer in the normalized field; source retained.", "file.size")
            except ValueError:
                row.add_issue("invalid_file_size", "error", "File size exceeds the supported integer conversion limit.", "file.size")
        else:
            row.add_issue("invalid_file_size", "error", "File size must be a nonnegative integer or an ASCII decimal-integer string.", "file.size")
        if not isinstance(file.get("sha256"), str) or not _SHA256.fullmatch(file["sha256"]):
            row.add_issue("invalid_sha256", "error", "File SHA-256 must contain exactly 64 hexadecimal characters.", "file.sha256")
        mtime = _time(row, file.get("mtime"), "file.mtime", "file_mtime")
        if mtime is not None and matched is not None and mtime >= matched:
            row.add_issue("invalid_time_order", "error", "File modification must precede the match timestamp.", "file.mtime")
    if "collection" in objects:
        completed = _time(row, objects["collection"].get("completed_at"), "collection.completed_at", "collection_completed_at")
        if matched is not None and completed is not None and matched > completed:
            row.add_issue("invalid_time_order", "error", "Match timestamp must not follow collection completion.", "collection.completed_at")

    patterns = record.get("matched_patterns")
    if not isinstance(patterns, list):
        row.add_issue("invalid_patterns", "error", "Matched patterns must be an array.", "matched_patterns")
    else:
        if not patterns:
            row.add_issue("empty_patterns", "warning", "No pattern evidence is present.", "matched_patterns")
        for i, pattern in enumerate(patterns):
            path = f"matched_patterns[{i}]"
            if not isinstance(pattern, dict):
                row.add_issue("invalid_pattern", "error", "Each pattern must be an object containing pattern_id and offset.", path)
                continue
            _required_string(row, pattern, "pattern_id", f"{path}.pattern_id")
            offset = pattern.get("offset")
            if type(offset) is not int or offset < 0:
                row.add_issue("invalid_pattern_offset", "error", "Pattern offset must be a nonnegative integer, excluding booleans.", f"{path}.offset")
            elif "file_size" in row.normalized and offset >= row.normalized["file_size"]:
                row.add_issue("pattern_offset_out_of_bounds", "warning", "Pattern offset is at or beyond the reported file size.", f"{path}.offset")

    if "disposition" in objects:
        disposition = objects["disposition"]
        status = disposition.get("status")
        if _nonempty(status):
            if status not in KNOWN_DISPOSITIONS:
                row.add_issue("unknown_disposition", "warning", "Unknown status is preserved without assigning known-status meaning.", "disposition.status")
            if status == "UNREVIEWED":
                for field in ("analyst", "comment", "updated_at"):
                    if field not in disposition or disposition[field] is not None:
                        row.add_issue("invalid_unreviewed_disposition", "error", "UNREVIEWED requires explicit null analyst, comment, and updated_at fields.", f"disposition.{field}")
                row.normalized.update(disposition_rank=0, disposition_time=0.0)
            else:
                updated = disposition.get("updated_at")
                # Unknown statuses can carry either a dated revision or an undated baseline.
                if updated is not None or status in KNOWN_DISPOSITIONS:
                    parsed = _time(row, updated, "disposition.updated_at", "disposition_time")
                    row.normalized["disposition_rank"] = 1
                    if parsed is not None and matched is not None and parsed < matched:
                        row.add_issue("invalid_disposition_time", "error", "Disposition revision must not precede the match.", "disposition.updated_at")
                else:
                    row.normalized.update(disposition_rank=0, disposition_time=0.0)
                for field in ("analyst", "comment"):
                    if field not in disposition or (disposition[field] is not None and not isinstance(disposition[field], str)):
                        row.add_issue("optional_context_invalid", "warning", "Disposition supporting context is missing or is not a string/null.", f"disposition.{field}")
    _optional_context(row, objects)
    return row


def validate_document(data: Any, source_sha256: str = "") -> ValidationResult:
    """Return one outcome per source row, after all cross-record checks.

    Errors in row content quarantine rows. Invalid document shape or non-JSON
    values fail the document before a caller can send any rows.
    """
    if not isinstance(data, list):
        raise DocumentError("Lantern input must be a JSON array of event objects.")
    try:
        canonical_json(data).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as error:
        raise DocumentError("Input must contain only finite, serializable JSON values.") from error
    rows = [_validate_row(record, i) for i, record in enumerate(data, 1)]
    by_id: dict[str, list[RowResult]] = defaultdict(list)
    by_collection: dict[str, list[RowResult]] = defaultdict(list)
    by_hash: dict[str, list[RowResult]] = defaultdict(list)
    for row in rows:
        if row.event_id is not None:
            by_id[row.event_id].append(row)
        if not isinstance(row.record, dict):
            continue
        collection = row.record.get("collection")
        if isinstance(collection, dict) and _nonempty(collection.get("collection_id")):
            by_collection[collection["collection_id"]].append(row)
        file = row.record.get("file")
        if isinstance(file, dict) and isinstance(file.get("sha256"), str) and _SHA256.fullmatch(file["sha256"]):
            by_hash[file["sha256"].lower()].append(row)

    for group in by_id.values():
        if len({row.immutable_fingerprint for row in group}) > 1:
            for row in group:
                row.add_issue("immutable_id_conflict", "error", "This finding ID has conflicting source values outside disposition; all matching rows are withheld.", "event_id")
        revisions: dict[tuple[int, float], list[RowResult]] = defaultdict(list)
        for row in group:
            if "disposition_time" in row.normalized:
                revisions[(row.normalized["disposition_rank"], row.normalized["disposition_time"])].append(row)
        for tied in revisions.values():
            if len({canonical_json(row.record.get("disposition")) for row in tied}) > 1:
                for row in tied:
                    row.add_issue("ambiguous_disposition_revision", "error", "Different dispositions share the same revision rank/time; no winner is selected.", "disposition")

    for group in by_collection.values():
        valid_times = {row.normalized["collection_completed_at"] for row in group if "collection_completed_at" in row.normalized}
        if len(valid_times) > 1:
            for row in group:
                row.add_issue("collection_completion_conflict", "error", "The collection ID has different completion times; all rows in this collection are withheld.", "collection.completed_at")
    for group in by_hash.values():
        sizes = {row.normalized["file_size"] for row in group if "file_size" in row.normalized}
        if len(sizes) > 1:
            for row in group:
                row.add_issue("hash_size_conflict", "warning", "The same SHA-256 has differing reported file sizes in this snapshot.", "file.size")

    # Conflicts take precedence over duplicate classification, so a duplicate can
    # never hide a member of an ambiguous identity or collection group.
    retained: dict[str, int] = {}
    for row in rows:
        if row.status == "eligible":
            if row.event_version in retained:
                row.status = "duplicate"
                row.duplicate_of = retained[row.event_version]
            else:
                retained[row.event_version] = row.source_row
    return ValidationResult(source_sha256, rows)
