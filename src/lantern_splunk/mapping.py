"""Deterministic mapping policy 1: selected Alerts vocabulary plus evidence."""

from copy import deepcopy
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from .models import RowResult

MAPPING_VERSION = "1"


def severity_label(score: int) -> str:
    if type(score) is not int or not 0 <= score <= 100:
        raise ValueError("Severity score must be an integer from 0 through 100.")
    for upper, label in ((19, "informational"), (39, "low"), (69, "medium"), (89, "high"), (100, "critical")):
        if score <= upper:
            return label
    raise AssertionError("Unreachable severity value")


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def map_record(
    row: RowResult,
    source_sha256: str,
    index: str,
    source: str = "lantern:assessment",
    sourcetype: str = "lantern:indicator_match",
) -> dict[str, Any]:
    """Map an eligible row without changing it or deriving unsupported facts."""
    if row.status != "eligible":
        raise ValueError("Only eligible validated rows may be mapped.")
    for name, value in (("index", index), ("source", source), ("sourcetype", sourcetype)):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a nonempty string.")
    record = row.record
    host, rule, file, collection, disposition = (
        record[field] for field in ("host", "rule", "file", "collection", "disposition")
    )
    os_name = host.get("os")
    filename = None
    if os_name == "WINDOWS":
        filename = PureWindowsPath(file["path"]).name
    elif isinstance(os_name, str) and os_name in {"LINUX", "MACOS"}:
        filename = PurePosixPath(file["path"]).name
    rule_version = rule.get("version")
    event = {
        "app": "Lantern",
        "type": "event",
        "id": record["event_id"],
        "lantern_event_type": record["event_type"],
        "dest": host["hostname"],
        "host_id": host["host_id"],
        "dest_ip": None if "invalid_host_ip" in row.quality_flags else _text(host.get("ip")),
        "host_os": _text(os_name),
        "agent_version": _text(host.get("agent_version")),
        "severity_id": record["severity"],
        "severity": severity_label(record["severity"]),
        "signature": rule["name"],
        "rule_namespace": _text(rule.get("namespace")),
        "rule_version": rule_version if type(rule_version) is int and rule_version >= 0 else None,
        "rule_author": _text(rule.get("author")),
        "file_path": file["path"],
        "file_name": filename,
        "file_hash": file["sha256"].lower(),
        "file_hash_algorithm": "sha256",
        "file_size": row.normalized["file_size"],
        "file_mtime": file["mtime"],
        "file_owner": _text(file.get("owner")),
        "collection_id": collection["collection_id"],
        "collection_job": _text(collection.get("job_name")),
        "collection_requested_by": _text(collection.get("requested_by")),
        "collection_completed_at": collection["completed_at"],
        "pattern_count": len(record["matched_patterns"]),
        "disposition_status": disposition["status"],
        "disposition_analyst": disposition.get("analyst") if isinstance(disposition.get("analyst"), str) else None,
        "disposition_comment": disposition.get("comment") if isinstance(disposition.get("comment"), str) else None,
        "disposition_updated_at": disposition.get("updated_at"),
        "disposition_rank": row.normalized["disposition_rank"],
        "disposition_time": row.normalized["disposition_time"],
        "mapping_version": MAPPING_VERSION,
        "event_version": row.event_version,
        "immutable_fingerprint": row.immutable_fingerprint,
        "source_sha256": source_sha256,
        "source_row": row.source_row,
        "quality_flags": row.quality_flags,
        "lantern": deepcopy(record),
    }
    return {
        "time": row.normalized["timestamp"],
        "host": host["hostname"],
        "index": index,
        "source": source,
        "sourcetype": sourcetype,
        "event": event,
    }
