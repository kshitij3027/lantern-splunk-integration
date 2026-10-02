"""Reports are separate from delivery state and never contain credentials."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile


def write_json(path: Path, value: object) -> None:
    write_text(path, json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n")


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Atomic replacement prevents a half-written report from looking complete.
    fd, temp = tempfile.mkstemp(prefix=".report-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(value)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def write_validation(result, outdir: Path) -> None:
    report = result.to_dict()
    write_json(outdir / "validation-report.json", report)
    # Keep exact rejected values, not repaired substitutes.
    write_json(outdir / "quarantine.json", [r.to_dict() for r in result.rows if r.status == "quarantined"])
    summary = result.summary
    lines = ["LANTERN VALIDATION REPORT", "", f"Source SHA-256: {result.source_sha256}", ""]
    lines.extend(f"{key}: {value}" for key, value in summary.items())
    lines.extend(["", "RECORD ISSUES (row numbers are one-based)"])
    for row in result.rows:
        for issue in row.issues:
            lines.append(f"Row {row.source_row} | {row.event_id or '(no id)'} | {row.status} | {issue.level} | {issue.code} | {issue.field}: {issue.message}")
    write_text(outdir / "validation-report.txt", "\n".join(lines) + "\n")


def write_preview(envelopes: list[dict], outdir: Path) -> None:
    write_text(outdir / "mapped-events.jsonl", "".join(json.dumps(e, ensure_ascii=False, allow_nan=False) + "\n" for e in envelopes))
