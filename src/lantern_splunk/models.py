"""Small, serializable result types shared by validation and reporting."""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Issue:
    code: str
    level: str
    message: str
    field: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RowResult:
    source_row: int
    record: Any
    event_id: str | None = None
    status: str = "eligible"
    issues: list[Issue] = field(default_factory=list)
    immutable_fingerprint: str = ""
    event_version: str = ""
    normalized: dict[str, Any] = field(default_factory=dict)
    duplicate_of: int | None = None

    @property
    def quality_flags(self) -> list[str]:
        return sorted({issue.code for issue in self.issues if issue.level == "warning"})

    def add_issue(self, code: str, level: str, message: str, field: str = "") -> None:
        issue = Issue(code, level, message, field)
        if issue not in self.issues:
            self.issues.append(issue)
        if level == "error":
            self.status = "quarantined"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationResult:
    source_sha256: str
    rows: list[RowResult]

    @property
    def summary(self) -> dict[str, int]:
        eligible = [row for row in self.rows if row.status == "eligible"]
        with_warnings = sum(bool(row.quality_flags) for row in eligible)
        return {
            "total": len(self.rows),
            "eligible": len(eligible),
            "quarantined": sum(row.status == "quarantined" for row in self.rows),
            "duplicate": sum(row.status == "duplicate" for row in self.rows),
            "warning_rows": sum(bool(row.quality_flags) for row in self.rows),
            "eligible_with_warnings": with_warnings,
            "eligible_without_warnings": len(eligible) - with_warnings,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_sha256": self.source_sha256,
            "summary": self.summary,
            "rows": [row.to_dict() for row in self.rows],
        }
