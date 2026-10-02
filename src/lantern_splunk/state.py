"""Durable request attempts and acceptance, scoped to the actual destination."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from urllib.parse import urlunsplit

from .transport import validate_endpoint


class StateError(RuntimeError):
    """A state operation failed; a sender must not guess its result."""


class StateLocked(StateError):
    """Another importer owns the ledger."""


def _hash(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class DeliveryScope:
    endpoint: str
    index: str
    source: str
    sourcetype: str
    mapping_version: str = "1"
    instance_id: str = "default"

    def __post_init__(self):
        parsed = validate_endpoint(self.endpoint)
        hostname = parsed.hostname.lower()
        if ":" in hostname:
            hostname = "[" + hostname + "]"
        authority = hostname + (":" + str(parsed.port) if parsed.port not in (None, 443) else "")
        endpoint = urlunsplit(("https", authority, parsed.path or "/services/collector/event", "", ""))
        object.__setattr__(self, "endpoint", endpoint)
        if any(not isinstance(value, str) or not value for value in asdict(self).values()):
            raise ValueError("Every delivery scope field must be a nonempty string.")

    @property
    def key(self) -> str:
        return _hash(asdict(self))

    @property
    def identity_key(self) -> str:
        value = asdict(self)
        value.pop("mapping_version")
        return _hash(value)


@dataclass(frozen=True)
class StateDecision:
    status: str  # new, previously_accepted, conflict
    reason: str = ""
    possible_duplicate: bool = False


class StateStore:
    def __init__(self, path: str | Path, scope: DeliveryScope):
        self.path = Path(path).expanduser().resolve()
        self.scope = scope
        self._connection = None
        self._lock = None

    def __enter__(self):
        if self._connection is not None or self._lock is not None:
            raise StateError("Ledger is already open.")
        try:
            import fcntl
        except ImportError:
            raise StateError("Ledger locking currently requires macOS or Linux.") from None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._lock = os.open(str(self.path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise StateLocked("Another importer is using this delivery ledger.") from None
            self._connection = sqlite3.connect(self.path, timeout=0)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA journal_mode=DELETE")
            self._connection.execute("""CREATE TABLE IF NOT EXISTS attempts (
                attempt_id INTEGER PRIMARY KEY,
                scope_key TEXT NOT NULL, identity_key TEXT NOT NULL,
                event_id TEXT NOT NULL, event_version TEXT NOT NULL,
                immutable_fingerprint TEXT NOT NULL,
                disposition_rank INTEGER NOT NULL, disposition_time REAL NOT NULL,
                disposition_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending','accepted','rejected','uncertain')),
                message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            )""")
            self._connection.execute("CREATE INDEX IF NOT EXISTS identity_lookup ON attempts(identity_key,event_id,status)")
            self._connection.execute("CREATE INDEX IF NOT EXISTS version_lookup ON attempts(scope_key,event_version,status)")
            # With the process lock held, every leftover pending request belongs
            # to an interrupted run. It might already be indexed remotely.
            self._connection.execute("UPDATE attempts SET status='uncertain', message='Recovered interrupted pending request.' WHERE status='pending'")
            self._connection.commit()
            os.chmod(self.path, 0o600)
            return self
        except (OSError, sqlite3.Error) as exc:
            self.close()
            raise StateError("Could not open or initialize the delivery ledger.") from None
        except BaseException:
            self.close()
            raise

    def close(self):
        try:
            if self._connection is not None:
                self._connection.close()
        finally:
            self._connection = None
            if self._lock is not None:
                os.close(self._lock)
                self._lock = None

    def __exit__(self, *_):
        self.close()

    def _db(self):
        if self._connection is None:
            raise StateError("Delivery ledger is not open.")
        return self._connection

    def _identity(self, envelope):
        try:
            event = envelope["event"]
            if any(envelope[key] != getattr(self.scope, key) for key in ("index", "source", "sourcetype")):
                raise ValueError
            if event["mapping_version"] != self.scope.mapping_version:
                raise ValueError
            return (
                self.scope.key, self.scope.identity_key, event["id"], event["event_version"],
                event["immutable_fingerprint"], event["disposition_rank"], event["disposition_time"],
                _hash(event["lantern"]["disposition"]),
            )
        except (KeyError, TypeError, ValueError):
            raise StateError("Envelope metadata is incomplete or does not match the delivery scope.") from None

    def check(self, envelope) -> StateDecision:
        identity = self._identity(envelope)
        scope_key, identity_key, event_id, version, immutable, rank, revision_time, disposition = identity
        try:
            rows = self._db().execute(
                "SELECT * FROM attempts WHERE identity_key=? AND event_id=? AND status IN ('accepted','uncertain','pending')",
                (identity_key, event_id),
            ).fetchall()
        except sqlite3.Error:
            raise StateError("Could not read the delivery ledger.") from None
        if any(row["immutable_fingerprint"] != immutable for row in rows):
            return StateDecision("conflict", "Previously accepted or uncertain finding has different immutable evidence; investigation required.")
        if any(row["disposition_rank"] == rank and row["disposition_time"] == revision_time
               and row["disposition_fingerprint"] != disposition for row in rows):
            return StateDecision("conflict", "Previously accepted or uncertain finding has a conflicting disposition at the same revision time; investigation required.")
        matching = [row for row in rows if row["scope_key"] == scope_key and row["event_version"] == version]
        uncertain = any(row["status"] in ("uncertain", "pending") for row in matching)
        if any(row["status"] == "accepted" for row in matching):
            return StateDecision("previously_accepted", "This source version was already accepted in this delivery scope.", uncertain)
        return StateDecision("new", possible_duplicate=uncertain)

    def begin_attempt(self, envelope) -> int:
        identity = self._identity(envelope)
        try:
            with self._db():
                cursor = self._db().execute(
                    "INSERT INTO attempts(scope_key,identity_key,event_id,event_version,immutable_fingerprint,disposition_rank,disposition_time,disposition_fingerprint,status) VALUES (?,?,?,?,?,?,?,?, 'pending')",
                    identity,
                )
            return cursor.lastrowid
        except sqlite3.Error:
            raise StateError("Could not persist a pending attempt; no request should be sent.") from None

    def finish_attempt(self, attempt_id: int, status: str, message: str = "") -> None:
        if status not in ("accepted", "rejected", "uncertain"):
            raise StateError("Invalid attempt completion status.")
        try:
            with self._db():
                cursor = self._db().execute(
                    "UPDATE attempts SET status=?,message=? WHERE attempt_id=? AND scope_key=? AND status='pending'",
                    (status, message, attempt_id, self.scope.key),
                )
                if cursor.rowcount != 1:
                    raise StateError("Pending attempt was not found; acceptance is not established.")
        except sqlite3.Error:
            raise StateError("Could not persist the request outcome; acceptance is uncertain.") from None

    def attempts(self) -> list[dict]:
        """Read-only diagnostic metadata; no payloads, tokens, or headers are stored."""
        try:
            return [dict(row) for row in self._db().execute("SELECT * FROM attempts ORDER BY attempt_id")]
        except sqlite3.Error:
            raise StateError("Could not read delivery attempts.") from None
