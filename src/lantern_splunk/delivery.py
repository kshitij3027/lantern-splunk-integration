"""Sequential delivery with bounded retries and explicit uncertainty."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import time
from typing import Callable, Iterable

from .state import StateError, StateStore
from .transport import HECClient


@dataclass
class DeliveryRecord:
    event_id: str
    event_version: str
    status: str
    attempts: int = 0
    message: str = ""
    possible_duplicate: bool = False


@dataclass
class DeliveryReport:
    records: list[DeliveryRecord] = field(default_factory=list)
    stopped: bool = False

    @property
    def counts(self) -> dict[str, int]:
        return {status: sum(record.status == status for record in self.records)
                for status in ("accepted", "previously_accepted", "rejected", "uncertain", "not_attempted")}

    @property
    def attempts(self) -> int:
        return sum(record.attempts for record in self.records)

    @property
    def has_failures(self) -> bool:
        return any(self.counts[key] for key in ("rejected", "uncertain", "not_attempted"))

    def to_dict(self) -> dict:
        return {"counts": self.counts, "request_attempts": self.attempts, "stopped": self.stopped,
                "possible_duplicate_records": sum(record.possible_duplicate for record in self.records),
                "records": [asdict(record) for record in self.records]}


def deliver(
    envelopes: Iterable[dict], client: HECClient, state: StateStore,
    max_attempts: int = 3, sleep: Callable[[float], None] = time.sleep,
) -> DeliveryReport:
    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or not 1 <= max_attempts <= 3:
        raise ValueError("The sender permits between one and three attempts per event.")
    report = DeliveryReport()
    for envelope in envelopes:
        event = envelope["event"]
        record = DeliveryRecord(event["id"], event["event_version"], "not_attempted")
        report.records.append(record)
        if report.stopped:
            record.message = "Run stopped before this event could be attempted."
            continue
        try:
            decision = state.check(envelope)
        except StateError as exc:
            record.message = str(exc)
            report.stopped = True
            continue
        record.possible_duplicate = decision.possible_duplicate
        if decision.status == "previously_accepted":
            record.status, record.message = decision.status, decision.reason
            continue
        if decision.status == "conflict":
            record.status, record.message = "rejected", decision.reason
            continue
        for attempt_number in range(1, max_attempts + 1):
            try:
                attempt_id = state.begin_attempt(envelope)
            except StateError as exc:
                record.status = "uncertain" if record.possible_duplicate else "not_attempted"
                record.message = str(exc)
                report.stopped = True
                break
            record.attempts += 1
            # Exceptions such as KeyboardInterrupt deliberately leave the durable
            # pending attempt intact. On restart it becomes uncertain.
            result = client.send(envelope)
            if result.kind not in ("accepted", "rejected", "retryable", "uncertain"):
                raise ValueError("Transport returned an invalid result classification.")
            if result.kind == "uncertain":
                record.possible_duplicate = True
            ledger_status = "rejected" if result.kind == "retryable" else result.kind
            try:
                state.finish_attempt(attempt_id, ledger_status, result.message)
            except StateError as exc:
                record.status = "uncertain"
                record.possible_duplicate = True
                record.message = str(exc)
                report.stopped = True
                break
            record.message = result.message
            if result.kind == "accepted":
                record.status = "accepted"
                break
            if result.kind == "rejected" or not result.retry_allowed or attempt_number == max_attempts:
                record.status = "uncertain" if record.possible_duplicate else "rejected"
                report.stopped = True
                break
            delay = result.retry_after if result.retry_after is not None else 0.5 * (2 ** (attempt_number - 1))
            sleep(min(5.0, max(0.0, delay)))
    return report
