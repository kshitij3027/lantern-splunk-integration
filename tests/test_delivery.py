import pytest

from lantern_splunk.delivery import deliver
from lantern_splunk.state import StateError, StateStore
from lantern_splunk.transport import HECResult
from test_state import make_envelope, make_scope, record_attempt


class FakeClient:
    def __init__(self, *results):
        self.results = iter(results)
        self.calls = []

    def send(self, envelope):
        self.calls.append(envelope)
        result = next(self.results)
        if isinstance(result, BaseException):
            raise result
        return result


ACCEPT = HECResult("accepted", "Accepted.")
REJECT = HECResult("rejected", "Invalid token.")
RATE_LIMIT = HECResult("retryable", "Rate limited.", retry_after=999)
UNKNOWN = HECResult("uncertain", "Read timed out.")


def test_success_then_replay_sends_zero_and_reconciles_counts(tmp_path):
    rows = [make_envelope(event_id="synthetic-" + str(i), version="v" + str(i)) for i in range(3)]
    path = tmp_path / "state.db"
    with StateStore(path, make_scope()) as state:
        first_client = FakeClient(ACCEPT, ACCEPT, ACCEPT)
        report = deliver(rows, first_client, state)
        assert report.counts["accepted"] == 3 and report.attempts == 3
        assert not report.has_failures
    with StateStore(path, make_scope()) as state:
        replay_client = FakeClient()
        report = deliver(rows, replay_client, state)
        assert report.counts["previously_accepted"] == 3 and report.attempts == 0
        assert replay_client.calls == []
        assert sum(report.counts.values()) == len(rows)


def test_pending_is_durable_before_request(tmp_path):
    with StateStore(tmp_path / "state.db", make_scope()) as state:
        class AssertingClient:
            def send(self, envelope):
                assert state.attempts()[-1]["status"] == "pending"
                return ACCEPT
        assert deliver([make_envelope()], AssertingClient(), state).counts["accepted"] == 1


def test_explicit_retry_bounded_and_no_duplicate_warning(tmp_path):
    sleeps = []
    with StateStore(tmp_path / "state.db", make_scope()) as state:
        report = deliver([make_envelope()], FakeClient(RATE_LIMIT, ACCEPT), state, sleep=sleeps.append)
        assert report.counts["accepted"] == 1 and report.attempts == 2
        assert not report.records[0].possible_duplicate
        assert sleeps == [5]
        assert [row["status"] for row in state.attempts()] == ["rejected", "accepted"]


def test_unknown_retry_success_retains_possible_duplicate(tmp_path):
    with StateStore(tmp_path / "state.db", make_scope()) as state:
        report = deliver([make_envelope()], FakeClient(UNKNOWN, ACCEPT), state, sleep=lambda _: None)
        assert report.counts["accepted"] == 1
        assert report.records[0].possible_duplicate
        assert report.to_dict()["possible_duplicate_records"] == 1
        assert [row["status"] for row in state.attempts()] == ["uncertain", "accepted"]


@pytest.mark.parametrize("result,attempts,status", [(REJECT, 1, "rejected"), (RATE_LIMIT, 3, "rejected"), (UNKNOWN, 3, "uncertain")])
def test_failure_stops_remaining_records(tmp_path, result, attempts, status):
    with StateStore(tmp_path / "state.db", make_scope()) as state:
        client = FakeClient(result, result, result)
        report = deliver([make_envelope(), make_envelope("v2", event_id="synthetic-002")], client, state, sleep=lambda _: None)
        assert report.stopped
        assert report.counts[status] == 1 and report.counts["not_attempted"] == 1
        assert report.attempts == attempts


def test_permanent_error_after_uncertain_attempt_stays_uncertain(tmp_path):
    with StateStore(tmp_path / "state.db", make_scope()) as state:
        report = deliver([make_envelope()], FakeClient(UNKNOWN, REJECT), state, sleep=lambda _: None)
        assert report.counts["uncertain"] == 1


def test_state_write_failure_before_request_sends_nothing(tmp_path, monkeypatch):
    with StateStore(tmp_path / "state.db", make_scope()) as state:
        def fail(_):
            raise StateError("Storage unavailable.")
        monkeypatch.setattr(state, "begin_attempt", fail)
        client = FakeClient()
        report = deliver([make_envelope()], client, state)
        assert report.counts["not_attempted"] == 1 and report.attempts == 0
        assert client.calls == []


def test_acceptance_write_failure_is_uncertain_and_recovered(tmp_path, monkeypatch):
    path = tmp_path / "state.db"
    with StateStore(path, make_scope()) as state:
        def fail(*_):
            raise StateError("Could not save acceptance.")
        monkeypatch.setattr(state, "finish_attempt", fail)
        report = deliver([make_envelope()], FakeClient(ACCEPT), state)
        assert report.counts["uncertain"] == 1 and report.counts["accepted"] == 0
        assert state.attempts()[0]["status"] == "pending"
    with StateStore(path, make_scope()) as state:
        assert state.check(make_envelope()).possible_duplicate


def test_keyboard_interrupt_recovers_uncertainty(tmp_path):
    path = tmp_path / "state.db"
    with StateStore(path, make_scope()) as state:
        with pytest.raises(KeyboardInterrupt):
            deliver([make_envelope()], FakeClient(KeyboardInterrupt()), state)
    with StateStore(path, make_scope()) as state:
        assert state.attempts()[0]["status"] == "uncertain"


def test_cross_run_conflict_is_reported_without_sending_and_other_ids_continue(tmp_path):
    with StateStore(tmp_path / "state.db", make_scope()) as state:
        record_attempt(state, make_envelope())
        client = FakeClient(ACCEPT)
        report = deliver([make_envelope("changed", immutable="changed"), make_envelope("other", event_id="other")], client, state)
        assert report.counts["rejected"] == 1 and report.counts["accepted"] == 1
        assert len(client.calls) == 1 and client.calls[0]["event"]["id"] == "other"


def test_recovered_uncertain_version_warns_even_if_first_retry_succeeds(tmp_path):
    path = tmp_path / "state.db"
    with StateStore(path, make_scope()) as state:
        state.begin_attempt(make_envelope())
    with StateStore(path, make_scope()) as state:
        report = deliver([make_envelope()], FakeClient(ACCEPT), state)
        assert report.counts["accepted"] == 1 and report.records[0].possible_duplicate
