from dataclasses import replace
import os
import subprocess
import sys

import pytest

from lantern_splunk.state import DeliveryScope, StateError, StateLocked, StateStore


def make_scope(**overrides):
    values = dict(endpoint="https://receiver.example/services/collector/event", index="synthetic",
                  source="lantern:synthetic", sourcetype="lantern:indicator_match")
    values.update(overrides)
    return DeliveryScope(**values)


def make_envelope(version="v1", immutable="original", rank=0, revision_time=0.0,
                  disposition=None, scope=None, event_id="synthetic-001"):
    scope = scope or make_scope()
    disposition = disposition or {"status": "UNREVIEWED", "analyst": None, "comment": None, "updated_at": None}
    return {"index": scope.index, "source": scope.source, "sourcetype": scope.sourcetype,
            "event": {"id": event_id, "event_version": version, "immutable_fingerprint": immutable,
                      "mapping_version": scope.mapping_version, "disposition_rank": rank,
                      "disposition_time": revision_time, "lantern": {"disposition": disposition}}}


def record_attempt(state, envelope, status="accepted"):
    number = state.begin_attempt(envelope)
    state.finish_attempt(number, status)


def test_acceptance_persists_and_skip_is_scope_specific(tmp_path):
    path, scope = tmp_path / "ledger.db", make_scope()
    envelope = make_envelope()
    with StateStore(path, scope) as state:
        assert state.check(envelope).status == "new"
        record_attempt(state, envelope)
    with StateStore(path, scope) as state:
        assert state.check(envelope).status == "previously_accepted"
    for changes in ({"index": "other"}, {"source": "other"}, {"sourcetype": "other"},
                    {"mapping_version": "2"}, {"instance_id": "rebuilt"}, {"endpoint": "https://other.example"}):
        other = replace(scope, **changes)
        with StateStore(path, other) as state:
            assert state.check(make_envelope(scope=other)).status == "new"


def test_scope_does_not_include_token_and_normalizes_default_port():
    assert make_scope(endpoint="https://RECEIVER.example:443/services/collector/event").key == make_scope().key
    assert "token" not in make_scope().__dict__


@pytest.mark.parametrize("status", ["accepted", "uncertain", "pending"])
def test_known_or_uncertain_identity_blocks_changed_immutable(tmp_path, status):
    scope = make_scope()
    with StateStore(tmp_path / "state.db", scope) as state:
        attempt = state.begin_attempt(make_envelope())
        if status != "pending":
            state.finish_attempt(attempt, status)
        assert state.check(make_envelope(version="v2", immutable="changed")).status == "conflict"


def test_explicit_rejection_does_not_reserve_finding_identity(tmp_path):
    with StateStore(tmp_path / "state.db", make_scope()) as state:
        record_attempt(state, make_envelope(), "rejected")
        assert state.check(make_envelope(version="v2", immutable="changed")).status == "new"


@pytest.mark.parametrize("status", ["accepted", "uncertain"])
def test_tied_disposition_conflict_but_older_history_allowed(tmp_path, status):
    with StateStore(tmp_path / "state.db", make_scope()) as state:
        record_attempt(state, make_envelope("v2", rank=1, revision_time=1000,
                                           disposition={"status": "MALICIOUS"}), status)
        tied = make_envelope("v3", rank=1, revision_time=1000, disposition={"status": "BENIGN"})
        assert state.check(tied).status == "conflict"
        assert state.check(make_envelope()).status == "new"
        newer = make_envelope("v4", rank=1, revision_time=2000, disposition={"status": "BENIGN"})
        assert state.check(newer).status == "new"


def test_conflict_checks_survive_mapping_version_changes(tmp_path):
    path, scope = tmp_path / "state.db", make_scope()
    with StateStore(path, scope) as state:
        record_attempt(state, make_envelope())
    changed = replace(scope, mapping_version="2")
    with StateStore(path, changed) as state:
        assert state.check(make_envelope(scope=changed, immutable="changed")).status == "conflict"


def test_interrupted_pending_is_uncertain_on_recovery(tmp_path):
    path = tmp_path / "state.db"
    with StateStore(path, make_scope()) as state:
        state.begin_attempt(make_envelope())
    with StateStore(path, make_scope()) as state:
        assert state.attempts()[0]["status"] == "uncertain"
        decision = state.check(make_envelope())
        assert decision.status == "new" and decision.possible_duplicate
        record_attempt(state, make_envelope())
        decision = state.check(make_envelope())
        assert decision.status == "previously_accepted" and decision.possible_duplicate


def test_concurrent_ledger_user_refused_and_released_after_close(tmp_path):
    path = tmp_path / "state.db"
    with StateStore(path, make_scope()):
        with pytest.raises(StateLocked):
            with StateStore(path, make_scope()):
                pytest.fail("Concurrent ledger unexpectedly opened")
    with StateStore(path, make_scope()) as state:
        assert state.attempts() == []


def test_other_process_cannot_open_active_ledger(tmp_path):
    path = tmp_path / "state.db"
    script = """
import sys
from lantern_splunk.state import DeliveryScope, StateStore, StateLocked
scope = DeliveryScope('https://receiver.example/services/collector/event', 'synthetic',
                      'lantern:synthetic', 'lantern:indicator_match')
try:
    with StateStore(sys.argv[1], scope):
        pass
except StateLocked:
    sys.exit(0)
sys.exit(1)
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(__import__("pathlib").Path(__file__).resolve().parents[1] / "src")
    with StateStore(path, make_scope()):
        result = subprocess.run([sys.executable, "-c", script, str(path)], env=environment,
                                capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_wrong_scope_cannot_record_attempt(tmp_path):
    with StateStore(tmp_path / "state.db", make_scope()) as state:
        envelope = make_envelope()
        envelope["source"] = "wrong"
        with pytest.raises(StateError):
            state.begin_attempt(envelope)
        assert state.attempts() == []


def test_missing_attempt_cannot_be_falsely_accepted(tmp_path):
    with StateStore(tmp_path / "state.db", make_scope()) as state:
        with pytest.raises(StateError):
            state.finish_attempt(999, "accepted")
