import copy
import hashlib
import json
from pathlib import Path

import pytest
from lantern_splunk import cli
from lantern_splunk.transport import HECResult
from synthetic_validation import finding


def input_file(tmp_path, records=None):
    path = tmp_path / 'input.json'
    path.write_text(json.dumps(records if records is not None else [finding()]))
    return path


def read_report(tmp_path, name='validation-report.json'):
    return json.loads((tmp_path / 'out' / name).read_text())


def test_validate_retains_source_and_needs_no_network(tmp_path, monkeypatch, capsys):
    source = input_file(tmp_path)
    before = source.read_bytes()
    monkeypatch.setattr(cli, 'HECClient', lambda *a: pytest.fail('validation contacted HEC'))
    assert cli.main(['validate', '--input', str(source), '--output', str(tmp_path/'out')]) == 0
    report = read_report(tmp_path)
    assert report['summary']['eligible'] == 1
    assert report['source_sha256'] == hashlib.sha256(before).hexdigest()
    assert source.read_bytes() == before
    assert '1 eligible' in capsys.readouterr().out


def test_dry_run_reports_warnings_and_quarantine_without_token_or_ledger(tmp_path, monkeypatch):
    good = finding()
    warning = finding('synthetic-warning', file__size='1200')
    bad = finding('synthetic-invalid'); del bad['host']
    source = input_file(tmp_path, [good, warning, bad])
    monkeypatch.delenv('SPLUNK_HEC_TOKEN', raising=False)
    monkeypatch.setattr(cli, 'HECClient', lambda *a: pytest.fail('dry run contacted HEC'))
    state = tmp_path/'never.sqlite'
    assert cli.main(['send','--dry-run','--input',str(source),'--state',str(state),'--output',str(tmp_path/'out')]) == 2
    assert not state.exists()
    mapped = [json.loads(line) for line in (tmp_path/'out/mapped-events.jsonl').read_text().splitlines()]
    assert len(mapped) == 2
    assert mapped[1]['event']['lantern']['file']['size'] == '1200'
    assert read_report(tmp_path,'quarantine.json')[0]['record'] == bad
    assert read_report(tmp_path,'run-report.json')['status'] == 'completed_with_quality_issues'


@pytest.mark.parametrize('body', ['{', '{}', '[{"severity":1,"severity":2}]', '[NaN]', '[Infinity]', '\ufeffnot-json'])
def test_bad_documents_fail_before_network(tmp_path, monkeypatch, body):
    source = tmp_path/'input.json'; source.write_text(body)
    monkeypatch.setattr(cli, 'HECClient', lambda *a: pytest.fail('invalid input contacted HEC'))
    assert cli.main(['send','--dry-run','--input',str(source),'--output',str(tmp_path/'out')]) == 1
    assert read_report(tmp_path,'run-report.json')['status'] == 'operational_failure'
    assert not (tmp_path/'out/mapped-events.jsonl').exists()


def test_reports_cannot_overwrite_input(tmp_path):
    source = tmp_path/'validation-report.json'; source.write_text('[]')
    assert cli.main(['validate','--input',str(source),'--output',str(tmp_path)]) == 1
    assert source.read_text() == '[]'


def test_live_send_requires_explicit_destination_and_state(tmp_path):
    source = input_file(tmp_path)
    assert cli.main(['send','--input',str(source),'--output',str(tmp_path/'out')]) == 1


def test_live_send_and_replay_use_real_ledger(tmp_path, monkeypatch):
    calls = []
    class FakeClient:
        def __init__(self, *a): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def send(self, envelope):
            calls.append(copy.deepcopy(envelope))
            return HECResult('accepted', 'HEC accepted the event.')
    monkeypatch.setattr(cli, 'HECClient', FakeClient)
    monkeypatch.setenv('SPLUNK_HEC_TOKEN', 'synthetic-test-token')
    source = input_file(tmp_path)
    config = tmp_path/'config.toml'; config.write_text('[splunk]\nendpoint="https://splunk.example/services/collector/event"\n')
    args = ['send','--input',str(source),'--output',str(tmp_path/'out'),'--config',str(config),'--state',str(tmp_path/'state.sqlite')]
    assert cli.main(args) == 0
    assert len(calls) == 1
    assert read_report(tmp_path,'delivery-report.json')['counts']['accepted'] == 1
    assert cli.main(args) == 0
    assert len(calls) == 1
    assert read_report(tmp_path,'delivery-report.json')['counts']['previously_accepted'] == 1
    assert read_report(tmp_path,'delivery-report.json')['request_attempts'] == 0
    assert 'synthetic-test-token' not in ''.join(p.read_text() for p in (tmp_path/'out').iterdir())


def test_auth_failure_has_delivery_report_and_operational_exit(tmp_path, monkeypatch):
    class RejectedClient:
        def __init__(self, *a): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def send(self, _): return HECResult('rejected','HEC authentication or permission was rejected.')
    monkeypatch.setattr(cli, 'HECClient', RejectedClient)
    monkeypatch.setenv('SPLUNK_HEC_TOKEN', 'synthetic-token')
    source = input_file(tmp_path, [finding(), finding('synthetic-second')])
    config=tmp_path/'config.toml'; config.write_text('[splunk]\n')
    assert cli.main(['send','--input',str(source),'--output',str(tmp_path/'out'),'--config',str(config),'--state',str(tmp_path/'state.sqlite')]) == 1
    report=read_report(tmp_path,'delivery-report.json')
    assert report['counts']['rejected'] == 1
    assert report['counts']['not_attempted'] == 1
    assert report['request_attempts'] == 1


def test_reports_are_private_files(tmp_path):
    source=input_file(tmp_path)
    assert cli.main(['validate','--input',str(source),'--output',str(tmp_path/'out')]) == 0
    for path in (tmp_path/'out').iterdir():
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('key', ['token_file', 'ca_file'])
@pytest.mark.parametrize('report_name', ['run-report.json', 'validation-report.json', 'mapped-events.jsonl'])
def test_report_paths_cannot_overwrite_configured_secret_or_trust(tmp_path, key, report_name):
    source = input_file(tmp_path)
    out = tmp_path/'out'; out.mkdir()
    protected = out/report_name; protected.write_text('synthetic protected material')
    config = tmp_path/'config.toml'
    config.write_text(f'[splunk]\n{key}="out/{report_name}"\n')
    assert cli.main(['send','--dry-run','--input',str(source),'--config',str(config),'--output',str(out)]) == 1
    assert protected.read_text() == 'synthetic protected material'
