import pytest
from lantern_splunk.config import Config, ConfigError, load_config


def test_default_config_does_not_need_credentials():
    assert load_config(None).index == 'volexity_lantern'


def test_relative_paths_are_based_on_config_file(tmp_path):
    config = tmp_path / 'config.toml'
    config.write_text('[splunk]\nca_file="cert.pem"\ntoken_file="secret"\n')
    result = load_config(config)
    assert result.ca_file == str(tmp_path / 'cert.pem')
    assert result.token_file == str(tmp_path / 'secret')


@pytest.mark.parametrize('body', ['other=1', '[splunk]\ntimeout=7', '[splunk]\nmax_attempts=true', '[splunk]\nread_timeout=-1', '[splunk]\nsource=2', '[splunk]\nindex=""'])
def test_invalid_configuration_is_explicit(tmp_path, body):
    p = tmp_path / 'config.toml'; p.write_text(body)
    with pytest.raises(ConfigError): load_config(p)


def test_environment_wins_and_missing_token_error_never_echoes_secret(tmp_path, monkeypatch):
    p = tmp_path / 'token'; p.write_text('file-value'); p.chmod(0o600)
    monkeypatch.setenv('TEST_HEC_TOKEN', 'env-value')
    assert Config(token_file=str(p), token_env='TEST_HEC_TOKEN').load_token() == 'env-value'
    monkeypatch.setenv('TEST_HEC_TOKEN', 'private invalid value')
    with pytest.raises(ConfigError) as err:
        Config(token_env='TEST_HEC_TOKEN').load_token()
    assert 'private' not in str(err.value)


def test_missing_token_file_does_not_echo_path(tmp_path, monkeypatch):
    monkeypatch.delenv('SPLUNK_HEC_TOKEN', raising=False)
    with pytest.raises(ConfigError) as err:
        Config(token_file=str(tmp_path / 'secret-name')).load_token()
    assert 'secret-name' not in str(err.value)


def test_token_file_requires_private_permissions(tmp_path, monkeypatch):
    monkeypatch.delenv('SPLUNK_HEC_TOKEN', raising=False)
    p = tmp_path/'token'; p.write_text('private-token'); p.chmod(0o644)
    with pytest.raises(ConfigError, match='owner-only'):
        Config(token_file=str(p)).load_token()
    p.chmod(0o600)
    assert Config(token_file=str(p)).load_token() == 'private-token'
