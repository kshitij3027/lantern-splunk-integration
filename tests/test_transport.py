import json
import ssl
from types import SimpleNamespace

import pytest
import urllib3
from urllib3.util.ssl_match_hostname import CertificateError

from lantern_splunk.transport import HECClient, TransportConfigurationError, _retry_after


@pytest.fixture
def pool(monkeypatch):
    class FakePool:
        def __init__(self, host, port, **kwargs):
            self.host, self.port, self.options = host, port, kwargs
            self.calls = []
            self.response = SimpleNamespace(status=200, headers={}, data=b'{"code":0}')
            self.error = None
            self.closed = False

        def request(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            if self.error:
                raise self.error
            return self.response

        def close(self):
            self.closed = True

    instances = []

    def make(*args, **kwargs):
        instance = FakePool(*args, **kwargs)
        instances.append(instance)
        return instance

    monkeypatch.setattr(urllib3, "HTTPSConnectionPool", make)
    return instances


def test_request_checks_tls_disables_library_retries_and_redirects(pool):
    envelope = {"event": {"example": "synthetic"}}
    with HECClient("https://receiver.example:8088/services/collector/event", "dummy-token") as client:
        result = client.send(envelope)
    target = pool[0]
    args, kwargs = target.calls[0]
    assert result.kind == "accepted"
    assert args == ("POST", "/services/collector/event")
    assert json.loads(kwargs["body"]) == envelope
    assert kwargs["retries"] is False and kwargs["redirect"] is False
    assert kwargs["headers"]["Authorization"] == "Splunk dummy-token"
    assert kwargs["timeout"].connect_timeout == 5
    assert kwargs["timeout"].read_timeout == 15
    assert target.options["ssl_context"].verify_mode == ssl.CERT_REQUIRED
    assert target.options["ssl_context"].hostname_checks_common_name is False
    assert target.closed
    assert "dummy-token" not in repr(result)


@pytest.mark.parametrize("endpoint", [
    "http://localhost:8088/services/collector/event", "https://user:pass@receiver.example/",
    "https://receiver.example/?token=secret", "https://receiver.example/#secret",
    "https://receiver.example:bad/", "https://receiver.example:0/", "https:///missing-host",
])
def test_unsafe_endpoints_rejected(endpoint):
    with pytest.raises(TransportConfigurationError):
        HECClient(endpoint, "dummy-token")


def test_name_override_only_loopback_explicit_ca(pool, monkeypatch):
    with pytest.raises(TransportConfigurationError):
        HECClient("https://receiver.example", "dummy", ca_file="dummy.pem", tls_server_name="legacy-name")
    with pytest.raises(TransportConfigurationError):
        HECClient("https://127.0.0.1:8088", "dummy", tls_server_name="legacy-name")
    context = ssl.create_default_context()
    monkeypatch.setattr(ssl, "create_default_context", lambda **kwargs: context)
    HECClient("https://127.0.0.1:8088", "dummy", ca_file="dummy.pem", tls_server_name="legacy-name")
    assert context.hostname_checks_common_name is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert pool[-1].options["assert_hostname"] == "legacy-name"
    assert pool[-1].options["server_hostname"] == "legacy-name"


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), True, "5"])
def test_invalid_timeouts_rejected(timeout):
    with pytest.raises(TransportConfigurationError):
        HECClient("https://receiver.example", "dummy", connect_timeout=timeout)


@pytest.mark.parametrize("token", ["", "token\nheader", "token\x00", "token\u2603", None])
def test_invalid_header_token_has_safe_error(token):
    with pytest.raises(TransportConfigurationError, match="printable ASCII"):
        HECClient("https://receiver.example", token)


@pytest.mark.parametrize("status,body,kind", [
    (200, b'{"code":0}', "accepted"), (201, b'{"code":0}', "accepted"),
    (200, b'{"code":4}', "rejected"), (200, b'{"code":9}', "retryable"),
    (200, b'{"code":false}', "uncertain"), (200, b'{"code":"0"}', "uncertain"),
    (200, b'{}', "uncertain"), (200, b'[]', "uncertain"), (200, b'bad-json', "uncertain"),
    (200, b'\xff', "uncertain"), (204, b'', "uncertain"),
    (302, b'{"code":0}', "rejected"), (401, b'anything', "rejected"),
    (403, b'anything', "rejected"), (400, b'{"code":7}', "rejected"),
    (404, b'anything', "rejected"), (429, b'', "retryable"),
    (500, b'{"code":8}', "uncertain"), (503, b'bad-json', "uncertain"),
    (500, b'{"code":0}', "uncertain"),
    (500, b'{"code":4}', "rejected"), (503, b'{"code":7}', "rejected"),
])
def test_http_and_hec_must_both_succeed(pool, status, body, kind):
    client = HECClient("https://receiver.example", "dummy")
    pool[0].response = SimpleNamespace(status=status, data=body, headers={"Retry-After": "99"})
    result = client.send({"event": {}})
    assert result.kind == kind
    assert not result.retry_after or result.retry_after <= 5


@pytest.mark.parametrize("exception,kind,retry", [
    (urllib3.exceptions.ConnectTimeoutError("dummy secret detail"), "retryable", True),
    (urllib3.exceptions.NewConnectionError(None, "dummy secret detail"), "retryable", True),
    (urllib3.exceptions.ReadTimeoutError(None, "/", "dummy secret detail"), "uncertain", True),
    (urllib3.exceptions.ProtocolError("dummy secret detail"), "uncertain", True),
    (urllib3.exceptions.SSLError(ssl.SSLCertVerificationError("dummy secret detail")), "rejected", True),
    (urllib3.exceptions.SSLError(CertificateError("dummy secret detail")), "rejected", True),
    (urllib3.exceptions.SSLError("dummy secret detail"), "uncertain", False),
])
def test_transport_failure_classification_does_not_expose_exception(pool, exception, kind, retry):
    client = HECClient("https://receiver.example", "dummy")
    pool[0].error = exception
    result = client.send({"event": {}})
    assert result.kind == kind and result.retry_allowed is retry
    assert "secret" not in repr(result)


def test_retry_after_is_bounded_and_bad_values_ignored():
    assert _retry_after("1000") == 5
    assert _retry_after("-2") == 0
    assert _retry_after("2") == 2
    assert _retry_after("inf") is None
    assert _retry_after("invalid") is None
    assert _retry_after("Wed, 01 Jan 2020 00:00:00 GMT") == 0


def test_nonfinite_json_never_sent(pool):
    client = HECClient("https://receiver.example", "dummy")
    assert client.send({"event": {"score": float("nan")}}).kind == "rejected"
    assert pool[0].calls == []


@pytest.fixture(scope="module")
def ephemeral_certificates(tmp_path_factory):
    """Generate test-only TLS material; never check a private key into the repo."""
    import shutil
    import subprocess

    executable = shutil.which("openssl")
    if executable is None:
        pytest.skip("The real TLS receiver tests require the openssl command.")
    directory = tmp_path_factory.mktemp("synthetic-tls")
    pairs = {}
    for label, name, san in (("modern", "synthetic-receiver", "DNS:localhost,IP:127.0.0.1"),
                             ("legacy", "synthetic-legacy", None),
                             ("untrusted", "different-test-ca", None)):
        config = directory / (label + ".cnf")
        config.write_text(
            "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=extensions\n"
            f"[dn]\nCN={name}\n[extensions]\nbasicConstraints=critical,CA:TRUE\n"
            + (f"subjectAltName={san}\n" if san else ""), encoding="utf-8"
        )
        key, certificate = directory / (label + ".key"), directory / (label + ".pem")
        subprocess.run([executable, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "1", "-keyout", str(key), "-out", str(certificate),
                        "-config", str(config)], check=True, capture_output=True, timeout=15)
        pairs[label] = (certificate, key)
    return pairs


@pytest.fixture
def tls_receiver(ephemeral_certificates):
    """A real loopback HTTPS receiver with controllable HEC-shaped responses."""
    from contextlib import ExitStack, contextmanager
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    @contextmanager
    def start(kind="modern", status=200, body=b'{"code":0}'):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                received.append({"path": self.path, "body": json.loads(self.rfile.read(length)),
                                 "authorization": self.headers.get("Authorization")})
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        class QuietTLSHTTPServer(ThreadingHTTPServer):
            def handle_error(self, request, client_address):
                # Expected negative name/trust tests can close the TLS socket
                # before HTTP parsing. Suppress only those connection failures.
                import sys
                if not isinstance(sys.exc_info()[1], (ssl.SSLError, ConnectionError)):
                    super().handle_error(request, client_address)

        server = QuietTLSHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        certificate, key = ephemeral_certificates[kind]
        context.load_cert_chain(str(certificate), str(key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"https://127.0.0.1:{server.server_port}/services/collector/event", received
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    with ExitStack() as stack:
        yield lambda **kwargs: stack.enter_context(start(**kwargs))


def test_real_https_receiver_accepts_only_trusted_certificate(tls_receiver, ephemeral_certificates):
    endpoint, received = tls_receiver()
    envelope = {"event": {"synthetic": True, "id": "tls-smoke"}}
    with HECClient(endpoint, "dummy-not-a-real-token", ca_file=str(ephemeral_certificates["modern"][0])) as client:
        assert client.send(envelope).kind == "accepted"
    assert received == [{"path": "/services/collector/event", "body": envelope,
                         "authorization": "Splunk dummy-not-a-real-token"}]
    with HECClient(endpoint, "dummy", ca_file=str(ephemeral_certificates["untrusted"][0])) as client:
        result = client.send(envelope)
        assert result.kind == "rejected" and "certificate" in result.message
    assert len(received) == 1  # The failed TLS handshake sent no HTTP credentials or event.


def test_real_https_receiver_rejects_wrong_expected_name(tls_receiver, ephemeral_certificates):
    endpoint, received = tls_receiver()
    with HECClient(endpoint, "dummy", ca_file=str(ephemeral_certificates["modern"][0]),
                   tls_server_name="wrong-expected-name") as client:
        result = client.send({"event": {"synthetic": True}})
        assert result.kind == "rejected"
    assert received == []


def test_real_cn_only_certificate_requires_explicit_local_profile(tls_receiver, ephemeral_certificates):
    endpoint, received = tls_receiver(kind="legacy")
    ca = str(ephemeral_certificates["legacy"][0])
    with HECClient(endpoint, "dummy", ca_file=ca) as client:
        assert client.send({"event": {"synthetic": True}}).kind == "rejected"
    assert received == []
    with HECClient(endpoint, "dummy", ca_file=ca, tls_server_name="synthetic-legacy") as client:
        assert client.send({"event": {"synthetic": True}}).kind == "accepted"
    assert len(received) == 1


def test_real_hec_receiver_http_success_with_error_is_not_accepted(tls_receiver, ephemeral_certificates):
    endpoint, received = tls_receiver(status=200, body=b'{"code":7,"text":"Incorrect index"}')
    with HECClient(endpoint, "dummy", ca_file=str(ephemeral_certificates["modern"][0])) as client:
        assert client.send({"event": {"synthetic": True}}).kind == "rejected"
    assert len(received) == 1
