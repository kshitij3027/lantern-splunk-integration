"""One verified HTTPS request to Splunk HEC; retry policy lives in delivery."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import ipaddress
import json
import math
import ssl
from urllib.parse import urlsplit

import urllib3
from urllib3.util.ssl_match_hostname import CertificateError


class TransportConfigurationError(ValueError):
    """The sender cannot safely use its configured connection."""


@dataclass(frozen=True)
class HECResult:
    kind: str  # accepted, rejected, retryable (explicit rejection), or uncertain
    message: str
    retry_after: float | None = None
    retry_allowed: bool = True


def _retry_after(value: str | None) -> float | None:
    """Honor a server's delay without letting it suspend a CLI run indefinitely."""
    if not value:
        return None
    try:
        delay = float(value)
    except (TypeError, ValueError):
        try:
            date = parsedate_to_datetime(value)
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            delay = (date - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return None
    return min(5.0, max(0.0, delay)) if math.isfinite(delay) else None


def validate_endpoint(endpoint: str):
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise TransportConfigurationError("Invalid HEC endpoint.") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(char.isspace() for char in endpoint)
    ):
        raise TransportConfigurationError(
            "HEC requires an HTTPS URL without credentials, query, or fragment."
        )
    if port is not None and port == 0:
        raise TransportConfigurationError("Invalid HEC port.")
    return parsed


class HECClient:
    """No implicit retries, redirects, plaintext transport, or unverified TLS."""

    def __init__(
        self,
        endpoint: str,
        token: str,
        ca_file: str | None = None,
        tls_server_name: str | None = None,
        connect_timeout: float = 5,
        read_timeout: float = 15,
    ):
        parsed = validate_endpoint(endpoint)
        if not isinstance(token, str) or not token or not token.isascii() or not token.isprintable() or any(char.isspace() for char in token):
            raise TransportConfigurationError("The HEC token must contain printable ASCII without whitespace.")
        if any(
            isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value <= 0
            for value in (connect_timeout, read_timeout)
        ):
            raise TransportConfigurationError("Connection timeouts must be positive finite seconds.")
        if tls_server_name:
            try:
                loopback = ipaddress.ip_address(parsed.hostname).is_loopback
            except ValueError:
                loopback = False
            if not loopback or not ca_file:
                raise TransportConfigurationError(
                    "A TLS name override requires a literal loopback endpoint and explicit CA."
                )
            if any(char.isspace() for char in tls_server_name):
                raise TransportConfigurationError("Invalid local TLS certificate name.")
        try:
            context = ssl.create_default_context(cafile=ca_file)
        except (OSError, ssl.SSLError):
            raise TransportConfigurationError("Could not load the configured TLS trust store.") from None
        # The local Splunk certificate is CN-only. Never apply that compatibility
        # rule to a normal remote destination, or disable chain/name verification.
        context.hostname_checks_common_name = bool(tls_server_name)
        context.verify_mode = ssl.CERT_REQUIRED
        options = {"ssl_context": context, "cert_reqs": ssl.CERT_REQUIRED}
        if tls_server_name:
            options.update(server_hostname=tls_server_name, assert_hostname=tls_server_name)
        self._pool = urllib3.HTTPSConnectionPool(
            parsed.hostname, port=parsed.port or 443, **options
        )
        self._path = parsed.path or "/services/collector/event"
        self._token = token
        self._timeout = urllib3.Timeout(connect=connect_timeout, read=read_timeout)

    def close(self) -> None:
        self._pool.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def send(self, envelope: dict) -> HECResult:
        try:
            body = json.dumps(envelope, ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError):
            return HECResult("rejected", "Envelope is not finite JSON.")
        try:
            response = self._pool.request(
                "POST", self._path, body=body,
                headers={"Authorization": "Splunk " + self._token, "Content-Type": "application/json"},
                timeout=self._timeout, retries=False, redirect=False,
            )
        except (urllib3.exceptions.NewConnectionError, urllib3.exceptions.ConnectTimeoutError):
            return HECResult("retryable", "Connection failed before the request was sent.")
        except urllib3.exceptions.SSLError as exc:
            # Certificate failures are definite pre-send failures; other TLS
            # failures can occur after bytes have reached the destination.
            reason = exc.args[0] if exc.args else None
            if isinstance(reason, (ssl.SSLCertVerificationError, CertificateError)):
                return HECResult("rejected", "TLS certificate verification failed.")
            return HECResult("uncertain", "TLS negotiation or connection failed.", retry_allowed=False)
        except (urllib3.exceptions.ReadTimeoutError, urllib3.exceptions.ProtocolError):
            return HECResult("uncertain", "The response was lost; the event may have arrived.")
        except urllib3.exceptions.HTTPError:
            return HECResult("uncertain", "Transport failed; acceptance could not be established.")

        status = response.status
        delay = _retry_after(response.headers.get("Retry-After"))
        try:
            payload = json.loads(response.data) if len(response.data) <= 65536 else None
        except (ValueError, UnicodeError):
            payload = None
        code = payload.get("code") if isinstance(payload, dict) else None
        valid_code = isinstance(code, int) and not isinstance(code, bool)
        if 200 <= status < 300 and valid_code and code == 0:
            return HECResult("accepted", "HEC accepted the event.")
        if 300 <= status < 400:
            return HECResult("rejected", "HEC redirected the request; redirects are disabled.")
        if status in (401, 403):
            return HECResult("rejected", "HEC authentication or permission was rejected.")
        if valid_code and code in (1, 2, 3, 4, 7):
            return HECResult("rejected", "HEC rejected the token or index configuration (code %d)." % code)
        if valid_code and code == 8:
            return HECResult("uncertain", "HEC reported an internal ingestion error; acceptance is uncertain.", delay)
        if status == 429:
            return HECResult("retryable", "HEC rate limited the request.", delay)
        if status == 408 or status >= 500:
            kind = "retryable" if valid_code and code != 0 else "uncertain"
            return HECResult(kind, "HEC reported a transient server failure.", delay)
        if valid_code and code != 0:
            if code == 9:
                return HECResult("retryable", "HEC reported a temporary ingestion error.", delay)
            return HECResult("rejected", "HEC rejected the event (code %d)." % code)
        if 400 <= status < 500:
            return HECResult("rejected", "HEC rejected the HTTP request (status %d)." % status)
        return HECResult("uncertain", "HEC acceptance response was missing or invalid.")
