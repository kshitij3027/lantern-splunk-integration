"""Portable, non-secret TOML configuration and explicit credential loading."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
import tomllib


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Config:
    endpoint: str = "https://127.0.0.1:8088/services/collector/event"
    index: str = "volexity_lantern"
    source: str = "lantern:assessment"
    sourcetype: str = "lantern:indicator_match"
    instance_id: str = "local-prototype"
    ca_file: str | None = None
    tls_server_name: str | None = None
    token_file: str | None = None
    token_env: str = "SPLUNK_HEC_TOKEN"
    connect_timeout: float = 5.0
    read_timeout: float = 15.0
    max_attempts: int = 3

    def load_token(self) -> str:
        # Never echo token content, including in exception messages.
        value = os.environ.get(self.token_env, "")
        if not value and self.token_file:
            try:
                token_path = Path(self.token_file)
                if token_path.stat().st_mode & 0o077:
                    raise ConfigError("Token file must be owner-only; set its permissions to 600.")
                value = token_path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise ConfigError("Cannot read the configured token file.") from exc
        value = value.strip()
        if not value or any(c.isspace() for c in value):
            raise ConfigError("Provide a nonempty HEC token through the configured environment variable or token file.")
        return value


def load_config(path: str | Path | None) -> Config:
    if path is None:
        return Config()
    path = Path(path).expanduser().resolve()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError("Cannot read a valid TOML configuration.") from exc
    if set(data) != {"splunk"} or not isinstance(data["splunk"], dict):
        raise ConfigError("Configuration must contain exactly one [splunk] table.")
    values = dict(data["splunk"])
    unknown = set(values) - set(Config.__dataclass_fields__)
    if unknown:
        raise ConfigError("Unknown configuration keys: " + ", ".join(sorted(unknown)))
    for name, value in values.items():
        if name in {"connect_timeout", "read_timeout"}:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 120:
                raise ConfigError(f"{name} must be a number between 0 and 120 seconds.")
        elif name == "max_attempts":
            if type(value) is not int or not 1 <= value <= 3:
                raise ConfigError("max_attempts must be an integer from 1 to 3.")
        elif not isinstance(value, str) or (not value.strip() and name not in {"ca_file", "tls_server_name", "token_file"}):
            raise ConfigError(f"{name} must be a nonempty string.")
    for name in ("ca_file", "token_file"):
        value = values.get(name)
        if value:
            candidate = Path(value).expanduser()
            values[name] = str(candidate if candidate.is_absolute() else path.parent / candidate)
        elif name in values:
            values[name] = None
    if values.get("tls_server_name") == "":
        values["tls_server_name"] = None
    return Config(**values)
