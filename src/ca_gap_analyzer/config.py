"""Reads the tenant ID and client ID from .env (or real environment variables).

Environment variables win over .env, so a CI pipeline can set them without a file.
"""

import os
import re
from dataclasses import dataclass
from pathlib import Path

KEYS = ("CA_TENANT_ID", "CA_CLIENT_ID")
PLACEHOLDER = "00000000-0000-0000-0000-000000000000"
GUID = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")


class ConfigError(Exception):
    pass


@dataclass
class Settings:
    tenant_id: str
    client_id: str


def read_env_file(path: Path) -> dict[str, str]:
    """Parse simple NAME=value lines. Blank lines and # comments are skipped."""
    if not path.exists():
        return {}
    values = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name.strip()] = value.strip().strip("'\"")
    return values


def load_settings(env_file: Path = Path(".env"), environ=os.environ) -> Settings:
    values = read_env_file(env_file)
    values.update({k: environ[k] for k in KEYS if environ.get(k)})

    for key in KEYS:
        value = values.get(key, "")
        if not value:
            raise ConfigError(
                f"{key} is not set. Copy .env.example to .env and fill in your tenant ID and "
                f"client ID (looked in {env_file.resolve()})."
            )
        if value == PLACEHOLDER:
            raise ConfigError(f"{key} in {env_file} is still the placeholder. Replace it with your real ID.")
        if not GUID.match(value):
            raise ConfigError(f"{key} doesn't look like an ID (expected xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx): {value!r}")

    return Settings(tenant_id=values["CA_TENANT_ID"], client_id=values["CA_CLIENT_ID"])
