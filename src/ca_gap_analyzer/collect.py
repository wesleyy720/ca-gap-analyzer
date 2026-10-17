"""Pulls Conditional Access data from Graph and saves it as a snapshot file.

The snapshot keeps Graph's JSON exactly as returned, so `analyze` treats a live export and the
synthetic samples the same way. Snapshots go in exports/, which is git-ignored: they describe
a real tenant's defenses and shouldn't end up on GitHub.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__

POLICIES_PATH = "/identity/conditionalAccess/policies"
NAMED_LOCATIONS_PATH = "/identity/conditionalAccess/namedLocations"
EXPORTS_DIR = Path("exports")


def collect_snapshot(client, username: str, tenant_id: str, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    # Show the tenant's domain (from ca-auditor@contoso.onmicrosoft.com) rather than a bare GUID.
    tenant = username.split("@", 1)[1] if "@" in username else tenant_id
    return {
        "metadata": {
            "tenant": tenant,
            "tenantId": tenant_id,
            "collectedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "collectedBy": username,
            "source": "Microsoft Graph v1.0",
            "tool": f"ca-gap-analyzer {__version__}",
        },
        "conditionalAccessPolicies": client.get_all(POLICIES_PATH),
        "namedLocations": client.get_all(NAMED_LOCATIONS_PATH),
    }


def default_output_path(now: datetime | None = None) -> Path:
    now = now or datetime.now(timezone.utc)
    return EXPORTS_DIR / f"snapshot-{now:%Y%m%d-%H%M%S}.json"


def save_snapshot(snapshot: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False)
