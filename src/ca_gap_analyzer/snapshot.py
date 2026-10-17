"""Loads a tenant snapshot: a JSON file holding everything the checks need.

A snapshot keeps Microsoft Graph's own JSON shape, so a live export (Milestone 2) and the
synthetic samples in samples/ look identical to the checks:

    {
      "metadata": {"tenant": "...", "collectedAt": "2026-10-17T15:00:00Z", "source": "sample"},
      "conditionalAccessPolicies": [ ...objects from GET /identity/conditionalAccess/policies... ],
      "namedLocations":            [ ...objects from GET /identity/conditionalAccess/namedLocations... ]
    }
"""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .graphtime import parse_graph_datetime
from .policy import Policy


@dataclass
class Snapshot:
    tenant: str
    collected_at: datetime          # checks use this as "now", so results are repeatable
    policies: list[Policy]
    named_locations: list[dict]


def load_snapshot(path: Path) -> Snapshot:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return snapshot_from_dict(data)


def snapshot_from_dict(data: dict) -> Snapshot:
    metadata = data.get("metadata", {})
    collected_at = parse_graph_datetime(metadata.get("collectedAt")) or datetime.now(timezone.utc)
    return Snapshot(
        tenant=metadata.get("tenant", "unknown"),
        collected_at=collected_at,
        policies=[Policy(raw) for raw in data.get("conditionalAccessPolicies", [])],
        named_locations=data.get("namedLocations", []),
    )
