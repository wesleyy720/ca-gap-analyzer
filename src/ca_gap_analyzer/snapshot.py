"""Loads a tenant snapshot: a JSON file holding everything the checks need.

A snapshot keeps Microsoft Graph's own JSON shape, so a live export and the synthetic samples
in samples/ look identical to the checks:

    {
      "metadata": {"tenant": "...", "collectedAt": "2026-10-17T15:00:00Z", "warnings": [...]},
      "conditionalAccessPolicies": [ ...GET /identity/conditionalAccess/policies... ],
      "namedLocations":            [ ...GET /identity/conditionalAccess/namedLocations... ],
      "roleDefinitions":           [ ...GET /roleManagement/directory/roleDefinitions... ],
      "roleAssignments":           [ ...active role assignments... ],
      "roleEligibilities":         [ ...PIM eligible role assignments... ],
      "groupMembers":              { "<group id>": ["<member id>", ...] },
      "directoryObjects":          [ ...users, groups, and apps referenced above... ]
    }

The directory sections are optional, so snapshots from before identity enrichment still load.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .directory import Directory
from .graphtime import parse_graph_datetime
from .policy import Policy


@dataclass
class Snapshot:
    tenant: str
    collected_at: datetime          # checks use this as "now", so results are repeatable
    policies: list[Policy]
    named_locations: list[dict]
    directory: Directory = field(default_factory=Directory)
    warnings: list[str] = field(default_factory=list)
    user_count: int | None = None   # total users in the tenant, for "how broad is this exclusion?"
    # Break-glass accounts named in CA_BREAK_GLASS (UPNs or IDs). None means "not set; guess".
    break_glass_entries: list[str] | None = None


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
        directory=Directory(
            objects=data.get("directoryObjects", []),
            role_definitions=data.get("roleDefinitions", []),
            role_assignments=data.get("roleAssignments", []),
            role_eligibilities=data.get("roleEligibilities", []),
            group_members=data.get("groupMembers", {}),
        ),
        warnings=metadata.get("warnings", []),
        user_count=metadata.get("userCount"),
    )
