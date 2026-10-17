"""Parsing for Microsoft Graph timestamps."""

import re
from datetime import datetime, timezone


def parse_graph_datetime(value: str | None) -> datetime | None:
    """Parse Graph timestamps like '2026-10-17T15:04:05.1234567Z'.

    Graph sends up to 7 fractional-second digits, but Python only accepts 6, so we trim them.
    """
    if not value:
        return None
    value = re.sub(r"(\.\d{6})\d+", r"\1", value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
