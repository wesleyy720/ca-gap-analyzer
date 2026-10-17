"""The Finding type that every check returns."""

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Higher number = worse. IntEnum lets us sort findings by severity."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Finding:
    """One problem a check found."""

    check_id: str          # e.g. "CA-03", matching docs/CHECKS.md
    title: str             # one-line summary
    severity: Severity
    detail: str            # what exactly is wrong in this tenant
    remediation: str       # how to fix it
    affected: list[str] = field(default_factory=list)  # policy/location names involved

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.name
        return data
