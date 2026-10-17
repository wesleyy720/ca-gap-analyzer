"""Which accounts are break-glass (emergency access) accounts?

Break-glass accounts are *supposed* to be excluded from Conditional Access, so the identity
checks must not flag them. From policy data alone, though, a break-glass exclusion and a lazy
admin exclusion look identical. So:
  * If you designate them (CA_BREAK_GLASS in .env), the tool trusts that list.
  * If not, it guesses: users excluded from every enforced policy, preferring names that look
    like break-glass accounts. Reports say clearly when they're based on a guess.
"""

import re
from dataclasses import dataclass, field

from .snapshot import Snapshot

NAME_HINT = re.compile(r"break.?glass|emergency|\bbg\b", re.IGNORECASE)


@dataclass
class BreakGlass:
    ids: set[str] = field(default_factory=set)
    designated: bool = False        # True if from CA_BREAK_GLASS, False if guessed
    unresolved: list[str] = field(default_factory=list)  # designated entries not found

    def note(self, snapshot: Snapshot) -> str:
        names = ", ".join(sorted(snapshot.directory.name(i) for i in self.ids)) or "none"
        if self.designated:
            return f"designated: {names}"
        return f"guessed: {names} (set CA_BREAK_GLASS in .env to confirm)"


def designate(snapshot: Snapshot, entries: list[str]) -> BreakGlass:
    """Resolve CA_BREAK_GLASS entries (UPNs or object IDs) against the snapshot's directory."""
    by_upn = {(o.get("userPrincipalName") or "").lower(): oid
              for oid, o in snapshot.directory.objects.items()}
    result = BreakGlass(designated=True)
    for entry in entries:
        if entry in snapshot.directory.objects:
            result.ids.add(entry)
        elif entry.lower() in by_upn:
            result.ids.add(by_upn[entry.lower()])
        else:
            result.unresolved.append(entry)
    return result


def guess(snapshot: Snapshot) -> BreakGlass:
    enforced = [p for p in snapshot.policies if p.is_enforced]
    if not enforced:
        return BreakGlass()
    # Break-glass accounts are excluded by name, directly on each policy. Someone excluded only
    # through a group (like an admin in a "temp exclusions" group) is exactly what CA-04 should
    # flag, so group exclusions don't make someone a break-glass candidate.
    excluded_sets = [set(p.exclude_users) - {"GuestsOrExternalUsers"} for p in enforced]
    candidates = set.intersection(*excluded_sets)
    named = {c for c in candidates
             if NAME_HINT.search(snapshot.directory.name(c))
             or NAME_HINT.search(snapshot.directory.objects.get(c, {}).get("displayName") or "")}
    return BreakGlass(ids=named or candidates)


def resolve(snapshot: Snapshot) -> BreakGlass:
    if snapshot.break_glass_entries is not None:
        return designate(snapshot, snapshot.break_glass_entries)
    return guess(snapshot)
