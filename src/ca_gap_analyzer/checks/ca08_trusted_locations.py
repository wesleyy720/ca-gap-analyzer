"""CA-08: Do any trusted named locations cover suspiciously large IP ranges?

Trusted locations are often used to skip MFA or lower risk scores. A real office egress range
is usually tiny (a /29 or a few single IPs). Anything broader than /16 is worth questioning.
"""

import ipaddress

from ..findings import Finding, Severity
from ..snapshot import Snapshot

CHECK_ID = "CA-08"
TITLE = "Trusted locations use narrow IP ranges"

# Flag ranges with a shorter prefix (= more addresses) than these.
MAX_PREFIX = {4: 16, 6: 48}

IP_LOCATION_TYPE = "#microsoft.graph.ipNamedLocation"


def run(snapshot: Snapshot) -> list[Finding]:
    findings = []
    for loc in snapshot.named_locations:
        if loc.get("@odata.type") != IP_LOCATION_TYPE or not loc.get("isTrusted"):
            continue

        broad = []
        for ip_range in loc.get("ipRanges") or []:
            cidr = ip_range.get("cidrAddress", "")
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue  # malformed range; not this check's concern
            if network.prefixlen < MAX_PREFIX[network.version]:
                broad.append(f"{cidr} ({network.num_addresses:,} addresses)")

        if broad:
            name = loc.get("displayName", "(unnamed location)")
            findings.append(Finding(
                check_id=CHECK_ID,
                title=f"Trusted location '{name}' has an over-broad IP range",
                severity=Severity.HIGH,
                detail=(
                    f"'{name}' is marked trusted but includes: {'; '.join(broad)}. "
                    "Any sign-in from these addresses is treated as coming from a trusted network."
                ),
                remediation=(
                    "Limit the location to your real egress IPs (ask the network team for the "
                    "public NAT addresses). Don't rely on location in place of MFA."
                ),
                affected=[name],
            ))
    return findings
