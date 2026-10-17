"""All checks the analyzer runs.

Each check is a module with:
    CHECK_ID  e.g. "CA-03", matching docs/CHECKS.md
    TITLE     what a passing tenant looks like
    run(snapshot) -> list[Finding]   an empty list means the check passed
    REQUIRES_DIRECTORY (optional)    True if it needs users/groups/roles; skipped for older snapshots

To add a check: create a module like the ones below, then add it to ALL_CHECKS.
"""

from . import (
    ca01_mfa_all_users,
    ca02_admin_phishing_resistant,
    ca03_legacy_auth,
    ca04_privileged_exclusions,
    ca05_broad_exclusions,
    ca06_not_enforced,
    ca07_risk_policies,
    ca08_trusted_locations,
    ca09_device_code,
    ca10_break_glass,
    ca11_guests_mfa,
    ca12_admin_session,
)

ALL_CHECKS = [
    ca01_mfa_all_users,
    ca02_admin_phishing_resistant,
    ca03_legacy_auth,
    ca04_privileged_exclusions,
    ca05_broad_exclusions,
    ca06_not_enforced,
    ca07_risk_policies,
    ca08_trusted_locations,
    ca09_device_code,
    ca10_break_glass,
    ca11_guests_mfa,
    ca12_admin_session,
]
