"""All checks the analyzer runs.

Each check is a module with three things:
    CHECK_ID  e.g. "CA-03", matching docs/CHECKS.md
    TITLE     what a passing tenant looks like
    run(snapshot) -> list[Finding]   an empty list means the check passed

To add a check: create a module like the ones below, then add it to ALL_CHECKS.
"""

from . import ca01_mfa_all_users, ca03_legacy_auth, ca06_not_enforced, ca08_trusted_locations

ALL_CHECKS = [
    ca01_mfa_all_users,
    ca03_legacy_auth,
    ca06_not_enforced,
    ca08_trusted_locations,
]
