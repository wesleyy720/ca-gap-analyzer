from ca_gap_analyzer.checks import ca01_mfa_all_users as check
from conftest import make_policy, make_snapshot


def test_passes_with_enforced_mfa_for_everyone():
    assert check.run(make_snapshot([make_policy()])) == []


def test_fails_with_no_policies():
    findings = check.run(make_snapshot([]))
    assert len(findings) == 1
    assert findings[0].severity.name == "HIGH"


def test_fails_when_mfa_policy_is_report_only():
    findings = check.run(make_snapshot([make_policy(state="enabledForReportingButNotEnforced")]))
    assert len(findings) == 1
    assert "Report-only" in findings[0].detail


def test_fails_when_scoped_to_some_users():
    assert len(check.run(make_snapshot([make_policy(users=["some-user-id"])]))) == 1


def test_fails_when_scoped_to_one_app():
    sharepoint = "00000003-0000-0ff1-ce00-000000000000"
    assert len(check.run(make_snapshot([make_policy(apps=[sharepoint])]))) == 1


def test_fails_when_mfa_can_be_skipped_with_or():
    # "MFA OR compliant device" lets a compliant device skip MFA entirely.
    policy = make_policy(grant=["mfa", "compliantDevice"], operator="OR")
    assert len(check.run(make_snapshot([policy]))) == 1


def test_passes_when_mfa_and_other_control_are_both_required():
    policy = make_policy(grant=["mfa", "compliantDevice"], operator="AND")
    assert check.run(make_snapshot([policy])) == []


def test_fails_when_limited_by_platform_condition():
    policy = make_policy(platforms={"includePlatforms": ["android"]})
    findings = check.run(make_snapshot([policy]))
    assert len(findings) == 1
    assert "device platforms" in findings[0].detail


def test_any_device_or_any_location_is_not_narrowing():
    # Portal "Any device" / "Any location" is configured but covers everything.
    policy = make_policy(platforms={"includePlatforms": ["all"], "excludePlatforms": []},
                         locations={"includeLocations": ["All"], "excludeLocations": []})
    assert check.run(make_snapshot([policy])) == []


def test_any_device_except_one_platform_is_narrowing():
    policy = make_policy(platforms={"includePlatforms": ["all"], "excludePlatforms": ["linux"]})
    assert len(check.run(make_snapshot([policy]))) == 1


def test_mfa_skipped_from_trusted_locations_is_narrowing():
    policy = make_policy(locations={"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]})
    findings = check.run(make_snapshot([policy]))
    assert len(findings) == 1
    assert "locations" in findings[0].detail


def test_passes_with_authentication_strength_instead_of_mfa():
    policy = make_policy(grant=[])
    policy["grantControls"]["authenticationStrength"] = {"displayName": "Phishing-resistant MFA"}
    assert check.run(make_snapshot([policy])) == []
