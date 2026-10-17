"""Tests for the policy-only checks: CA-07, CA-09, CA-11, CA-12."""

from ca_gap_analyzer.checks import (
    ca07_risk_policies as ca07,
    ca09_device_code as ca09,
    ca11_guests_mfa as ca11,
    ca12_admin_session as ca12,
)
from conftest import GA, make_policy, make_snapshot

REPORT_ONLY = "enabledForReportingButNotEnforced"


def test_ca07_enforced_risk_policy_passes():
    assert ca07.run(make_snapshot([make_policy(grant=["block"], signInRiskLevels=["high"])])) == []


def test_ca07_report_only_risk_policy_fails():
    findings = ca07.run(make_snapshot([make_policy(state=REPORT_ONLY, grant=["block"], signInRiskLevels=["high"])]))
    assert "Report-only" in findings[0].detail


def test_ca07_no_risk_policy_fails():
    assert len(ca07.run(make_snapshot([make_policy()]))) == 1


def device_code_block(state="enabled", flows="deviceCodeFlow"):
    return make_policy(state=state, grant=["block"], authenticationFlows={"transferMethods": flows})


def test_ca09_enforced_block_passes():
    assert ca09.run(make_snapshot([device_code_block(flows="deviceCodeFlow,authenticationTransfer")])) == []


def test_ca09_report_only_fails():
    assert "Report-only" in ca09.run(make_snapshot([device_code_block(state=REPORT_ONLY)]))[0].detail


def test_ca09_no_policy_fails():
    assert len(ca09.run(make_snapshot([make_policy()]))) == 1


def test_ca11_guests_covered_passes():
    assert ca11.run(make_snapshot([make_policy()])) == []


def test_ca11_guests_excluded_fails():
    policy = make_policy()
    policy["conditions"]["users"]["excludeUsers"] = ["GuestsOrExternalUsers"]
    assert len(ca11.run(make_snapshot([policy]))) == 1


def test_ca11_newer_guest_exclusion_format_fails():
    policy = make_policy()
    policy["conditions"]["users"]["excludeGuestsOrExternalUsers"] = {"guestOrExternalUserTypes": "b2bCollaborationGuest"}
    assert len(ca11.run(make_snapshot([policy]))) == 1


def test_ca11_silent_when_no_mfa_baseline():
    assert ca11.run(make_snapshot([])) == []  # CA-01 reports the missing baseline


def with_frequency(state="enabled", roles=(GA,)):
    p = make_policy(state=state, users=[])
    p["conditions"]["users"]["includeRoles"] = list(roles)
    p["sessionControls"] = {"signInFrequency": {"isEnabled": True, "value": 4, "type": "hours"}}
    return p


def test_ca12_enforced_admin_frequency_passes():
    assert ca12.run(make_snapshot([with_frequency()])) == []


def test_ca12_report_only_frequency_fails():
    assert "Report-only" in ca12.run(make_snapshot([with_frequency(state=REPORT_ONLY)]))[0].detail


def test_ca12_no_frequency_fails():
    assert len(ca12.run(make_snapshot([make_policy()]))) == 1
