from ca_gap_analyzer.checks import ca03_legacy_auth as check
from conftest import make_policy, make_snapshot


def block_legacy(**overrides):
    defaults = {"name": "Block legacy", "client_apps": ["exchangeActiveSync", "other"], "grant": ["block"]}
    defaults.update(overrides)
    return make_policy(**defaults)


def test_passes_when_both_legacy_types_blocked():
    assert check.run(make_snapshot([block_legacy()])) == []


def test_passes_when_split_across_two_policies():
    policies = [block_legacy(client_apps=["exchangeActiveSync"]), block_legacy(client_apps=["other"])]
    assert check.run(make_snapshot(policies)) == []


def test_fails_with_no_blocking_policy():
    findings = check.run(make_snapshot([make_policy()]))  # MFA only, no block
    assert len(findings) == 1
    assert "exchangeActiveSync" in findings[0].detail and "other" in findings[0].detail


def test_fails_when_only_one_type_blocked():
    findings = check.run(make_snapshot([block_legacy(client_apps=["exchangeActiveSync"])]))
    assert len(findings) == 1
    assert "other" in findings[0].detail
    assert "exchangeActiveSync" not in findings[0].detail.split("blocked by any enforced policy:")[1]


def test_fails_when_blocking_policy_is_report_only():
    findings = check.run(make_snapshot([block_legacy(state="enabledForReportingButNotEnforced")]))
    assert len(findings) == 1
    assert "isn't enforced" in findings[0].detail


def test_fails_when_blocking_policy_targets_some_users():
    assert len(check.run(make_snapshot([block_legacy(users=["some-user-id"])]))) == 1
