from ca_gap_analyzer.checks import ca06_not_enforced as check
from ca_gap_analyzer.findings import Severity
from conftest import make_policy, make_snapshot


def test_passes_when_all_enforced():
    assert check.run(make_snapshot([make_policy(), make_policy(name="Another")])) == []


def test_recent_report_only_policy_is_low():
    findings = check.run(make_snapshot([make_policy(state="enabledForReportingButNotEnforced")]))
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


def test_old_disabled_policy_is_medium():
    # The snapshot is collected 2026-10-17, so this policy has been untouched for months.
    policy = make_policy(state="disabled", modified="2026-01-01T00:00:00Z")
    findings = check.run(make_snapshot([policy]))
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "likely forgotten" in findings[0].detail


def test_one_finding_per_unenforced_policy():
    policies = [
        make_policy(name="A", state="disabled"),
        make_policy(name="B", state="enabledForReportingButNotEnforced"),
        make_policy(name="C"),
    ]
    findings = check.run(make_snapshot(policies))
    assert [f.affected for f in findings] == [["A"], ["B"]]


def test_fix_text_matches_policy_state():
    policies = [
        make_policy(name="Off", state="disabled"),
        make_policy(name="Report", state="enabledForReportingButNotEnforced"),
    ]
    off, report = check.run(make_snapshot(policies))
    assert "Report-only tab" not in off.remediation
    assert "Report-only tab" in report.remediation


def test_handles_graph_seven_digit_fractional_seconds():
    policy = make_policy(state="disabled", modified="2026-01-01T00:00:00.1234567Z")
    assert len(check.run(make_snapshot([policy]))) == 1
