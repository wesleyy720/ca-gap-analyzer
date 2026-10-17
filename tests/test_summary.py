"""Plain-English policy descriptions, checked against the lab sample."""

from pathlib import Path

from ca_gap_analyzer.cli import main
from ca_gap_analyzer.snapshot import load_snapshot
from ca_gap_analyzer.summary import describe_policy
from conftest import make_policy, make_snapshot

SAMPLE = Path(__file__).parent.parent / "samples" / "lab_snapshot.json"


def describe(name):
    snapshot = load_snapshot(SAMPLE)
    policy = next(p for p in snapshot.policies if p.name.startswith(name))
    return "\n".join(describe_policy(policy, snapshot))


def test_exclusion_groups_show_their_members():
    text = describe("CA001")
    assert "[On]" in text
    assert "CA-Exclusions-Temp (group: carol, svc-legacy-scanner)" in text
    assert "breakglass01" in text


def test_roles_show_their_holders():
    assert "Global Administrator role (held by: breakglass01, labadmin)" in describe("CA100")


def test_apps_conditions_and_grants():
    assert "Office 365 SharePoint Online" in describe("CA102")
    assert "client apps: exchangeActiveSync, other" in describe("CA002")
    assert "sign-in risk: high" in describe("CA101")
    assert "Require authentication strength 'Phishing-resistant MFA'" in describe("CA100")


def test_or_and_operators():
    snapshot = make_snapshot([make_policy(grant=["mfa", "compliantDevice"], operator="AND")])
    text = "\n".join(describe_policy(snapshot.policies[0], snapshot))
    assert "Require MFA AND Require compliant device" in text


def test_policies_command(capsys):
    assert main(["policies", str(SAMPLE)]) == 0
    out = capsys.readouterr().out
    assert "Conditional Access policies in calab-sample.onmicrosoft.com (6)" in out
    assert out.index("CA001") < out.index("CA103")  # sorted by name


def test_policies_command_on_old_snapshot_explains_missing_names(tmp_path, capsys):
    old = tmp_path / "old.json"
    old.write_text('{"conditionalAccessPolicies": [], "namedLocations": []}', encoding="utf-8")
    assert main(["policies", str(old)]) == 0
    assert "no directory data" in capsys.readouterr().out
