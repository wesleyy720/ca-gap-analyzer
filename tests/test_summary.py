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


def test_bad_path_characters_give_a_friendly_error(capsys):
    assert main(["policies", "exports/snapshot-<time>.json"]) == 2
    assert "error:" in capsys.readouterr().err


def test_defaults_to_newest_snapshot(tmp_path, monkeypatch, capsys):
    exports = tmp_path / "exports"
    exports.mkdir()
    sample = SAMPLE.read_text(encoding="utf-8")
    (exports / "snapshot-20260101-000000.json").write_text('{"metadata": {"tenant": "old"}}', encoding="utf-8")
    (exports / "snapshot-20261017-120000.json").write_text(sample, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert main(["policies"]) == 0
    captured = capsys.readouterr()
    assert "snapshot-20261017-120000.json" in captured.err
    assert "calab-sample.onmicrosoft.com" in captured.out


def test_no_snapshots_yet(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["analyze"]) == 2
    assert "Run `ca-gap-analyzer collect` first" in capsys.readouterr().err


def test_policies_command_on_old_snapshot_explains_missing_names(tmp_path, capsys):
    old = tmp_path / "old.json"
    old.write_text('{"conditionalAccessPolicies": [], "namedLocations": []}', encoding="utf-8")
    assert main(["policies", str(old)]) == 0
    assert "no directory data" in capsys.readouterr().out
