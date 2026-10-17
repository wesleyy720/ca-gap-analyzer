"""End-to-end: the synthetic lab snapshot should produce exactly the gaps SETUP.md plants."""

import json
from pathlib import Path

from ca_gap_analyzer.cli import main, run_checks
from ca_gap_analyzer.snapshot import load_snapshot

SAMPLE = Path(__file__).parent.parent / "samples" / "lab_snapshot.json"
NO_ENV = ["--env-file", "does-not-exist.env"]  # don't pick up a developer's real .env


def results_by_id(break_glass=None):
    snapshot = load_snapshot(SAMPLE)
    snapshot.break_glass_entries = break_glass
    return {r.check_id: r for r in run_checks(snapshot)}


def test_baseline_policies_pass():
    results = results_by_id()
    assert results["CA-01"].passed  # CA001
    assert results["CA-03"].passed  # CA002
    assert results["CA-11"].passed  # CA001 doesn't exclude guests


def test_flawed_policies_are_flagged():
    results = results_by_id()
    flagged = {name for f in results["CA-06"].findings for name in f.affected}
    assert flagged == {
        "CA100 - Phishing-resistant MFA - Admins",
        "CA101 - Block high-risk sign-ins",
        "CA102 - Require compliant device",
        "CA103 - Old pilot policy",
    }


def test_office_hq_is_flagged():
    assert results_by_id()["CA-08"].findings[0].affected == ["Office-HQ"]


def test_carol_hiding_in_exclusion_group_is_caught():
    findings = results_by_id()["CA-04"].findings
    assert [f.affected for f in findings] == [["carol"]]
    assert "via group CA-Exclusions-Temp" in findings[0].detail


def test_admins_without_phishing_resistant_mfa():
    assert results_by_id()["CA-02"].findings[0].affected == ["bob", "carol", "erin", "labadmin"]


def test_designating_break_glass_matches_guess():
    guessed = results_by_id()
    designated = results_by_id(break_glass=["breakglass01@calab-sample.onmicrosoft.com"])
    assert [f.affected for f in guessed["CA-04"].findings] == [f.affected for f in designated["CA-04"].findings]


def test_cli_text_output(capsys):
    assert main(["analyze", str(SAMPLE), *NO_ENV]) == 0
    out = capsys.readouterr().out
    assert "FAIL  CA-08" in out
    assert "Break-glass: guessed: breakglass01" in out
    assert "Summary: 3 of 12 checks passed." in out


def test_cli_json_output(capsys):
    assert main(["analyze", str(SAMPLE), "--format", "json", *NO_ENV]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [c["id"] for c in data["checks"]] == [f"CA-{n:02d}" for n in range(1, 13)]


def test_old_snapshot_skips_identity_checks(tmp_path, capsys):
    old = json.loads(SAMPLE.read_text(encoding="utf-8"))
    for key in ("roleDefinitions", "roleAssignments", "roleEligibilities", "groupMembers", "directoryObjects"):
        del old[key]
    path = tmp_path / "old.json"
    path.write_text(json.dumps(old), encoding="utf-8")

    assert main(["analyze", str(path), *NO_ENV]) == 0
    out = capsys.readouterr().out
    assert "SKIP  CA-04" in out
    assert "4 skipped" in out


def test_cli_missing_file(capsys):
    assert main(["analyze", "does-not-exist.json"]) == 2
    assert "not found" in capsys.readouterr().err
