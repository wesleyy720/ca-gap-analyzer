"""End-to-end: the synthetic lab snapshot should produce exactly the gaps SETUP.md plants."""

import json
from pathlib import Path

from ca_gap_analyzer.cli import main, run_checks
from ca_gap_analyzer.snapshot import load_snapshot

SAMPLE = Path(__file__).parent.parent / "samples" / "lab_snapshot.json"


def results_by_id():
    return {r.check_id: r for r in run_checks(load_snapshot(SAMPLE))}


def test_baseline_policies_pass():
    results = results_by_id()
    assert results["CA-01"].passed  # CA001
    assert results["CA-03"].passed  # CA002


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


def test_cli_text_output(capsys):
    assert main(["analyze", str(SAMPLE)]) == 0
    out = capsys.readouterr().out
    assert "FAIL  CA-08" in out
    assert "Summary: 2 of 4 checks passed." in out


def test_cli_json_output(capsys):
    assert main(["analyze", str(SAMPLE), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert {c["id"] for c in data["checks"]} == {"CA-01", "CA-03", "CA-06", "CA-08"}


def test_cli_missing_file(capsys):
    assert main(["analyze", "does-not-exist.json"]) == 2
    assert "not found" in capsys.readouterr().err
