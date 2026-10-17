"""HTML report and threat-context tests."""

import re
from datetime import datetime, timezone
from pathlib import Path

from ca_gap_analyzer.checks import ALL_CHECKS
from ca_gap_analyzer.cli import main
from ca_gap_analyzer.guidance import GUIDANCE, kql_for, technique_url
from ca_gap_analyzer.report import default_report_path, render_report
from ca_gap_analyzer.runner import all_findings, run_checks
from ca_gap_analyzer.snapshot import load_snapshot
from conftest import make_policy, make_snapshot

SAMPLE = Path(__file__).parent.parent / "samples" / "lab_snapshot.json"
GENERATED = datetime(2026, 10, 17, 19, 0, tzinfo=timezone.utc)


def sample():
    return load_snapshot(SAMPLE)


def render(snapshot):
    return render_report(snapshot, run_checks(snapshot), generated_at=GENERATED)


# --- Guidance --------------------------------------------------------------------

def test_every_check_has_guidance_and_a_query():
    ids = {c.CHECK_ID for c in ALL_CHECKS}
    assert ids == set(GUIDANCE)
    assert all(GUIDANCE[i].kql for i in ids)


def test_technique_url_handles_subtechniques():
    assert technique_url("T1110.003") == "https://attack.mitre.org/techniques/T1110/003/"


def test_queries_are_filled_with_the_findings_users():
    snapshot = sample()
    ca04 = next(f for f in all_findings(run_checks(snapshot)) if f.check_id == "CA-04")
    kql = kql_for(ca04, snapshot)
    assert '"carol@calab-sample.onmicrosoft.com"' in kql
    assert "{users}" not in kql


def test_trusted_location_query_uses_the_real_range():
    snapshot = sample()
    ca08 = next(f for f in all_findings(run_checks(snapshot)) if f.check_id == "CA-08")
    assert 'dynamic(["20.0.0.0/8"])' in kql_for(ca08, snapshot)


def test_no_placeholders_left_in_any_query():
    snapshot = sample()
    for finding in all_findings(run_checks(snapshot)):
        assert not re.search(r"\{(users|policies|cidrs)\}", kql_for(finding, snapshot))


# --- Report ----------------------------------------------------------------------

def test_report_has_summary_counts_and_every_finding():
    html = render(sample())
    findings = all_findings(run_checks(sample()))
    assert "calab-sample.onmicrosoft.com" in html
    assert html.count('class="finding"') == len(findings)
    assert '<div class="num">1</div><div class="label">Critical</div>' in html
    assert "3/12" in html
    assert "Generated 2026-10-17 19:00 UTC" in html


def test_report_lists_worst_findings_first_in_summary():
    html = render(sample())
    summary = html.split("Executive summary")[1].split("<h2>")[0]
    assert summary.index("Critical") < summary.index("High")


def test_report_includes_attack_links_and_queries():
    html = render(sample())
    assert 'href="https://attack.mitre.org/techniques/T1557/"' in html
    assert "SigninLogs" in html


def test_report_includes_policy_appendix():
    html = render(sample())
    assert "Appendix: policies in plain English" in html
    assert "CA-Exclusions-Temp (group: carol, svc-legacy-scanner)" in html


def test_tenant_text_is_escaped():
    # Policy and user names are attacker-controllable; they must never become live HTML.
    evil = make_policy(name='<script>alert("x")</script>', state="disabled")
    html = render(make_snapshot([evil]))
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html


def test_report_is_self_contained():
    html = render(sample())
    assert not re.search(r'<(script|link|img)[^>]+(src|href)="http', html)


def test_clean_tenant_says_so():
    snapshot = make_snapshot([])
    html = render_report(snapshot, [], generated_at=GENERATED)
    assert "No gaps found" in html


def test_default_report_path_matches_snapshot_time():
    assert default_report_path(Path("exports/snapshot-20261017-213742.json")) == Path("reports/report-20261017-213742.html")
    assert default_report_path(Path("samples/lab_snapshot.json")) == Path("reports/report-lab_snapshot.html")


def test_report_command_writes_file(tmp_path, capsys):
    output = tmp_path / "out" / "report.html"
    assert main(["report", str(SAMPLE), "--output", str(output), "--env-file", "none.env"]) == 0
    assert output.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert "Report saved to" in capsys.readouterr().out
