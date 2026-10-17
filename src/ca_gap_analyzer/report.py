"""Renders the analysis as a single, self-contained HTML file.

No external CSS, fonts, or scripts: the report opens offline, can be emailed or attached to a
ticket, and doesn't leak that it was opened. Every value from the tenant is HTML-escaped, since
display names and policy names are attacker-controllable text (a user named
"<script>...</script>" must not run code in an auditor's browser).
"""

from datetime import datetime, timezone
from html import escape
from pathlib import Path

from . import __version__
from .breakglass import resolve
from .findings import Finding, Severity
from .guidance import GUIDANCE, kql_for, technique_url
from .runner import CheckResult, all_findings
from .snapshot import Snapshot
from .summary import policy_rows

REPORTS_DIR = Path("reports")
SEVERITIES = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


def default_report_path(snapshot_path: Path | None) -> Path:
    """reports/report-<same timestamp as the snapshot>.html"""
    stem = snapshot_path.stem if snapshot_path else "snapshot"
    suffix = stem.removeprefix("snapshot-") if stem.startswith("snapshot-") else stem
    return REPORTS_DIR / f"report-{suffix}.html"


def write_report(html: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")


# --- Pieces -------------------------------------------------------------------

def _badge(severity: Severity) -> str:
    return f'<span class="badge sev-{severity.name.lower()}">{severity.name.title()}</span>'


def _status(result: CheckResult) -> str:
    return f'<span class="status status-{result.status.lower()}">{result.status.title()}</span>'


def _executive_summary(snapshot: Snapshot, results: list[CheckResult], findings: list[Finding]) -> str:
    failed = [r for r in results if not r.passed and not r.skipped]
    if not findings:
        return "<p>No gaps found. Every check passed against this snapshot.</p>"

    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITIES}
    urgent = counts[Severity.CRITICAL] + counts[Severity.HIGH]
    text = (f"<p>The analyzer found <strong>{len(findings)} findings</strong> across "
            f"{len(failed)} of {len(results)} checks")
    text += f", including <strong>{urgent} critical or high</strong>.</p>" if urgent else ".</p>"

    top = findings[:3]
    text += "<p>Fix these first:</p><ol>"
    text += "".join(f"<li>{_badge(f.severity)} {escape(f.title)}</li>" for f in top)
    text += "</ol>"
    return text


def _finding_card(finding: Finding, snapshot: Snapshot, index: int) -> str:
    guidance = GUIDANCE.get(finding.check_id)
    parts = [f'<article class="finding" id="finding-{index}">',
             f'<header>{_badge(finding.severity)}<span class="check-id">{escape(finding.check_id)}</span>'
             f'<h3>{escape(finding.title)}</h3></header>',
             f'<p>{escape(finding.detail)}</p>',
             f'<p class="fix"><strong>Fix:</strong> {escape(finding.remediation)}</p>']

    if guidance and guidance.techniques:
        links = ", ".join(
            f'<a href="{technique_url(tid)}" target="_blank" rel="noopener">{escape(tid)} {escape(name)}</a>'
            for tid, name in guidance.techniques)
        parts.append(f'<p class="attack"><strong>MITRE ATT&amp;CK:</strong> {links}</p>')

    kql = kql_for(finding, snapshot)
    if kql:
        parts.append(
            '<details class="kql"><summary>Hunting query (KQL): has this gap been used?</summary>'
            f'<button type="button" class="copy" data-target="kql-{index}">Copy</button>'
            f'<pre id="kql-{index}"><code>{escape(kql)}</code></pre></details>')
    parts.append("</article>")
    return "\n".join(parts)


def _policy_table(snapshot: Snapshot) -> str:
    blocks = []
    for policy in sorted(snapshot.policies, key=lambda p: p.name):
        rows = "".join(f"<tr><th>{escape(label)}</th><td>{escape(value)}</td></tr>"
                       for label, value in policy_rows(policy, snapshot))
        state = policy.state_label.lower().replace("-", "")
        blocks.append(f'<div class="policy"><h3>{escape(policy.name)} '
                      f'<span class="state state-{state}">{escape(policy.state_label)}</span></h3>'
                      f'<table>{rows}</table></div>')
    return "\n".join(blocks)


# --- Page ---------------------------------------------------------------------

def render_report(snapshot: Snapshot, results: list[CheckResult], generated_at: datetime | None = None) -> str:
    generated_at = generated_at or datetime.now(timezone.utc)
    findings = all_findings(results)
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITIES}
    passed = sum(r.passed for r in results)

    meta = [f"Collected {snapshot.collected_at:%Y-%m-%d %H:%M} UTC"]
    if snapshot.collected_by:
        meta.append(f"by {escape(snapshot.collected_by)}")
    if not snapshot.directory.is_empty:
        meta.append(f"Break-glass {escape(resolve(snapshot).note(snapshot))}")

    cards = "".join(
        f'<div class="card sev-{s.name.lower()}"><div class="num">{counts[s]}</div>'
        f'<div class="label">{s.name.title()}</div></div>' for s in SEVERITIES)
    cards += (f'<div class="card neutral"><div class="num">{passed}/{len(results)}</div>'
              f'<div class="label">Checks passed</div></div>')

    warnings = "".join(f'<p class="warning">{escape(w)}</p>' for w in snapshot.warnings)

    check_rows = "".join(
        f"<tr><td>{_status(r)}</td><td>{escape(r.check_id)}</td><td>{escape(r.title)}</td>"
        f"<td class='num'>{len(r.findings) or ''}</td></tr>" for r in results)

    finding_cards = "\n".join(_finding_card(f, snapshot, i) for i, f in enumerate(findings, 1)) \
        or "<p>No findings.</p>"

    return PAGE.format(
        title=f"CA Gap Report: {escape(snapshot.tenant)}",
        tenant=escape(snapshot.tenant),
        meta=" · ".join(meta),
        cards=cards,
        warnings=warnings,
        summary=_executive_summary(snapshot, results, findings),
        check_rows=check_rows,
        findings=finding_cards,
        policies=_policy_table(snapshot),
        generated=f"{generated_at:%Y-%m-%d %H:%M} UTC",
        version=__version__,
        style=STYLE,
        script=SCRIPT,
    )


STYLE = """
:root {
  --bg: #f6f7f9; --panel: #ffffff; --text: #1d2433; --muted: #5b6475; --border: #e2e5ea;
  --code-bg: #f1f3f6; --link: #1d5bd6;
  --critical: #b42318; --high: #c4320a; --medium: #b54708; --low: #1d5bd6;
  --pass: #067647; --fail: #b42318; --skip: #5b6475;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #12151b; --panel: #1b1f27; --text: #e6e9ef; --muted: #9aa3b2; --border: #2c323d;
    --code-bg: #232833; --link: #7aa7ff;
    --critical: #f97066; --high: #fb8c55; --medium: #fdb022; --low: #7aa7ff;
    --pass: #47cd89; --fail: #f97066; --skip: #9aa3b2;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
main { max-width: 1040px; margin: 0 auto; padding: 32px 16px 64px; }
h1 { font-size: 26px; margin: 0 0 4px; }
h2 { font-size: 19px; margin: 40px 0 12px; padding-bottom: 6px; border-bottom: 1px solid var(--border); }
h3 { font-size: 16px; margin: 0; }
a { color: var(--link); }
.meta { color: var(--muted); margin: 0 0 24px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px;
  border-top: 4px solid var(--muted); }
.card .num { font-size: 28px; font-weight: 700; }
.card .label { color: var(--muted); font-size: 13px; }
.card.sev-critical { border-top-color: var(--critical); } .card.sev-high { border-top-color: var(--high); }
.card.sev-medium { border-top-color: var(--medium); } .card.sev-low { border-top-color: var(--low); }
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px 20px; }
.warning { background: var(--panel); border-left: 4px solid var(--medium); padding: 8px 12px; margin: 8px 0; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
td.num { text-align: right; color: var(--muted); }
.badge, .status, .state { display: inline-block; font-size: 12px; font-weight: 600; padding: 1px 8px;
  border-radius: 999px; border: 1px solid currentColor; white-space: nowrap; }
.sev-critical .badge, .badge.sev-critical { color: var(--critical); }
.badge.sev-high { color: var(--high); } .badge.sev-medium { color: var(--medium); } .badge.sev-low { color: var(--low); }
.status-pass, .state-on { color: var(--pass); } .status-fail { color: var(--fail); }
.status-skip, .state-off { color: var(--skip); } .state-reportonly { color: var(--medium); }
.finding { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px 20px; margin: 12px 0; }
.finding header { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 6px; }
.check-id { color: var(--muted); font-size: 13px; font-weight: 600; }
.fix { border-left: 3px solid var(--pass); padding-left: 10px; }
.attack { font-size: 14px; color: var(--muted); }
details.kql { margin-top: 10px; position: relative; }
details.kql summary { cursor: pointer; color: var(--link); font-size: 14px; }
pre { background: var(--code-bg); border-radius: 8px; padding: 12px; overflow-x: auto; font-size: 13px; }
button.copy { position: absolute; right: 8px; top: 30px; font-size: 12px; padding: 3px 10px; cursor: pointer;
  border: 1px solid var(--border); border-radius: 6px; background: var(--panel); color: var(--text); }
.policy { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 18px; margin: 10px 0; }
.policy h3 { margin-bottom: 8px; }
.policy th { width: 120px; color: var(--muted); font-weight: 500; }
footer { color: var(--muted); font-size: 13px; margin-top: 48px; }
@media print { details.kql { display: none; } .finding, .policy { break-inside: avoid; } }
"""

SCRIPT = """
document.querySelectorAll("button.copy").forEach(function (button) {
  button.addEventListener("click", function () {
    var text = document.getElementById(button.dataset.target).innerText;
    navigator.clipboard.writeText(text).then(function () {
      button.textContent = "Copied";
      setTimeout(function () { button.textContent = "Copy"; }, 1500);
    });
  });
});
"""

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{style}</style>
</head>
<body>
<main>
<h1>Conditional Access Gap Report</h1>
<p class="meta"><strong>{tenant}</strong> · {meta}</p>
<div class="cards">{cards}</div>
{warnings}

<h2>Executive summary</h2>
<div class="panel">{summary}</div>

<h2>Checks</h2>
<div class="panel"><table>
<thead><tr><th>Status</th><th>ID</th><th>Check</th><th class="num">Findings</th></tr></thead>
<tbody>{check_rows}</tbody>
</table></div>

<h2>Findings</h2>
{findings}

<h2>Appendix: policies in plain English</h2>
{policies}

<footer>Generated {generated} by ca-gap-analyzer {version}. Collected with read-only
Microsoft Graph permissions. Hunting queries run against SigninLogs in Log Analytics or
Microsoft Sentinel.</footer>
</main>
<script>{script}</script>
</body>
</html>
"""
