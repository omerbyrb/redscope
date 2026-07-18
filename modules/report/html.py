import json
from datetime import datetime
from pathlib import Path
from typing import List

from core.base_module import BaseModule, ScanResult, Finding

SEVERITY_COLOR = {
    "critical": "#e74c3c",
    "high":     "#e67e22",
    "medium":   "#f1c40f",
    "low":      "#3498db",
    "info":     "#95a5a6",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RedScope Report — {target}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e;
    --critical: #e74c3c; --high: #e67e22;
    --medium: #f1c40f; --low: #3498db; --info: #95a5a6;
    --accent: #ff4444;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.6; }}
  a {{ color: var(--accent); text-decoration: none; }}

  /* Header */
  .header {{ background: var(--surface); border-bottom: 2px solid var(--accent); padding: 24px 40px; display: flex; align-items: center; justify-content: space-between; }}
  .header-logo {{ font-size: 24px; font-weight: 800; color: var(--accent); letter-spacing: 2px; }}
  .header-meta {{ text-align: right; color: var(--muted); font-size: 12px; }}
  .header-meta strong {{ color: var(--text); display: block; font-size: 16px; }}

  /* Summary cards */
  .summary {{ display: flex; gap: 16px; padding: 24px 40px; flex-wrap: wrap; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px 28px; flex: 1; min-width: 140px; text-align: center; }}
  .card-count {{ font-size: 36px; font-weight: 800; }}
  .card-label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
  .card.critical .card-count {{ color: var(--critical); }}
  .card.high     .card-count {{ color: var(--high); }}
  .card.medium   .card-count {{ color: var(--medium); }}
  .card.low      .card-count {{ color: var(--low); }}
  .card.info     .card-count {{ color: var(--info); }}
  .card.total    .card-count {{ color: var(--text); }}

  /* Progress bar */
  .risk-bar {{ margin: 0 40px 24px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px 20px; }}
  .risk-bar-label {{ color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }}
  .bar {{ display: flex; height: 12px; border-radius: 6px; overflow: hidden; gap: 2px; }}
  .bar-segment {{ height: 100%; border-radius: 3px; transition: width 0.3s; }}

  /* Filters */
  .filters {{ padding: 0 40px 16px; display: flex; gap: 8px; flex-wrap: wrap; }}
  .filter-btn {{ padding: 6px 14px; border-radius: 20px; border: 1px solid var(--border); background: var(--surface); color: var(--muted); cursor: pointer; font-size: 12px; transition: all 0.2s; }}
  .filter-btn:hover, .filter-btn.active {{ border-color: var(--accent); color: var(--accent); background: rgba(255,68,68,0.1); }}

  /* Findings */
  .findings {{ padding: 0 40px 40px; }}
  .module-group {{ margin-bottom: 32px; }}
  .module-title {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 2px; border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-bottom: 12px; }}

  .finding {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 10px; overflow: hidden; border-left: 4px solid var(--border); transition: border-color 0.2s; }}
  .finding:hover {{ border-color: var(--accent); }}
  .finding.critical {{ border-left-color: var(--critical); }}
  .finding.high     {{ border-left-color: var(--high); }}
  .finding.medium   {{ border-left-color: var(--medium); }}
  .finding.low      {{ border-left-color: var(--low); }}
  .finding.info     {{ border-left-color: var(--info); }}

  .finding-header {{ padding: 14px 18px; display: flex; align-items: center; gap: 12px; cursor: pointer; user-select: none; }}
  .badge {{ font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; padding: 3px 8px; border-radius: 4px; white-space: nowrap; }}
  .badge.critical {{ background: rgba(231,76,60,0.2);  color: var(--critical); }}
  .badge.high     {{ background: rgba(230,126,34,0.2); color: var(--high); }}
  .badge.medium   {{ background: rgba(241,196,15,0.2); color: var(--medium); }}
  .badge.low      {{ background: rgba(52,152,219,0.2); color: var(--low); }}
  .badge.info     {{ background: rgba(149,165,166,0.2);color: var(--info); }}

  .finding-title {{ font-weight: 600; flex: 1; }}
  .chevron {{ color: var(--muted); font-size: 10px; transition: transform 0.2s; }}
  .finding.open .chevron {{ transform: rotate(90deg); }}

  .finding-body {{ display: none; padding: 0 18px 16px; border-top: 1px solid var(--border); }}
  .finding.open .finding-body {{ display: block; }}
  .finding-section {{ margin-top: 12px; }}
  .finding-section-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 4px; }}
  .finding-section-value {{ color: var(--text); white-space: pre-wrap; font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 12px; background: var(--bg); padding: 10px; border-radius: 4px; border: 1px solid var(--border); word-break: break-all; }}

  /* Tags */
  .tags {{ display: flex; flex-wrap: wrap; gap: 4px; margin-top: 8px; }}
  .tag {{ font-size: 10px; padding: 2px 8px; border-radius: 10px; background: var(--bg); border: 1px solid var(--border); color: var(--muted); }}

  /* CVSS */
  .cvss {{ display: inline-flex; align-items: center; gap: 6px; margin-top: 8px; }}
  .cvss-score {{ font-weight: 700; font-size: 16px; }}
  .cvss-label {{ color: var(--muted); font-size: 11px; }}

  /* Footer */
  .footer {{ text-align: center; padding: 24px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); }}

  /* No findings */
  .empty {{ text-align: center; padding: 60px; color: var(--muted); }}
  .empty-icon {{ font-size: 48px; margin-bottom: 12px; }}
</style>
</head>
<body>

<div class="header">
  <div class="header-logo">&#x25CF; REDSCOPE</div>
  <div class="header-meta">
    <strong>{target}</strong>
    Generated {generated_at} &bull; {total} findings across {module_count} modules
  </div>
</div>

<div class="summary">
  <div class="card total">
    <div class="card-count">{total}</div>
    <div class="card-label">Total</div>
  </div>
  <div class="card critical">
    <div class="card-count">{count_critical}</div>
    <div class="card-label">Critical</div>
  </div>
  <div class="card high">
    <div class="card-count">{count_high}</div>
    <div class="card-label">High</div>
  </div>
  <div class="card medium">
    <div class="card-count">{count_medium}</div>
    <div class="card-label">Medium</div>
  </div>
  <div class="card low">
    <div class="card-count">{count_low}</div>
    <div class="card-label">Low</div>
  </div>
  <div class="card info">
    <div class="card-count">{count_info}</div>
    <div class="card-label">Info</div>
  </div>
</div>

<div class="risk-bar">
  <div class="risk-bar-label">Finding Distribution</div>
  <div class="bar" id="riskBar"></div>
</div>

<div class="filters">
  <button class="filter-btn active" onclick="filterFindings('all')">All</button>
  <button class="filter-btn" onclick="filterFindings('critical')">&#x25CF; Critical</button>
  <button class="filter-btn" onclick="filterFindings('high')">&#x25CF; High</button>
  <button class="filter-btn" onclick="filterFindings('medium')">&#x25CF; Medium</button>
  <button class="filter-btn" onclick="filterFindings('low')">&#x25CF; Low</button>
  <button class="filter-btn" onclick="filterFindings('info')">&#x25CF; Info</button>
</div>

<div class="findings" id="findings">
{findings_html}
</div>

<div class="footer">
  RedScope &bull; For authorized security testing only &bull; {generated_at}
</div>

<script>
const counts = {{
  critical: {count_critical},
  high:     {count_high},
  medium:   {count_medium},
  low:      {count_low},
  info:     {count_info},
}};
const colors = {{
  critical: '#e74c3c', high: '#e67e22',
  medium: '#f1c40f', low: '#3498db', info: '#95a5a6'
}};
const total = {total} || 1;
const bar = document.getElementById('riskBar');
['critical','high','medium','low','info'].forEach(s => {{
  if (counts[s] > 0) {{
    const seg = document.createElement('div');
    seg.className = 'bar-segment';
    seg.style.width = (counts[s] / total * 100) + '%';
    seg.style.background = colors[s];
    seg.title = s + ': ' + counts[s];
    bar.appendChild(seg);
  }}
}});

function toggleFinding(el) {{
  el.closest('.finding').classList.toggle('open');
}}

function filterFindings(severity) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding').forEach(f => {{
    f.style.display = (severity === 'all' || f.dataset.severity === severity) ? '' : 'none';
  }});
  document.querySelectorAll('.module-group').forEach(g => {{
    const visible = [...g.querySelectorAll('.finding')].some(f => f.style.display !== 'none');
    g.style.display = visible ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""


class Module(BaseModule):
    name = "htmlreport"
    description = "HTML report generator — single-file, dark theme, interactive findings"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        scan_results: List[ScanResult] = kwargs.get("results", [])
        output_path = Path(kwargs.get("output", f"output/report_{self._safe_name(target)}.html"))

        if not scan_results:
            self.log.warning("No scan results provided — pass results= to generate report")
            result.add_error("No results to report")
            return result

        html = self._render(target, scan_results)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")

        self.log.info(f"HTML report saved → [bold green]{output_path}[/]")
        result.data["report_path"] = str(output_path)
        return result

    def render_and_save(self, target: str, scan_results: List[ScanResult], output_path: Path) -> Path:
        html = self._render(target, scan_results)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        self.log.info(f"HTML report → [bold green]{output_path}[/]")
        return output_path

    def _render(self, target: str, scan_results: List[ScanResult]) -> str:
        all_findings = []
        for sr in scan_results:
            for f in sr.findings:
                all_findings.append((sr.module, f))

        all_findings.sort(key=lambda x: SEVERITY_ORDER.index(x[1].severity) if x[1].severity in SEVERITY_ORDER else 99)

        counts = {s: sum(1 for _, f in all_findings if f.severity == s) for s in SEVERITY_ORDER}

        # Group by module
        modules: dict = {}
        for module, finding in all_findings:
            modules.setdefault(module, []).append(finding)

        findings_html = ""
        if not all_findings:
            findings_html = '<div class="empty"><div class="empty-icon">✓</div><p>No findings — target looks clean.</p></div>'
        else:
            for module, findings in modules.items():
                findings_html += f'<div class="module-group"><div class="module-title">{module}</div>'
                for i, f in enumerate(findings):
                    findings_html += self._render_finding(f, f"{module}_{i}")
                findings_html += "</div>"

        return HTML_TEMPLATE.format(
            target=target,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            total=len(all_findings),
            module_count=len(modules),
            count_critical=counts["critical"],
            count_high=counts["high"],
            count_medium=counts["medium"],
            count_low=counts["low"],
            count_info=counts["info"],
            findings_html=findings_html,
        )

    def _render_finding(self, f: Finding, uid: str) -> str:
        sections = ""
        if f.description:
            sections += self._section("Description", f.description)
        if f.evidence:
            sections += self._section("Evidence", f.evidence)
        if f.remediation:
            sections += self._section("Remediation", f.remediation)
        if f.cvss:
            sections += f'<div class="finding-section"><div class="cvss"><span class="cvss-score" style="color:{SEVERITY_COLOR.get(f.severity,"#fff")}">{f.cvss}</span><span class="cvss-label">CVSS Score</span></div></div>'
        if f.cve:
            sections += self._section("CVE", f'<a href="https://nvd.nist.gov/vuln/detail/{f.cve}" target="_blank">{f.cve}</a>')
        if f.tags:
            tags_html = "".join(f'<span class="tag">{t}</span>' for t in f.tags)
            sections += f'<div class="finding-section"><div class="tags">{tags_html}</div></div>'

        return f"""
<div class="finding {f.severity}" data-severity="{f.severity}">
  <div class="finding-header" onclick="toggleFinding(this)">
    <span class="badge {f.severity}">{f.severity}</span>
    <span class="finding-title">{f.title}</span>
    <span class="chevron">&#9654;</span>
  </div>
  <div class="finding-body">{sections}</div>
</div>"""

    def _section(self, label: str, value: str) -> str:
        return f"""
<div class="finding-section">
  <div class="finding-section-label">{label}</div>
  <div class="finding-section-value">{value}</div>
</div>"""

    def _safe_name(self, target: str) -> str:
        return target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
