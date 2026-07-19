import json
from datetime import datetime
from pathlib import Path
from typing import List

from core.base_module import BaseModule, ScanResult

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class Module(BaseModule):
    name = "jsonreport"
    description = "JSON and Markdown report generator"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        scan_results: List[ScanResult] = kwargs.get("results", [])
        fmt = kwargs.get("format", "both")  # json, markdown, both
        output_dir = Path(kwargs.get("output_dir", "output"))

        if not scan_results:
            result.add_error("No results to report")
            return result

        safe = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")

        if fmt in ("json", "both"):
            path = output_dir / f"report_{safe}.json"
            self.save_json(target, scan_results, path)
            result.data["json_path"] = str(path)

        if fmt in ("markdown", "both"):
            path = output_dir / f"report_{safe}.md"
            self.save_markdown(target, scan_results, path)
            result.data["markdown_path"] = str(path)

        return result

    # ── JSON ─────────────────────────────────────────────────────────────────

    def save_json(self, target: str, scan_results: List[ScanResult], path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)

        all_findings = []
        for sr in scan_results:
            for f in sr.findings:
                all_findings.append(f.to_dict() | {"module": sr.module})

        all_findings.sort(
            key=lambda x: SEVERITY_ORDER.index(x["severity"]) if x["severity"] in SEVERITY_ORDER else 99
        )

        counts = {s: sum(1 for f in all_findings if f["severity"] == s) for s in SEVERITY_ORDER}

        report = {
            "meta": {
                "tool": "RedScope",
                "version": "1.0.0",
                "target": target,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "total_findings": len(all_findings),
            },
            "summary": counts,
            "modules": [sr.to_dict() for sr in scan_results],
            "findings": all_findings,
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.log.info(f"JSON report → [bold green]{path}[/]")
        return path

    # ── Markdown ──────────────────────────────────────────────────────────────

    def save_markdown(self, target: str, scan_results: List[ScanResult], path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)

        all_findings = []
        for sr in scan_results:
            for f in sr.findings:
                all_findings.append((sr.module, f))

        all_findings.sort(
            key=lambda x: SEVERITY_ORDER.index(x[1].severity) if x[1].severity in SEVERITY_ORDER else 99
        )

        counts = {s: sum(1 for _, f in all_findings if f.severity == s) for s in SEVERITY_ORDER}

        ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}

        lines = []

        # Header
        lines += [
            "# RedScope Security Report",
            "",
            f"**Target:** `{target}`  ",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"**Total Findings:** {len(all_findings)}  ",
            "",
            "---",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for s in SEVERITY_ORDER:
            lines.append(f"| {ICONS[s]} {s.capitalize()} | {counts[s]} |")

        lines += ["", "---", "", "## Findings", ""]

        # Group by module
        modules: dict = {}
        for module, finding in all_findings:
            modules.setdefault(module, []).append(finding)

        for module, findings in modules.items():
            lines += [f"### Module: `{module}`", ""]
            for f in findings:
                lines += [
                    f"#### {ICONS.get(f.severity, '⚪')} {f.title}",
                    "",
                    f"**Severity:** `{f.severity.upper()}`" +
                    (f" | **CVSS:** `{f.cvss}`" if f.cvss else "") +
                    (f" | **CVE:** [{f.cve}](https://nvd.nist.gov/vuln/detail/{f.cve})" if f.cve else ""),
                    "",
                ]
                if f.description:
                    lines += ["**Description:**", "", f.description, ""]
                if f.evidence:
                    lines += ["**Evidence:**", "", "```", f.evidence, "```", ""]
                if f.remediation:
                    lines += ["**Remediation:**", "", f"> {f.remediation}", ""]
                if f.tags:
                    lines += [f"**Tags:** {' '.join(f'`{t}`' for t in f.tags)}", ""]
                lines += ["---", ""]

        # Errors
        errors = [(sr.module, e) for sr in scan_results for e in sr.errors]
        if errors:
            lines += ["## Errors", ""]
            for module, err in errors:
                lines.append(f"- `{module}`: {err}")
            lines.append("")

        # Footer
        lines += [
            "---",
            "",
            "*Generated by [RedScope](https://github.com/omerbyrb/redscope) — "
            "for authorized security testing only.*",
        ]

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        self.log.info(f"Markdown report → [bold green]{path}[/]")
        return path
