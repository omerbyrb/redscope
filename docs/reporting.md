# Reporting

RedScope generates reports in three formats: **HTML**, **JSON**, and **Markdown**.

## HTML Report

The HTML report is a single self-contained file with no external dependencies (no CDN, no internet required). It features a dark theme, collapsible findings, and filter-by-severity buttons.

```bash
redscope scan https://example.com --all-web --report html
```

Output: `output/<target>/<timestamp>/report.html`

Features:
- Summary cards (total findings by severity)
- Risk bar chart
- Filter by severity (Critical / High / Medium / Low / Info)
- Collapsible finding cards with evidence and remediation
- Fully self-contained — works offline

## JSON Report

Machine-readable output suitable for integration with other tools, SIEM, or ticket systems.

```bash
redscope scan https://example.com --all-web --save
```

Output: `output/<target>/<timestamp>/results.json`

Structure:
```json
{
  "meta": {
    "target": "https://example.com",
    "started_at": "2024-01-15T10:00:00Z",
    "finished_at": "2024-01-15T10:03:45Z",
    "redscope_version": "1.0.0"
  },
  "summary": {
    "total_findings": 12,
    "critical": 1,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 2
  },
  "modules": [...],
  "findings": [
    {
      "title": "SQL Injection — Error-Based",
      "severity": "critical",
      "description": "...",
      "evidence": "...",
      "remediation": "...",
      "cvss": 9.8,
      "cve": null,
      "tags": ["sqli", "web"],
      "timestamp": "2024-01-15T10:01:23Z"
    }
  ]
}
```

## Markdown Report

GitHub-flavored Markdown suitable for issue trackers and documentation.

```bash
redscope scan https://example.com --all-web --report markdown
```

Output: `output/<target>/<timestamp>/report.md`

Features:
- Emoji severity icons (🔴 🟠 🟡 🔵 ⚪)
- CVE links to NVD
- Evidence and remediation tables

## Output Directory Structure

```
output/
└── example.com/
    └── 2024-01-15_10-00-00/
        ├── results.json
        ├── report.html
        └── report.md
```

## Generating All Formats

```bash
redscope scan https://example.com --all --save --report html
```

Then generate Markdown separately:
```bash
redscope scan https://example.com --all --report markdown
```
