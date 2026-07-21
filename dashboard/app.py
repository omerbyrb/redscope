import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from flask import Flask, jsonify, render_template_string, request

from core.config import load_config
from core.engine import Engine

app = Flask(__name__)
app.secret_key = "redscope-dashboard"

# In-memory scan store: scan_id -> {status, target, modules, results, engine}
SCANS: Dict[str, dict] = {}

ALL_MODULES = [
    # Recon
    {"id": "dns",           "label": "DNS Recon",           "category": "recon"},
    {"id": "subdomain",     "label": "Subdomain Enum",      "category": "recon"},
    {"id": "portscan",      "label": "Port Scanner",        "category": "recon"},
    {"id": "emailsec",      "label": "Email Security",      "category": "recon"},
    {"id": "takeover",      "label": "Subdomain Takeover",  "category": "recon"},
    {"id": "shodan",        "label": "Shodan Intel",        "category": "recon"},
    # Web
    {"id": "headers",       "label": "HTTP Headers",        "category": "web"},
    {"id": "dirbrute",      "label": "Dir Brute Force",     "category": "web"},
    {"id": "sqli",          "label": "SQL Injection",       "category": "web"},
    {"id": "xss",           "label": "XSS Scanner",         "category": "web"},
    {"id": "cors",          "label": "CORS Check",          "category": "web"},
    {"id": "openredirect",  "label": "Open Redirect",       "category": "web"},
    {"id": "ssrf",          "label": "SSRF Detector",       "category": "web"},
    {"id": "jwt",           "label": "JWT Analyzer",        "category": "web"},
    {"id": "lfi",           "label": "LFI / RFI",           "category": "web"},
    {"id": "cmdi",          "label": "Command Injection",   "category": "web"},
    {"id": "xxe",           "label": "XXE Injection",       "category": "web"},
    {"id": "idor",          "label": "IDOR Checker",        "category": "web"},
    {"id": "waf",           "label": "WAF Detector",        "category": "web"},
    # Network
    {"id": "ssltls",        "label": "SSL/TLS Analyzer",   "category": "network"},
    {"id": "banner",        "label": "Banner Grabber",      "category": "network"},
    {"id": "cvelookup",     "label": "CVE Lookup",          "category": "network"},
    {"id": "serviceenum",   "label": "Service Enum",        "category": "network"},
    {"id": "osfingerprint", "label": "OS Fingerprint",      "category": "network"},
]

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML, modules=ALL_MODULES)


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.json or {}
    target = data.get("target", "").strip()
    modules = data.get("modules", [])

    if not target:
        return jsonify({"error": "Target is required"}), 400
    if not modules:
        return jsonify({"error": "Select at least one module"}), 400

    scan_id = str(uuid.uuid4())[:8]
    SCANS[scan_id] = {
        "id": scan_id,
        "target": target,
        "modules": modules,
        "status": "running",
        "started_at": datetime.utcnow().isoformat(),
        "finished_at": None,
        "findings": [],
        "errors": [],
        "log": [],
        "counts": {s: 0 for s in SEVERITY_ORDER},
    }

    thread = threading.Thread(target=_run_scan, args=(scan_id, target, modules), daemon=True)
    thread.start()

    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/<scan_id>")
def get_scan(scan_id):
    scan = SCANS.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)


@app.route("/api/scans")
def list_scans():
    return jsonify([
        {
            "id": s["id"],
            "target": s["target"],
            "status": s["status"],
            "started_at": s["started_at"],
            "total": sum(s["counts"].values()),
            "critical": s["counts"]["critical"],
        }
        for s in reversed(list(SCANS.values()))
    ])


@app.route("/api/scan/<scan_id>/report")
def download_report(scan_id):
    from flask import send_file
    scan = SCANS.get(scan_id)
    if not scan or scan["status"] != "done":
        return jsonify({"error": "Scan not complete"}), 404

    engine: Engine = scan.get("_engine")
    if not engine:
        return jsonify({"error": "Engine not available"}), 500

    safe = scan["target"].replace("https://", "").replace("http://", "").replace("/", "_")
    path = Path(f"output/report_{safe}.html")
    engine.generate_html_report(scan["target"], path)
    return send_file(path, as_attachment=True)


# ── Background scan runner ────────────────────────────────────────────────────

def _run_scan(scan_id: str, target: str, modules: List[str]) -> None:
    scan = SCANS[scan_id]
    config = load_config()
    engine = Engine()
    engine.config = config
    scan["_engine"] = engine

    for mod_name in modules:
        scan["log"].append(f"[{_now()}] Running {mod_name}...")
        try:
            result = engine.run_module(mod_name, target)
            if result:
                for finding in result.findings:
                    f_dict = finding.to_dict()
                    f_dict["module"] = mod_name
                    scan["findings"].append(f_dict)
                    scan["counts"][finding.severity] = scan["counts"].get(finding.severity, 0) + 1
                scan["log"].append(
                    f"[{_now()}] {mod_name} done — {len(result.findings)} findings"
                )
                for err in result.errors:
                    scan["errors"].append(f"{mod_name}: {err}")
        except Exception as e:
            scan["errors"].append(f"{mod_name}: {e}")
            scan["log"].append(f"[{_now()}] {mod_name} ERROR: {e}")

    scan["findings"].sort(
        key=lambda x: SEVERITY_ORDER.index(x["severity"]) if x["severity"] in SEVERITY_ORDER else 99
    )
    scan["status"] = "done"
    scan["finished_at"] = datetime.utcnow().isoformat()
    scan["log"].append(f"[{_now()}] Scan complete — {len(scan['findings'])} total findings")


def _now() -> str:
    return datetime.utcnow().strftime("%H:%M:%S")


# ── HTML Template ─────────────────────────────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>RedScope Dashboard</title>
<style>
:root{--bg:#0d1117;--s:#161b22;--b:#30363d;--t:#e6edf3;--m:#8b949e;--acc:#ff4444;--crit:#e74c3c;--high:#e67e22;--med:#f1c40f;--low:#3498db;--info:#95a5a6}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--t);font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;display:flex;height:100vh;overflow:hidden}
a{color:var(--acc);text-decoration:none}

/* Sidebar */
.sidebar{width:240px;background:var(--s);border-right:1px solid var(--b);display:flex;flex-direction:column;flex-shrink:0}
.logo{padding:20px;font-size:18px;font-weight:800;color:var(--acc);letter-spacing:2px;border-bottom:1px solid var(--b)}
.nav{padding:12px 0;flex:1;overflow-y:auto}
.nav-item{padding:10px 20px;cursor:pointer;color:var(--m);transition:all .15s;display:flex;align-items:center;gap:8px}
.nav-item:hover,.nav-item.active{background:rgba(255,68,68,.08);color:var(--acc)}
.history{padding:12px 20px;border-top:1px solid var(--b);font-size:11px;color:var(--m);text-transform:uppercase;letter-spacing:1px}
.scan-item{padding:8px 20px;cursor:pointer;border-bottom:1px solid var(--b);transition:background .15s}
.scan-item:hover{background:rgba(255,255,255,.03)}
.scan-item .si-target{font-weight:600;color:var(--t);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.scan-item .si-meta{font-size:11px;color:var(--m);margin-top:2px}
.dot{width:6px;height:6px;border-radius:50%;display:inline-block}
.dot.running{background:#f1c40f;animation:pulse 1s infinite}
.dot.done{background:#2ecc71}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}

/* Main */
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.topbar{background:var(--s);border-bottom:1px solid var(--b);padding:14px 24px;display:flex;align-items:center;gap:12px}
.topbar input{flex:1;background:var(--bg);border:1px solid var(--b);border-radius:6px;padding:8px 14px;color:var(--t);font-size:13px;outline:none;transition:border .2s}
.topbar input:focus{border-color:var(--acc)}
.btn{padding:8px 18px;border-radius:6px;border:none;cursor:pointer;font-size:13px;font-weight:600;transition:all .2s}
.btn-primary{background:var(--acc);color:#fff}
.btn-primary:hover{background:#cc3333}
.btn-primary:disabled{background:#555;cursor:not-allowed}
.btn-sm{padding:5px 12px;font-size:11px;background:var(--s);color:var(--m);border:1px solid var(--b)}
.btn-sm:hover{color:var(--t)}

/* Module picker */
.modules-bar{background:var(--s);border-bottom:1px solid var(--b);padding:10px 24px;display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.mod-chip{padding:4px 10px;border-radius:12px;border:1px solid var(--b);color:var(--m);cursor:pointer;font-size:11px;transition:all .15s;user-select:none}
.mod-chip:hover{border-color:var(--acc);color:var(--acc)}
.mod-chip.selected{background:rgba(255,68,68,.15);border-color:var(--acc);color:var(--acc)}
.mod-chip.recon{--hl:#2ecc71}.mod-chip.recon.selected{background:rgba(46,204,113,.12);border-color:#2ecc71;color:#2ecc71}
.mod-chip.network{--hl:#3498db}.mod-chip.network.selected{background:rgba(52,152,219,.12);border-color:#3498db;color:#3498db}
.select-all-btns{display:flex;gap:6px;margin-left:auto}

/* Content */
.content{flex:1;overflow-y:auto;padding:24px}

/* Summary */
.summary-row{display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap}
.stat{background:var(--s);border:1px solid var(--b);border-radius:8px;padding:16px 20px;flex:1;min-width:90px;text-align:center}
.stat-n{font-size:28px;font-weight:800}
.stat-l{color:var(--m);font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-top:2px}
.stat.c .stat-n{color:var(--crit)}.stat.h .stat-n{color:var(--high)}.stat.m .stat-n{color:var(--med)}.stat.l .stat-n{color:var(--low)}.stat.i .stat-n{color:var(--info)}

/* Findings */
.finding{background:var(--s);border:1px solid var(--b);border-left:3px solid var(--b);border-radius:6px;margin-bottom:8px;overflow:hidden;cursor:pointer;transition:border-color .15s}
.finding:hover{border-color:var(--acc)}
.finding.critical{border-left-color:var(--crit)}.finding.high{border-left-color:var(--high)}.finding.medium{border-left-color:var(--med)}.finding.low{border-left-color:var(--low)}.finding.info{border-left-color:var(--info)}
.fh{padding:12px 16px;display:flex;align-items:center;gap:10px}
.badge{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:1px;padding:2px 7px;border-radius:3px;white-space:nowrap}
.badge.critical{background:rgba(231,76,60,.2);color:var(--crit)}.badge.high{background:rgba(230,126,34,.2);color:var(--high)}.badge.medium{background:rgba(241,196,15,.2);color:var(--med)}.badge.low{background:rgba(52,152,219,.2);color:var(--low)}.badge.info{background:rgba(149,165,166,.2);color:var(--info)}
.ft{flex:1;font-weight:600}.fm{font-size:11px;color:var(--m)}
.fb{display:none;padding:0 16px 14px;border-top:1px solid var(--b)}
.finding.open .fb{display:block}
.fl{font-size:10px;text-transform:uppercase;color:var(--m);letter-spacing:1px;margin-top:10px;margin-bottom:3px}
.fv{font-family:'Cascadia Code',monospace;font-size:11px;background:var(--bg);padding:8px 10px;border-radius:4px;border:1px solid var(--b);white-space:pre-wrap;word-break:break-all;color:var(--t)}

/* Log */
.log-box{background:var(--bg);border:1px solid var(--b);border-radius:6px;padding:12px;font-family:monospace;font-size:11px;color:var(--m);height:160px;overflow-y:auto;line-height:1.6}

/* Status bar */
.status-bar{padding:6px 24px;background:var(--s);border-top:1px solid var(--b);font-size:11px;color:var(--m);display:flex;gap:16px}

/* Empty state */
.empty{text-align:center;padding:80px 24px;color:var(--m)}
.empty-icon{font-size:48px;margin-bottom:12px}
</style>
</head>
<body>

<div class="sidebar">
  <div class="logo">● REDSCOPE</div>
  <div class="nav">
    <div class="nav-item active" onclick="showView('scan')">⬡ New Scan</div>
    <div class="nav-item" onclick="showView('history')">◈ Scan History</div>
  </div>
  <div class="history">Recent Scans</div>
  <div id="sidebarScans" style="overflow-y:auto;max-height:300px"></div>
</div>

<div class="main">
  <div class="topbar">
    <input id="targetInput" type="text" placeholder="https://target.com or domain.com" />
    <button class="btn btn-primary" id="scanBtn" onclick="startScan()">▶ Scan</button>
    <button class="btn btn-sm" onclick="generateReport()">⤓ HTML Report</button>
  </div>

  <div class="modules-bar">
    {% for mod in modules %}
    <div class="mod-chip {{ mod.category }}" data-id="{{ mod.id }}" onclick="toggleMod(this)">{{ mod.label }}</div>
    {% endfor %}
    <div class="select-all-btns">
      <button class="btn btn-sm" onclick="selectAll()">All</button>
      <button class="btn btn-sm" onclick="selectNone()">None</button>
      <button class="btn btn-sm" onclick="selectCategory('recon')" style="color:#2ecc71">Recon</button>
      <button class="btn btn-sm" onclick="selectCategory('web')" style="color:var(--acc)">Web</button>
      <button class="btn btn-sm" onclick="selectCategory('network')" style="color:#3498db">Network</button>
    </div>
  </div>

  <div class="content" id="mainContent">
    <div class="empty">
      <div class="empty-icon">⬡</div>
      <p>Enter a target and select modules to begin scanning.</p>
    </div>
  </div>

  <div class="status-bar">
    <span id="statusText">Ready</span>
    <span id="statusFindings"></span>
    <span id="statusTime"></span>
  </div>
</div>

<script>
let currentScanId = null;
let pollInterval = null;
let scanStartTime = null;

function toggleMod(el) { el.classList.toggle('selected'); }
function selectAll() { document.querySelectorAll('.mod-chip').forEach(e => e.classList.add('selected')); }
function selectNone() { document.querySelectorAll('.mod-chip').forEach(e => e.classList.remove('selected')); }
function selectCategory(cat) {
  document.querySelectorAll('.mod-chip').forEach(e => {
    if (e.dataset.id && e.classList.contains(cat)) e.classList.add('selected');
    else e.classList.remove('selected');
  });
}

function getSelectedModules() {
  return [...document.querySelectorAll('.mod-chip.selected')].map(e => e.dataset.id);
}

async function startScan() {
  const target = document.getElementById('targetInput').value.trim();
  const modules = getSelectedModules();
  if (!target) { alert('Enter a target'); return; }
  if (!modules.length) { alert('Select at least one module'); return; }

  document.getElementById('scanBtn').disabled = true;
  scanStartTime = Date.now();
  renderLoading(target, modules);

  const res = await fetch('/api/scan', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({target, modules})
  });
  const data = await res.json();
  currentScanId = data.scan_id;

  pollInterval = setInterval(() => pollScan(currentScanId), 1500);
}

async function pollScan(scanId) {
  const res = await fetch(`/api/scan/${scanId}`);
  const scan = await res.json();
  updateUI(scan);
  if (scan.status === 'done') {
    clearInterval(pollInterval);
    document.getElementById('scanBtn').disabled = false;
    loadSidebarScans();
  }
}

function updateUI(scan) {
  const elapsed = ((Date.now() - scanStartTime) / 1000).toFixed(0);
  const total = Object.values(scan.counts).reduce((a,b)=>a+b,0);
  document.getElementById('statusText').textContent = scan.status === 'done' ? '✓ Complete' : '⟳ Scanning...';
  document.getElementById('statusFindings').textContent = `${total} findings`;
  document.getElementById('statusTime').textContent = `${elapsed}s elapsed`;

  const colors = {critical:'var(--crit)',high:'var(--high)',medium:'var(--med)',low:'var(--low)',info:'var(--info)'};

  let html = `
  <div class="summary-row">
    <div class="stat"><div class="stat-n">${total}</div><div class="stat-l">Total</div></div>
    <div class="stat c"><div class="stat-n">${scan.counts.critical}</div><div class="stat-l">Critical</div></div>
    <div class="stat h"><div class="stat-n">${scan.counts.high}</div><div class="stat-l">High</div></div>
    <div class="stat m"><div class="stat-n">${scan.counts.medium}</div><div class="stat-l">Medium</div></div>
    <div class="stat l"><div class="stat-n">${scan.counts.low}</div><div class="stat-l">Low</div></div>
    <div class="stat i"><div class="stat-n">${scan.counts.info}</div><div class="stat-l">Info</div></div>
  </div>
  <div class="log-box" id="logBox">${scan.log.slice(-20).join('<br>')}</div>
  <div style="margin:16px 0 8px;color:var(--m);font-size:11px;text-transform:uppercase;letter-spacing:1px">Findings</div>
  `;

  if (scan.findings.length === 0 && scan.status !== 'done') {
    html += '<div style="color:var(--m);padding:20px 0">Scanning...</div>';
  } else if (scan.findings.length === 0) {
    html += '<div style="color:var(--m);padding:20px 0">No findings.</div>';
  } else {
    scan.findings.forEach((f, i) => {
      html += `
      <div class="finding ${f.severity}" onclick="this.classList.toggle('open')">
        <div class="fh">
          <span class="badge ${f.severity}">${f.severity}</span>
          <span class="ft">${f.title}</span>
          <span class="fm">${f.module}</span>
        </div>
        <div class="fb">
          ${f.description ? `<div class="fl">Description</div><div class="fv">${f.description}</div>` : ''}
          ${f.evidence ? `<div class="fl">Evidence</div><div class="fv">${f.evidence}</div>` : ''}
          ${f.remediation ? `<div class="fl">Remediation</div><div class="fv">${f.remediation}</div>` : ''}
          ${f.cve ? `<div class="fl">CVE</div><div class="fv"><a href="https://nvd.nist.gov/vuln/detail/${f.cve}" target="_blank">${f.cve}</a></div>` : ''}
        </div>
      </div>`;
    });
  }

  document.getElementById('mainContent').innerHTML = html;
  const lb = document.getElementById('logBox');
  if (lb) lb.scrollTop = lb.scrollHeight;
}

function renderLoading(target, modules) {
  document.getElementById('mainContent').innerHTML = `
  <div class="summary-row">
    ${'<div class="stat"><div class="stat-n">—</div><div class="stat-l">...</div></div>'.repeat(6)}
  </div>
  <div class="log-box">Starting scan against ${target} with ${modules.length} modules...</div>`;
}

async function generateReport() {
  if (!currentScanId) { alert('Run a scan first'); return; }
  window.open(`/api/scan/${currentScanId}/report`, '_blank');
}

async function loadSidebarScans() {
  const res = await fetch('/api/scans');
  const scans = await res.json();
  const el = document.getElementById('sidebarScans');
  el.innerHTML = scans.slice(0, 10).map(s => `
  <div class="scan-item" onclick="loadScan('${s.id}')">
    <div class="si-target">
      <span class="dot ${s.status}"></span> ${s.target}
    </div>
    <div class="si-meta">${s.total} findings · ${s.critical} crit</div>
  </div>`).join('');
}

async function loadScan(scanId) {
  currentScanId = scanId;
  const res = await fetch(`/api/scan/${scanId}`);
  const scan = await res.json();
  document.getElementById('targetInput').value = scan.target;
  updateUI(scan);
}

function showView(v) {
  document.querySelectorAll('.nav-item').forEach(e => e.classList.remove('active'));
  event.target.classList.add('active');
}

loadSidebarScans();
</script>
</body>
</html>"""


def run(host: str = "127.0.0.1", port: int = 5000, debug: bool = False) -> None:
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run()
