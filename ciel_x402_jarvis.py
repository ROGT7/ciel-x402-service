"""
CIEL JARVIS Dashboard — Iron Man HUD Interface
================================================
Dashboard web temps réel intégré au serveur x402.
Vue complète de tout ce que CIEL fait en autonomie.

Endpoints ajoutés:
- /jarvis       → Dashboard HTML (HUD Iron Man)
- /jarvis/api   → JSON agrégé de toutes les métriques

Le dashboard poll /jarvis/api toutes les 2 secondes et affiche:
- Santé serveur (uptime, RAM, CPU, services actifs)
- Sécurité (IPs bannies, violations, rate limiting)
- Paiements (tx vérifiées, replays bloqués, revenus)
- Services (93 endpoints, prix dynamiques, latences)
- Red Team (attaques lancées, crashes détectés)
- Auto-Patch (patches appliqués, boucle status)
- Logs en direct (dernières requêtes)
"""
import os
import json
import time
import psutil
import threading
from datetime import datetime, timezone
from collections import deque
from pathlib import Path


# ============================================================
# Live Metrics Collector
# ============================================================

class JarvisCollector:
    """Collecte toutes les métriques en temps réel pour le dashboard."""

    def __init__(self, server_app=None, security_mw=None, pricing=None,
                 signer=None, sweeper=None, services=None, wallet="", network=""):
        self.server_app = server_app
        self.security_mw = security_mw
        self.pricing = pricing
        self.signer = signer
        self.sweeper = sweeper
        self.services = services or []
        self.wallet = wallet
        self.network = network
        self.start_time = time.time()

        # Live request log (last 100)
        self.request_log = deque(maxlen=100)
        self._lock = threading.Lock()

        # Red Team / Auto-Patch status
        self.redteam_status = {"running": False, "last_round": None, "total_attacks": 0, "total_crashes": 0}
        self.autopatch_status = {"running": False, "total_patches": 0, "last_patch": None}

        # Revenue tracking
        self.revenue = {"total_usdc": 0.0, "tx_count": 0, "replays_blocked": 0}

        # Crash log reader
        self.crash_log_path = Path(os.environ.get("CIEL_ROOT", ".")) / "memory" / "redteam" / "crash_logs.jsonl"
        self.patch_log_path = Path(os.environ.get("CIEL_ROOT", ".")) / "memory" / "redteam" / "patch_history.jsonl"
        self.redteam_results_path = Path(os.environ.get("CIEL_ROOT", ".")) / "memory" / "redteam" / "redteam_results.jsonl"

    def log_request(self, method: str, path: str, status: int, ip: str, duration_ms: float):
        """Log a request for the live feed."""
        with self._lock:
            self.request_log.appendleft({
                "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "method": method,
                "path": path,
                "status": status,
                "ip": ip,
                "duration_ms": round(duration_ms, 1),
            })

    def _read_redteam_data(self) -> dict:
        """Read Red Team results and crash logs."""
        data = {"total_attacks": 0, "total_crashes": 0, "last_round": None, "recent_crashes": []}

        # Read last round
        if self.redteam_results_path.exists():
            try:
                lines = self.redteam_results_path.read_text().strip().split("\n")
                if lines:
                    last = json.loads(lines[-1])
                    data["last_round"] = {
                        "round": last.get("round"),
                        "timestamp": last.get("timestamp"),
                        "summary": last.get("summary"),
                    }
                    # Sum all attacks
                    for line in lines[-20:]:
                        try:
                            r = json.loads(line)
                            s = r.get("summary", {})
                            data["total_attacks"] += s.get("total_attacks", 0)
                            data["total_crashes"] += s.get("total_crashes", 0)
                        except Exception:
                            pass
            except Exception:
                pass

        # Read recent crashes
        if self.crash_log_path.exists():
            try:
                lines = self.crash_log_path.read_text().strip().split("\n")
                for line in lines[-10:]:
                    try:
                        data["recent_crashes"].append(json.loads(line))
                    except Exception:
                        pass
            except Exception:
                pass

        return data

    def _read_autopatch_data(self) -> dict:
        """Read auto-patch history."""
        data = {"total_patches": 0, "last_patch": None, "recent_patches": []}

        if self.patch_log_path.exists():
            try:
                lines = self.patch_log_path.read_text().strip().split("\n")
                data["total_patches"] = len(lines)
                if lines:
                    last = json.loads(lines[-1])
                    data["last_patch"] = {
                        "timestamp": last.get("timestamp"),
                        "crash_hash": last.get("crash_hash"),
                        "action": last.get("patch_result", {}).get("action"),
                        "success": last.get("patch_result", {}).get("success"),
                    }
                for line in lines[-5:]:
                    try:
                        entry = json.loads(line)
                        data["recent_patches"].append({
                            "timestamp": entry.get("timestamp", ""),
                            "action": entry.get("patch_result", {}).get("action", ""),
                            "success": entry.get("patch_result", {}).get("success", False),
                            "root_cause": entry.get("analysis", {}).get("root_cause", ""),
                        })
                    except Exception:
                        pass
            except Exception:
                pass

        return data

    def collect_all(self) -> dict:
        """Collect all metrics for the dashboard."""
        now = time.time()
        uptime_s = int(now - self.start_time)

        # System metrics
        try:
            cpu_pct = psutil.cpu_percent(interval=0.5)
            ram = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
        except Exception:
            cpu_pct = 0
            ram = None
            disk = None

        # Security status
        sec_status = {}
        if self.security_mw:
            try:
                sec_status = self.security_mw.get_status()
            except Exception:
                sec_status = {"error": "unavailable"}

        # Pricing
        pricing_data = {}
        if self.pricing:
            try:
                pricing_data = self.pricing.get_pricing_report()
            except Exception:
                pricing_data = {"error": "unavailable"}

        # Signer
        signer_data = {}
        if self.signer:
            try:
                signer_data = self.signer.get_stats()
            except Exception:
                signer_data = {"error": "unavailable"}

        # Services
        svc_count = len(self.services)
        svc_categories = {}
        for s in self.services:
            cat = s.get("category", "general")
            svc_categories[cat] = svc_categories.get(cat, 0) + 1

        # Red Team + Auto-Patch
        redteam_data = self._read_redteam_data()
        autopatch_data = self._read_autopatch_data()

        # Live request log
        with self._lock:
            recent_requests = list(self.request_log[:30])

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime_s": uptime_s,
            "uptime_human": self._format_uptime(uptime_s),
            "system": {
                "cpu_pct": cpu_pct,
                "ram_total_gb": round(ram.total / 1e9, 1) if ram else 0,
                "ram_used_gb": round(ram.used / 1e9, 1) if ram else 0,
                "ram_pct": ram.percent if ram else 0,
                "disk_total_gb": round(disk.total / 1e9, 1) if disk else 0,
                "disk_used_gb": round(disk.used / 1e9, 1) if disk else 0,
                "disk_pct": disk.percent if disk else 0,
            },
            "server": {
                "wallet": self.wallet[:10] + "..." if self.wallet else "not_set",
                "network": self.network,
                "services_count": svc_count,
                "categories": svc_categories,
            },
            "security": sec_status,
            "pricing": pricing_data,
            "signer": signer_data,
            "revenue": self.revenue,
            "redteam": redteam_data,
            "autopatch": autopatch_data,
            "live_requests": recent_requests,
        }

    @staticmethod
    def _format_uptime(s: int) -> str:
        d = s // 86400
        h = (s % 86400) // 3600
        m = (s % 3600) // 60
        sec = s % 60
        if d > 0:
            return f"{d}d {h}h {m}m"
        if h > 0:
            return f"{h}h {m}m {sec}s"
        if m > 0:
            return f"{m}m {sec}s"
        return f"{sec}s"


# ============================================================
# JARVIS Dashboard HTML
# ============================================================

JARVIS_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CIEL — JARVIS Dashboard</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
:root {
  --cyan: #00f0ff;
  --cyan-dim: #00a8b5;
  --blue: #0a84ff;
  --gold: #ffd700;
  --red: #ff3b3b;
  --green: #00ff88;
  --orange: #ff9500;
  --bg: #000510;
  --panel: rgba(0, 20, 40, 0.85);
  --border: rgba(0, 240, 255, 0.3);
}
body {
  background: var(--bg);
  color: var(--cyan);
  font-family: "Courier New", monospace;
  overflow: hidden;
  height: 100vh;
}
/* Animated background grid */
body::before {
  content: "";
  position: fixed;
  top: 0; left: 0; width: 100%; height: 100%;
  background-image:
    linear-gradient(rgba(0,240,255,0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,240,255,0.03) 1px, transparent 1px);
  background-size: 40px 40px;
  pointer-events: none;
  z-index: 0;
}
/* Arc reactor pulse */
body::after {
  content: "";
  position: fixed;
  top: 50%; left: 50%;
  width: 600px; height: 600px;
  border: 2px solid rgba(0,240,255,0.05);
  border-radius: 50%;
  transform: translate(-50%, -50%);
  animation: pulse 4s ease-in-out infinite;
  pointer-events: none;
  z-index: 0;
}
@keyframes pulse {
  0%, 100% { opacity: 0.3; transform: translate(-50%,-50%) scale(1); }
  50% { opacity: 0.6; transform: translate(-50%,-50%) scale(1.05); }
}
#app {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  grid-template-rows: auto 1fr 1fr auto;
  gap: 10px;
  padding: 10px;
  height: 100vh;
  position: relative;
  z-index: 1;
}
/* Header */
.header {
  grid-column: 1 / -1;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 20px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
}
.header h1 {
  font-size: 22px;
  letter-spacing: 4px;
  text-shadow: 0 0 10px var(--cyan);
}
.header .status-dot {
  display: inline-block;
  width: 10px; height: 10px;
  border-radius: 50%;
  background: var(--green);
  box-shadow: 0 0 8px var(--green);
  animation: blink 2s infinite;
  margin-right: 8px;
}
@keyframes blink { 50% { opacity: 0.4; } }
.header .uptime {
  color: var(--cyan-dim);
  font-size: 14px;
}
/* Panels */
.panel {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px;
  overflow-y: auto;
  position: relative;
}
.panel h2 {
  font-size: 13px;
  letter-spacing: 2px;
  color: var(--cyan);
  margin-bottom: 10px;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--border);
  text-transform: uppercase;
}
.panel h2 .icon { margin-right: 6px; }
/* Metric rows */
.metric {
  display: flex;
  justify-content: space-between;
  padding: 4px 0;
  font-size: 13px;
}
.metric .label { color: var(--cyan-dim); }
.metric .value { color: var(--cyan); font-weight: bold; }
.metric .value.warn { color: var(--orange); }
.metric .value.crit { color: var(--red); }
.metric .value.ok { color: var(--green); }
/* Progress bars */
.bar-container {
  width: 100%;
  height: 6px;
  background: rgba(0,240,255,0.1);
  border-radius: 3px;
  margin: 4px 0 8px 0;
  overflow: hidden;
}
.bar-fill {
  height: 100%;
  border-radius: 3px;
  transition: width 0.5s ease;
}
.bar-fill.cpu { background: linear-gradient(90deg, var(--green), var(--orange), var(--red)); }
.bar-fill.ram { background: linear-gradient(90deg, var(--blue), var(--cyan)); }
.bar-fill.disk { background: linear-gradient(90deg, var(--cyan-dim), var(--cyan)); }
/* Live request feed */
.request-feed {
  font-size: 11px;
  font-family: monospace;
}
.request-feed .req {
  padding: 3px 0;
  border-bottom: 1px solid rgba(0,240,255,0.1);
  display: flex;
  gap: 8px;
  align-items: center;
}
.req .time { color: var(--cyan-dim); min-width: 65px; }
.req .method {
  min-width: 40px;
  font-weight: bold;
  padding: 1px 4px;
  border-radius: 3px;
  font-size: 10px;
}
.req .method.GET { background: rgba(0,255,136,0.2); color: var(--green); }
.req .method.POST { background: rgba(10,132,255,0.2); color: var(--blue); }
.req .path { color: var(--cyan); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.req .status {
  min-width: 30px;
  text-align: right;
  font-weight: bold;
}
.req .status.s2 { color: var(--green); }
.req .status.s4 { color: var(--orange); }
.req .status.s5 { color: var(--red); }
.req .dur { color: var(--cyan-dim); min-width: 50px; text-align: right; }
/* Service grid */
.svc-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
  gap: 6px;
  font-size: 11px;
}
.svc-card {
  background: rgba(0,240,255,0.05);
  border: 1px solid rgba(0,240,255,0.15);
  border-radius: 4px;
  padding: 6px;
  text-align: center;
}
.svc-card .name { color: var(--cyan); font-size: 10px; }
.svc-card .price { color: var(--gold); font-weight: bold; }
/* Crash log */
.crash-item {
  padding: 6px;
  margin: 4px 0;
  background: rgba(255,59,59,0.1);
  border-left: 3px solid var(--red);
  border-radius: 4px;
  font-size: 11px;
}
.crash-item .endpoint { color: var(--red); font-weight: bold; }
.crash-item .error { color: var(--orange); }
/* Patch log */
.patch-item {
  padding: 6px;
  margin: 4px 0;
  background: rgba(0,255,136,0.1);
  border-left: 3px solid var(--green);
  border-radius: 4px;
  font-size: 11px;
}
.patch-item .action { color: var(--green); font-weight: bold; }
.patch-item .fail { color: var(--red); }
/* Footer */
.footer {
  grid-column: 1 / -1;
  display: flex;
  justify-content: space-between;
  padding: 6px 20px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  font-size: 12px;
  color: var(--cyan-dim);
}
/* Scrollbar */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: rgba(0,240,255,0.05); }
::-webkit-scrollbar-thumb { background: rgba(0,240,255,0.3); border-radius: 3px; }
/* Boot animation */
.boot {
  position: fixed;
  top: 0; left: 0; width: 100%; height: 100%;
  background: var(--bg);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
  animation: bootFade 3s ease forwards;
}
.boot-text {
  font-size: 28px;
  letter-spacing: 8px;
  color: var(--cyan);
  text-shadow: 0 0 20px var(--cyan);
  animation: bootGlow 1.5s ease-in-out infinite;
}
@keyframes bootFade { 80% { opacity: 1; } 100% { opacity: 0; pointer-events: none; } }
@keyframes bootGlow { 50% { text-shadow: 0 0 40px var(--cyan); } }
/* Responsive */
@media (max-width: 1200px) {
  #app { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 700px) {
  #app { grid-template-columns: 1fr; grid-template-rows: auto auto auto auto auto auto; }
}
</style>
</head>
<body>
<div class="boot"><div class="boot-text">J.A.R.V.I.S</div></div>
<div id="app">
  <!-- Header -->
  <div class="header">
    <div><span class="status-dot" id="dot"></span><h1 style="display:inline">CIEL JARVIS</h1></div>
    <div class="uptime" id="uptime">BOOTING...</div>
  </div>

  <!-- Panel 1: System -->
  <div class="panel" id="sys-panel">
    <h2><span class="icon">&#9881;</span>SYSTEM</h2>
    <div class="metric"><span class="label">CPU</span><span class="value" id="cpu-val">0%</span></div>
    <div class="bar-container"><div class="bar-fill cpu" id="cpu-bar" style="width:0%"></div></div>
    <div class="metric"><span class="label">RAM</span><span class="value" id="ram-val">0 / 0 GB</span></div>
    <div class="bar-container"><div class="bar-fill ram" id="ram-bar" style="width:0%"></div></div>
    <div class="metric"><span class="label">DISK</span><span class="value" id="disk-val">0 / 0 GB</span></div>
    <div class="bar-container"><div class="bar-fill disk" id="disk-bar" style="width:0%"></div></div>
    <div class="metric"><span class="label">UPTIME</span><span class="value" id="uptime-val">--</span></div>
    <div class="metric"><span class="label">NETWORK</span><span class="value" id="net-val">--</span></div>
    <div class="metric"><span class="label">WALLET</span><span class="value" id="wallet-val">--</span></div>
  </div>

  <!-- Panel 2: Security -->
  <div class="panel" id="sec-panel">
    <h2><span class="icon">&#128737;</span>SECURITY</h2>
    <div class="metric"><span class="label">Status</span><span class="value ok" id="sec-status">ACTIVE</span></div>
    <div class="metric"><span class="label">IPs Banned</span><span class="value" id="sec-banned">0</span></div>
    <div class="metric"><span class="label">Violations</span><span class="value" id="sec-violations">0</span></div>
    <div class="metric"><span class="label">Total Requests</span><span class="value" id="sec-requests">0</span></div>
    <div class="metric"><span class="label">Blocklist</span><span class="value" id="sec-blocklist">0</span></div>
    <div class="metric"><span class="label">Max RPM</span><span class="value" id="sec-rpm">--</span></div>
    <div class="metric"><span class="label">Ban Duration</span><span class="value" id="sec-bandur">--</span></div>
    <div id="sec-extra"></div>
  </div>

  <!-- Panel 3: Revenue -->
  <div class="panel" id="rev-panel">
    <h2><span class="icon">&#128176;</span>REVENUE</h2>
    <div class="metric"><span class="label">Total USDC</span><span class="value" id="rev-total" style="color:var(--gold)">$0.00</span></div>
    <div class="metric"><span class="label">Transactions</span><span class="value" id="rev-tx">0</span></div>
    <div class="metric"><span class="label">Replays Blocked</span><span class="value" id="rev-replays">0</span></div>
    <div class="metric"><span class="label">Services Online</span><span class="value ok" id="rev-services">0</span></div>
    <div class="metric"><span class="label">Avg Price</span><span class="value" id="rev-avgprice">$0.00</span></div>
    <div style="margin-top:10px">
      <h2 style="font-size:11px">CATEGORIES</h2>
      <div id="cat-list"></div>
    </div>
  </div>

  <!-- Panel 4: Live Feed -->
  <div class="panel" id="feed-panel" style="grid-row: span 2">
    <h2><span class="icon">&#128248;</span>LIVE REQUEST FEED</h2>
    <div class="request-feed" id="req-feed">
      <div style="color:var(--cyan-dim);text-align:center;padding:20px">Waiting for requests...</div>
    </div>
  </div>

  <!-- Panel 5: Red Team -->
  <div class="panel" id="rt-panel">
    <h2><span class="icon">&#128737;</span>RED TEAM</h2>
    <div class="metric"><span class="label">Total Attacks</span><span class="value" id="rt-attacks">0</span></div>
    <div class="metric"><span class="label">Total Crashes</span><span class="value" id="rt-crashes">0</span></div>
    <div class="metric"><span class="label">Last Round</span><span class="value" id="rt-round">--</span></div>
    <div style="margin-top:10px">
      <h2 style="font-size:11px">RECENT CRASHES</h2>
      <div id="crash-list"><div style="color:var(--cyan-dim);font-size:11px">No crashes detected</div></div>
    </div>
  </div>

  <!-- Panel 6: Auto-Patch -->
  <div class="panel" id="ap-panel">
    <h2><span class="icon">&#128736;</span>AUTO-PATCH</h2>
    <div class="metric"><span class="label">Patches Applied</span><span class="value" id="ap-total">0</span></div>
    <div class="metric"><span class="label">Last Patch</span><span class="value" id="ap-last">--</span></div>
    <div class="metric"><span class="label">Loop Status</span><span class="value" id="ap-loop">--</span></div>
    <div style="margin-top:10px">
      <h2 style="font-size:11px">RECENT PATCHES</h2>
      <div id="patch-list"><div style="color:var(--cyan-dim);font-size:11px">No patches applied yet</div></div>
    </div>
  </div>

  <!-- Footer -->
  <div class="footer">
    <span id="footer-left">CIEL Autonomous System &mdash; JARVIS Interface v1.0</span>
    <span id="footer-right">Polling: 2s | <span id="poll-count">0</span> cycles</span>
  </div>
</div>

<script>
let pollCount = 0;
let lastData = null;

async function poll() {
  try {
    const resp = await fetch("/jarvis/api");
    const data = await resp.json();
    lastData = data;
    pollCount++;
    updateUI(data);
  } catch (e) {
    document.getElementById("dot").style.background = "var(--red)";
    document.getElementById("dot").style.boxShadow = "0 0 8px var(--red)";
    document.getElementById("uptime").textContent = "CONNECTION LOST";
  }
}

function updateUI(d) {
  // Header
  document.getElementById("dot").style.background = "var(--green)";
  document.getElementById("dot").style.boxShadow = "0 0 8px var(--green)";
  document.getElementById("uptime").textContent = d.uptime_human + " | " + new Date(d.timestamp).toLocaleTimeString();

  // System
  const sys = d.system;
  document.getElementById("cpu-val").textContent = sys.cpu_pct + "%";
  document.getElementById("cpu-bar").style.width = sys.cpu_pct + "%";
  document.getElementById("ram-val").textContent = sys.ram_used_gb + " / " + sys.ram_total_gb + " GB";
  document.getElementById("ram-bar").style.width = sys.ram_pct + "%";
  document.getElementById("disk-val").textContent = sys.disk_used_gb + " / " + sys.disk_total_gb + " GB";
  document.getElementById("disk-bar").style.width = sys.disk_pct + "%";
  document.getElementById("uptime-val").textContent = d.uptime_human;
  document.getElementById("net-val").textContent = d.server.network;
  document.getElementById("wallet-val").textContent = d.server.wallet;

  // Security
  const sec = d.security || {};
  document.getElementById("sec-status").textContent = sec.active ? "ACTIVE" : "INACTIVE";
  document.getElementById("sec-status").className = "value " + (sec.active ? "ok" : "crit");
  document.getElementById("sec-banned").textContent = sec.banned_ips || 0;
  document.getElementById("sec-violations").textContent = sec.total_violations || 0;
  document.getElementById("sec-requests").textContent = sec.total_requests || 0;
  document.getElementById("sec-blocklist").textContent = sec.blocklist_size || 0;
  document.getElementById("sec-rpm").textContent = sec.max_rpm || "--";
  document.getElementById("sec-bandur").textContent = (sec.ban_duration_s || 0) + "s";

  // Revenue
  const rev = d.revenue || {};
  document.getElementById("rev-total").textContent = "$" + (rev.total_usdc || 0).toFixed(2);
  document.getElementById("rev-tx").textContent = rev.tx_count || 0;
  document.getElementById("rev-replays").textContent = rev.replays_blocked || 0;
  document.getElementById("rev-services").textContent = d.server.services_count || 0;

  // Categories
  const cats = d.server.categories || {};
  let catHtml = "";
  for (const [cat, count] of Object.entries(cats)) {
    catHtml += '<div class="metric"><span class="label">' + cat + '</span><span class="value">' + count + '</span></div>';
  }
  document.getElementById("cat-list").innerHTML = catHtml;

  // Live requests
  const reqs = d.live_requests || [];
  if (reqs.length === 0) {
    document.getElementById("req-feed").innerHTML = '<div style="color:var(--cyan-dim);text-align:center;padding:20px">Waiting for requests...</div>';
  } else {
    let html = "";
    for (const r of reqs) {
      const sc = r.status < 300 ? "s2" : r.status < 500 ? "s4" : "s5";
      const mc = r.method === "GET" ? "GET" : "POST";
      html += '<div class="req"><span class="time">' + r.time + '</span>' +
        '<span class="method ' + mc + '">' + r.method + '</span>' +
        '<span class="path">' + r.path + '</span>' +
        '<span class="status ' + sc + '">' + r.status + '</span>' +
        '<span class="dur">' + r.duration_ms + 'ms</span></div>';
    }
    document.getElementById("req-feed").innerHTML = html;
  }

  // Red Team
  const rt = d.redteam || {};
  document.getElementById("rt-attacks").textContent = rt.total_attacks || 0;
  document.getElementById("rt-crashes").textContent = rt.total_crashes || 0;
  const lr = rt.last_round;
  document.getElementById("rt-round").textContent = lr ? "Round #" + lr.round : "None";

  const crashes = rt.recent_crashes || [];
  if (crashes.length === 0) {
    document.getElementById("crash-list").innerHTML = '<div style="color:var(--green);font-size:11px">No crashes detected &#10003;</div>';
  } else {
    let html = "";
    for (const c of crashes.slice(0, 5)) {
      html += '<div class="crash-item"><span class="endpoint">' + (c.endpoint || c.component || "unknown") +
        '</span> <span class="error">' + (c.error || "").substring(0, 80) + '</span></div>';
    }
    document.getElementById("crash-list").innerHTML = html;
  }

  // Auto-Patch
  const ap = d.autopatch || {};
  document.getElementById("ap-total").textContent = ap.total_patches || 0;
  const lp = ap.last_patch;
  document.getElementById("ap-last").textContent = lp ? (lp.action || "applied") : "None";

  const patches = ap.recent_patches || [];
  if (patches.length === 0) {
    document.getElementById("patch-list").innerHTML = '<div style="color:var(--cyan-dim);font-size:11px">No patches applied yet</div>';
  } else {
    let html = "";
    for (const p of patches.slice(0, 5)) {
      const cls = p.success ? "" : " fail";
      html += '<div class="patch-item"><span class="action' + cls + '">' + p.action +
        '</span> ' + (p.root_cause || "").substring(0, 60) + '</div>';
    }
    document.getElementById("patch-list").innerHTML = html;
  }

  // Footer
  document.getElementById("poll-count").textContent = pollCount;
}

// Start polling
poll();
setInterval(poll, 2000);
</script>
</body>
</html>'''


# ============================================================
# FastAPI Integration
# ============================================================

def integrate_jarvis(app, collector: JarvisCollector):
    """
    Integrate JARVIS dashboard into the FastAPI app.
    Adds /jarvis (HTML), /jarvis/api (JSON), /ironman (HUD) endpoints.
    """
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi import Request

    @app.get("/jarvis", response_class=HTMLResponse)
    async def jarvis_dashboard():
        return JARVIS_HTML

    @app.get("/jarvis/api")
    async def jarvis_api():
        return JSONResponse(collector.collect_all())

    # === Iron Man HUD — Dashboard VPS2 + MoE ===
    @app.get("/ironman", response_class=HTMLResponse)
    async def ironman_hud():
        """Iron Man HUD — dashboard CIEL autonome."""
        import urllib.request as urlopen
        status = collector.collect_all()

        # Recuperer modeles Ollama VPS2
        vps2_models = []
        try:
            req = urlopen.Request("http://127.0.0.1:11434/api/tags")
            resp = urlopen.urlopen(req, timeout=5)
            import json as _json
            data = _json.loads(resp.read().decode())
            vps2_models = [m["name"] for m in data.get("models", [])]
        except Exception:
            pass

        # Recuperer statut MoE
        moe_status = {}
        try:
            import json as _json
            req = urlopen.Request("http://127.0.0.1:11434/api/ps")
            resp = urlopen.urlopen(req, timeout=5)
            moe_status = _json.loads(resp.read().decode())
        except Exception:
            pass

        sys_info = status.get("system", {})
        srv_info = status.get("server", {})

        html = """<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CIEL Iron Man HUD</title><style>
*{margin:0;padding:0;box-sizing:border-box;font-family:system-ui,sans-serif}
body{background:#0a0e1a;color:#e0e6f0;min-height:100vh;padding:16px}
.header{text-align:center;padding:16px 0;border-bottom:2px solid #00d4ff;margin-bottom:16px}
.header h1{color:#00d4ff;font-size:24px;text-transform:uppercase;letter-spacing:3px;text-shadow:0 0 20px rgba(0,212,255,0.5)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px;max-width:1200px;margin:0 auto}
.card{background:#131826;border-radius:12px;padding:16px;border:1px solid #1e2536}
.card h2{color:#00d4ff;font-size:13px;text-transform:uppercase;letter-spacing:2px;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #1e2536}
.stat{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #1e2536}
.stat:last-child{border:none}.stat .label{color:#888;font-size:12px}.stat .value{color:#e0e6f0;font-size:13px;font-weight:bold}
.ok{color:#00ff88}.err{color:#ff4466}.warn{color:#ffaa00}
.model{display:inline-block;background:#0a0e1a;padding:3px 6px;margin:2px;border-radius:4px;font-size:10px;color:#888}
</style></head><body>
<div class="header"><h1>CIEL Iron Man HUD</h1><div style="color:#666;font-size:11px">Dashboard autonome VPS2</div></div>
<div class="grid">
<div class="card"><h2>VPS2 Status</h2>
<div class="stat"><span class="label">Uptime</span><span class="value">""" + str(status.get("uptime_human", "N/A")) + """</span></div>
<div class="stat"><span class="label">CPU</span><span class="value">""" + str(sys_info.get("cpu_pct", "?")) + """%</span></div>
<div class="stat"><span class="label">RAM</span><span class="value">""" + str(sys_info.get("ram_used_gb", "?")) + """/""" + str(sys_info.get("ram_total_gb", "?")) + """ GB</span></div>
<div class="stat"><span class="label">Disk</span><span class="value">""" + str(sys_info.get("disk_used_gb", "?")) + """/""" + str(sys_info.get("disk_total_gb", "?")) + """ GB</span></div>
<div class="stat"><span class="label">Services</span><span class="value">""" + str(srv_info.get("services_count", "?")) + """</span></div>
<div class="stat"><span class="label">Wallet</span><span class="value">""" + str(srv_info.get("wallet", "N/A"))[:16] + """</span></div>
</div>
<div class="card"><h2>Ollama VPS2 - Modeles</h2>
<div class="stat"><span class="label">Total modeles</span><span class="value">""" + str(len(vps2_models)) + """</span></div>
<div style="margin-top:8px">""" + "".join(['<span class="model">' + m + '</span>' for m in vps2_models]) + """</div>
</div>
<div class="card"><h2>MoE Status</h2>
<div class="stat"><span class="label">Modeles charges</span><span class="value">""" + str(len(moe_status.get("models", []))) + """</span></div>
<div class="stat"><span class="label">Statut</span><span class="value ok">ACTIF</span></div>
<div class="stat"><span class="label">12 Experts</span><span class="value ok">DISPONIBLE</span></div>
<div class="stat"><span class="label">Backend</span><span class="value">VPS2 + Local</span></div>
</div>
<div class="card"><h2>Shadow Council</h2>
<div class="stat"><span class="label">MoE integre</span><span class="value ok">ACTIVE</span></div>
<div class="stat"><span class="label">Source primaire</span><span class="value">MoE Local</span></div>
<div class="stat"><span class="label">Fallback</span><span class="value warn">Cloud (rate-limited)</span></div>
</div>
<div class="card"><h2>Autonomous Compute</h2>
<div class="stat"><span class="label">Budget</span><span class="value">$20.00</span></div>
<div class="stat"><span class="label">Providers</span><span class="value">Vast.ai, RunPod, Akash</span></div>
</div>
</div>
<script>setTimeout(function(){location.reload()},30000);</script>
</body></html>"""
        return html

    @app.get("/api/ironman")
    async def ironman_api():
        """API JSON pour Iron Man HUD."""
        import json as _json
        status = collector.collect_all()
        vps2_models = []
        try:
            import urllib.request as urlopen
            req = urlopen.Request("http://127.0.0.1:11434/api/tags")
            resp = urlopen.urlopen(req, timeout=5)
            data = _json.loads(resp.read().decode())
            vps2_models = [m["name"] for m in data.get("models", [])]
        except Exception:
            pass
        return JSONResponse({
            "vps2": status,
            "ollama_models": vps2_models,
            "moe_experts": 12,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        })

    # Add middleware to log requests
    from starlette.middleware.base import BaseHTTPMiddleware

    class RequestLogger(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            start = time.time()
            response = await call_next(request)
            duration_ms = (time.time() - start) * 1000

            # Get client IP
            xff = request.headers.get("x-forwarded-for", "")
            ip = xff.split(",")[0].strip() if xff else (
                request.client.host if request.client else "unknown"
            )

            collector.log_request(
                method=request.method,
                path=str(request.url.path),
                status=response.status_code,
                ip=ip,
                duration_ms=duration_ms,
            )
            return response

    app.add_middleware(RequestLogger)

    print("[JARVIS] Dashboard available at /jarvis")
    print("[JARVIS] API endpoint at /jarvis/api")
    print("[JARVIS] Iron Man HUD at /ironman")
    return collector
