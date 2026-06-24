"""html_report.py - Generate a self-contained HTML dashboard from SIEM run output.

Produces a single dashboard.html with embedded CSS and JS (no external deps).
Open directly in any browser.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List


def _severity_color(s: str) -> str:
    return {"CRITICAL": "#dc2626", "HIGH": "#ea580c",
            "MEDIUM": "#d97706", "LOW": "#2563eb", "INFO": "#6b7280"}.get(s, "#6b7280")


def _mitre_short(t: str) -> str:
    return t if t else "N/A"


def generate_report(events, signals, tickets, out_path: str) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sev_counts = Counter(t.severity for t in tickets)
    type_counts = Counter(s.signal_type.split(".")[0] for s in signals)
    mitre_counts = Counter(s.mitre_technique for s in signals if s.mitre_technique)
    hosts = Counter(s.host.hostname if s.host else "unknown" for s in signals)

    tickets_sorted = sorted(tickets, key=lambda t: t.score, reverse=True)

    # -- Build ticket rows ------------------------------------------------------
    ticket_rows = ""
    for t in tickets_sorted:
        color = _severity_color(t.severity)
        hashes_html = ""
        if t.file_hashes:
            for k, v in t.file_hashes.items():
                hashes_html += f'<span class="hash">{k.upper()}: {v[:16]}...</span> '
        actions_html = ""
        for a in t.actions_taken[:3]:
            actions_html += f'<span class="action">{a.get("action","?")}</span> '
        ticket_rows += f"""
        <tr>
          <td><code class="tid">{t.ticket_id}</code></td>
          <td><span class="badge" style="background:{color}">{t.severity}</span></td>
          <td class="score">{t.score:.2f}</td>
          <td class="stype">{t.signal_type}</td>
          <td>{t.host}</td>
          <td>{_mitre_short(t.mitre_technique)}</td>
          <td>{hashes_html or '<span class="na">-</span>'}</td>
          <td class="actions">{actions_html}</td>
          <td><span class="status {t.status}">{t.status}</span></td>
        </tr>"""

    # -- Signal type bars -------------------------------------------------------
    max_type = max(type_counts.values(), default=1)
    type_bars = ""
    for stype, cnt in type_counts.most_common(8):
        pct = int(cnt / max_type * 100)
        type_bars += f"""
        <div class="bar-row">
          <div class="bar-label">{stype}</div>
          <div class="bar-track"><div class="bar-fill" style="width:{pct}%"></div></div>
          <div class="bar-count">{cnt}</div>
        </div>"""

    # -- MITRE bars -------------------------------------------------------------
    max_mitre = max(mitre_counts.values(), default=1)
    mitre_bars = ""
    for tech, cnt in mitre_counts.most_common(8):
        pct = int(cnt / max_mitre * 100)
        mitre_bars += f"""
        <div class="bar-row">
          <div class="bar-label">{tech}</div>
          <div class="bar-track"><div class="bar-fill mitre" style="width:{pct}%"></div></div>
          <div class="bar-count">{cnt}</div>
        </div>"""

    # -- Severity donut data ----------------------------------------------------
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_js = json.dumps({s: sev_counts.get(s, 0) for s in sev_order})
    sev_colors_js = json.dumps({s: _severity_color(s) for s in sev_order})

    # -- Host bars -------------------------------------------------------------
    max_host = max(hosts.values(), default=1)
    host_bars = ""
    for host, cnt in hosts.most_common(5):
        pct = int(cnt / max_host * 100)
        host_bars += f"""
        <div class="bar-row">
          <div class="bar-label">{host[:30]}</div>
          <div class="bar-track"><div class="bar-fill host" style="width:{pct}%"></div></div>
          <div class="bar-count">{cnt}</div>
        </div>"""

    total_critical = sev_counts.get("CRITICAL", 0)
    total_high     = sev_counts.get("HIGH", 0)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mini SIEM Dashboard</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #273449;
    --border: #334155; --text: #e2e8f0; --muted: #94a3b8;
    --accent: #3b82f6; --critical: #dc2626; --high: #ea580c;
    --medium: #d97706; --low: #2563eb;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }}
  .header {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 16px 28px; display: flex; align-items: center; justify-content: space-between; }}
  .header h1 {{ font-size: 18px; font-weight: 700; letter-spacing: -0.3px; }}
  .header .sub {{ color: var(--muted); font-size: 12px; margin-top: 2px; }}
  .badge-run {{ background: #1d4ed8; color: #fff; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; }}
  .main {{ padding: 24px 28px; max-width: 1400px; margin: 0 auto; }}
  .grid4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 18px 20px; }}
  .card .label {{ font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }}
  .card .value {{ font-size: 32px; font-weight: 700; line-height: 1; }}
  .card .sub {{ font-size: 11px; color: var(--muted); margin-top: 4px; }}
  .card.critical .value {{ color: var(--critical); }}
  .card.high .value {{ color: var(--high); }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }}
  .grid3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 24px; }}
  .card h3 {{ font-size: 13px; font-weight: 600; margin-bottom: 14px; color: var(--text); }}
  .bar-row {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
  .bar-label {{ width: 160px; font-size: 11px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex-shrink: 0; }}
  .bar-track {{ flex: 1; background: var(--surface2); border-radius: 4px; height: 8px; }}
  .bar-fill {{ height: 8px; border-radius: 4px; background: var(--accent); transition: width 0.3s; }}
  .bar-fill.mitre {{ background: #7c3aed; }}
  .bar-fill.host  {{ background: #0891b2; }}
  .bar-count {{ width: 28px; text-align: right; font-size: 11px; color: var(--muted); flex-shrink: 0; }}
  canvas#donut {{ max-height: 160px; }}
  .donut-wrap {{ display: flex; align-items: center; gap: 20px; }}
  .donut-legend {{ flex: 1; }}
  .legend-row {{ display: flex; align-items: center; gap: 8px; margin-bottom: 6px; font-size: 11px; }}
  .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th {{ background: var(--surface2); color: var(--muted); text-transform: uppercase; font-size: 10px; letter-spacing: 0.5px; padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); }}
  td {{ padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: middle; }}
  tr:hover td {{ background: var(--surface2); }}
  .badge {{ color: #fff; padding: 2px 8px; border-radius: 12px; font-size: 10px; font-weight: 700; white-space: nowrap; }}
  .tid {{ font-size: 11px; color: var(--accent); font-family: monospace; }}
  .score {{ font-weight: 700; font-family: monospace; }}
  .stype {{ font-family: monospace; font-size: 11px; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .hash {{ display: inline-block; background: var(--surface2); border-radius: 4px; padding: 1px 5px; font-size: 10px; font-family: monospace; margin-right: 4px; color: #a78bfa; }}
  .action {{ display: inline-block; background: #1e3a5f; border-radius: 4px; padding: 1px 6px; font-size: 10px; margin-right: 3px; color: #60a5fa; }}
  .status {{ font-size: 10px; font-weight: 600; text-transform: uppercase; }}
  .status.open {{ color: #f59e0b; }}
  .status.investigating {{ color: #3b82f6; }}
  .status.resolved {{ color: #10b981; }}
  .na {{ color: var(--border); }}
  .actions {{ max-width: 180px; }}
  .section-title {{ font-size: 13px; font-weight: 600; margin-bottom: 14px; }}
</style>
</head>
<body>
<div class="header">
  <div>
    <div class="h1" style="font-size:18px;font-weight:700">Mini SIEM <span style="color:var(--muted);font-weight:400">Dashboard</span></div>
    <div class="sub">Generated {now} &nbsp;|&nbsp; Damien Defer / SME Security Hardening</div>
  </div>
  <span class="badge-run">v8 SOAR Active</span>
</div>

<div class="main">
  <!-- KPI row -->
  <div class="grid4">
    <div class="card"><div class="label">Total Signals</div><div class="value">{len(signals)}</div><div class="sub">after deduplication</div></div>
    <div class="card"><div class="label">Tickets Created</div><div class="value">{len(tickets)}</div><div class="sub">by SOAR orchestrator</div></div>
    <div class="card critical"><div class="label">Critical</div><div class="value">{total_critical}</div><div class="sub">score &gt;= 0.90</div></div>
    <div class="card high"><div class="label">High</div><div class="value">{total_high}</div><div class="sub">score &gt;= 0.75</div></div>
  </div>

  <!-- Charts row -->
  <div class="grid3">
    <div class="card">
      <h3>Severity Distribution</h3>
      <div class="donut-wrap">
        <canvas id="donut" width="140" height="140"></canvas>
        <div class="donut-legend" id="donut-legend"></div>
      </div>
    </div>
    <div class="card">
      <h3>Signal Types</h3>
      {type_bars}
    </div>
    <div class="card">
      <h3>MITRE ATT&CK / ATLAS Techniques</h3>
      {mitre_bars}
    </div>
  </div>

  <!-- Hosts -->
  <div class="card" style="margin-bottom:24px">
    <h3>Signals by Host</h3>
    {host_bars}
  </div>

  <!-- Ticket table -->
  <div class="card">
    <div class="section-title">SOAR Tickets ({len(tickets)})</div>
    <div style="overflow-x:auto">
    <table>
      <thead>
        <tr>
          <th>Ticket ID</th><th>Severity</th><th>Score</th>
          <th>Signal Type</th><th>Host</th><th>MITRE</th>
          <th>File Hashes</th><th>Actions Taken</th><th>Status</th>
        </tr>
      </thead>
      <tbody>{ticket_rows}</tbody>
    </table>
    </div>
  </div>
</div>

<script>
const sevData   = {sev_js};
const sevColors = {sev_colors_js};
const order     = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"];

// Donut chart
const canvas = document.getElementById("donut");
const ctx    = canvas.getContext("2d");
const total  = Object.values(sevData).reduce((a,b) => a+b, 0) || 1;
let start = -Math.PI/2;
const R = 58, cx = 70, cy = 70, iR = 38;

order.forEach(k => {{
  const v = sevData[k];
  if (!v) return;
  const angle = (v/total) * 2 * Math.PI;
  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.arc(cx, cy, R, start, start+angle);
  ctx.closePath();
  ctx.fillStyle = sevColors[k];
  ctx.fill();
  start += angle;
}});
// hole
ctx.beginPath();
ctx.arc(cx, cy, iR, 0, 2*Math.PI);
ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--surface").trim() || "#1e293b";
ctx.fill();
// center text
ctx.fillStyle = "#e2e8f0";
ctx.font = "bold 18px Segoe UI";
ctx.textAlign = "center";
ctx.textBaseline = "middle";
ctx.fillText(total, cx, cy);

// legend
const leg = document.getElementById("donut-legend");
order.forEach(k => {{
  if (!sevData[k]) return;
  leg.innerHTML += `<div class="legend-row"><div class="legend-dot" style="background:${{sevColors[k]}}"></div><span style="color:#94a3b8">${{k}}</span><span style="margin-left:auto;font-weight:700">${{sevData[k]}}</span></div>`;
}});
</script>
</body>
</html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
