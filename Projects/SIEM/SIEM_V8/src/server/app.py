"""app.py - Mini SOAR web server (v8).

Run:
    cd SIEM_V8
    $env:PYTHONPATH = "src"     (PowerShell)
    py src/server/app.py
    open http://localhost:5000

Mode is chosen at launch via SIEM_MODE (local|server), default local.
In local mode the file browser is unrestricted (single operator on their own
machine). In server mode (v10) it is confined to SIEM_SCAN_ROOT.
"""
from __future__ import annotations

import json
import os
import string
import subprocess
import sys
import threading
import webbrowser
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, Response, jsonify, request, stream_with_context

BASE    = Path(__file__).parent.parent.parent
SRC_DIR = BASE / "src"
OUT_DIR = BASE / "out" / "large"
TICKETS = OUT_DIR / "tickets.jsonl"
SIGNALS = OUT_DIR / "signals.jsonl"

MODE      = os.environ.get("SIEM_MODE", "local").lower()
SCAN_ROOT = Path(os.environ.get("SIEM_SCAN_ROOT", str(BASE)))
ALLOWED_FORMATS = ("json", "syslog", "auto")

app = Flask(__name__, static_folder=None)


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


def _write_tickets(tickets: List[Dict]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(TICKETS, "w", encoding="utf-8") as f:
        for t in tickets:
            f.write(json.dumps(t) + "\n")


def _base_label(signal_type: str) -> str:
    return "merged" if signal_type.startswith("merged[") else signal_type


def _human(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def _within_scan_root(target: Path) -> bool:
    root = SCAN_ROOT.resolve()
    return target == root or root in target.parents


# -- Config --------------------------------------------------------------------

@app.route("/api/config")
def api_config():
    return jsonify({
        "mode": MODE,
        "scan_root": str(SCAN_ROOT.resolve()) if MODE == "server" else None,
    })


# -- Dashboard stats -----------------------------------------------------------

@app.route("/api/stats")
def api_stats():
    tickets = _read_jsonl(TICKETS)
    signals = _read_jsonl(SIGNALS)
    sev    = Counter(t.get("severity") for t in tickets)
    status = Counter(t.get("status") for t in tickets)
    mitre  = Counter(t.get("mitre_technique") for t in tickets if t.get("mitre_technique"))
    hosts  = Counter(t.get("host") for t in tickets)
    types  = Counter(_base_label(t.get("signal_type", "")) for t in tickets)
    return jsonify({
        "total_tickets": len(tickets),
        "total_signals": len(signals),
        "severity": dict(sev),
        "status":   dict(status),
        "mitre":    dict(mitre.most_common(10)),
        "hosts":    dict(hosts.most_common(10)),
        "types":    dict(types.most_common(10)),
    })


# -- Tickets -------------------------------------------------------------------

@app.route("/api/tickets")
def api_tickets():
    tickets = _read_jsonl(TICKETS)
    sev    = request.args.get("severity")
    status = request.args.get("status")
    host   = request.args.get("host")
    mitre  = request.args.get("mitre")
    stype  = request.args.get("type")
    if sev:    tickets = [t for t in tickets if t.get("severity") == sev]
    if status: tickets = [t for t in tickets if t.get("status") == status]
    if host:   tickets = [t for t in tickets if t.get("host") == host]
    if mitre:  tickets = [t for t in tickets if t.get("mitre_technique") == mitre]
    if stype:  tickets = [t for t in tickets if _base_label(t.get("signal_type", "")) == stype]
    tickets.sort(key=lambda t: t.get("score", 0), reverse=True)
    return jsonify(tickets)


@app.route("/api/tickets/<tid>", methods=["GET"])
def api_ticket(tid):
    for t in _read_jsonl(TICKETS):
        if t.get("ticket_id") == tid:
            return jsonify(t)
    return jsonify({"error": "not found"}), 404


@app.route("/api/tickets/<tid>", methods=["PATCH"])
def api_ticket_update(tid):
    tickets = _read_jsonl(TICKETS)
    body    = request.get_json(silent=True) or {}
    updated = False
    for t in tickets:
        if t.get("ticket_id") == tid:
            for field in ("status", "assignee", "notes", "disposition"):
                if field in body:
                    t[field] = body[field]
            t["updated_at"] = datetime.now(timezone.utc).isoformat()
            updated = True
            break
    if not updated:
        return jsonify({"error": "not found"}), 404
    _write_tickets(tickets)
    return jsonify({"ok": True})


# -- Signals -------------------------------------------------------------------

@app.route("/api/signals")
def api_signals():
    signals = _read_jsonl(SIGNALS)
    signals.sort(key=lambda s: s.get("score", 0), reverse=True)
    return jsonify(signals)


# -- File browser --------------------------------------------------------------

def _drive_roots() -> List[Dict[str, Any]]:
    out = []
    for letter in string.ascii_uppercase:
        root = f"{letter}:\\"
        if os.path.exists(root):
            out.append({"name": root, "is_dir": True, "size": "", "path": root})
    return out


def _crumbs(target: Path) -> List[Dict[str, str]]:
    crumbs, acc = [], None
    for part in target.parts:
        acc = Path(part) if acc is None else acc / part
        label = part[:-1] if part.endswith("\\") else part
        crumbs.append({"name": label, "path": str(acc)})
    return crumbs


def _parent_of(target: Path) -> Optional[str]:
    parent = target.parent
    if parent == target:                       # filesystem root
        return "" if os.name == "nt" else None  # nt: back to drive list
    return str(parent)


@app.route("/api/browse")
def api_browse():
    raw = request.args.get("path", "")
    try:
        if raw == "":
            if os.name == "nt":
                return jsonify({"path": "", "parent": None, "crumbs": [], "entries": _drive_roots()})
            raw = "/"

        target = Path(raw).resolve()

        if MODE == "server" and not _within_scan_root(target):
            return jsonify({"error": "path outside allowed root"}), 403
        if not target.exists():
            return jsonify({"error": "path not found"}), 404
        if target.is_file():
            return jsonify({"error": "not a directory"}), 400

        entries = []
        for child in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            try:
                is_dir = child.is_dir()
                size = "" if is_dir else _human(child.stat().st_size)
            except (PermissionError, OSError):
                continue
            entries.append({"name": child.name, "is_dir": is_dir, "size": size, "path": str(child)})

        return jsonify({
            "path":    str(target),
            "parent":  _parent_of(target),
            "crumbs":  _crumbs(target),
            "entries": entries,
        })
    except PermissionError:
        return jsonify({"error": "permission denied"}), 403
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# -- Run pipeline (SSE) --------------------------------------------------------

def _sse(text: str) -> str:
    return "data: " + json.dumps(text) + "\n\n"


@app.route("/api/run-stream")
def api_run_stream():
    raw = request.args.get("input", "")
    fmt = request.args.get("format", "auto")
    if fmt not in ALLOWED_FORMATS:
        fmt = "auto"

    target = Path(raw).resolve()
    error = None
    if not raw:
        error = "no input file"
    elif MODE == "server" and not _within_scan_root(target):
        error = "input outside allowed root"
    elif not target.exists():
        error = "input not found: " + str(target)

    if error:
        return Response(_sse("[!] " + error) + _sse("__DONE__"),
                        mimetype="text/event-stream")

    def generate():
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SRC_DIR)
        cmd = [sys.executable, "-m", "ingest.replay",
               "--input", str(target),
               "--out-dir", str(OUT_DIR),
               "--format", fmt]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, env=env, cwd=str(BASE))
        for line in proc.stdout:
            yield _sse(line.rstrip())
        proc.wait()
        yield _sse("__DONE__")

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# -- Index ---------------------------------------------------------------------

@app.route("/")
def index():
    from server.frontend import FRONTEND_HTML
    return FRONTEND_HTML


if __name__ == "__main__":
    print("[soar-server] mode=" + MODE + " at http://localhost:5000")
    threading.Timer(1.2, lambda: webbrowser.open("http://localhost:5000")).start()
    app.run(host="0.0.0.0", port=5000, debug=False)
