"""test_process_context.py - enriched process ancestry attached to signals.

Run:
    cd SIEM_V8
    export PYTHONPATH=src
    python tests/test_process_context.py
"""
from __future__ import annotations

import sys, os
from dataclasses import replace
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC  = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from core.schemas import CanonicalEvent, ProcessRef, HostRef, Signal
from normalize.process_tree import build_tree
from detect.engine import _attach_process_context

PASS = 0; FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {name}")
    else:    FAIL += 1; print(f"  FAIL  {name}" + (f" - {detail}" if detail else ""))

_NOW = datetime.now(timezone.utc)

def mk(eid, pid, ppid, image, cmd):
    return CanonicalEvent(
        event_id=eid, event_time_utc=_NOW, ingest_time_utc=_NOW,
        source="sysmon_like", event_type="process",
        host=HostRef(hostname="host01"),
        process=ProcessRef(name=image, image_path="C:/Windows/" + image,
                           pid=pid, ppid=ppid, command_line=cmd),
    )

# winword(100) -> powershell(200) -> cmd(300); powershell also spawns whoami(201)
events = [
    mk("e1", 100, 1,   "winword.exe",    "winword.exe /n"),
    mk("e2", 200, 100, "powershell.exe", "powershell -enc ABCD"),
    mk("e3", 300, 200, "cmd.exe",        "cmd /c whoami"),
    mk("e4", 201, 200, "whoami.exe",     "whoami /all"),
]
tree = build_tree(events)

# -- tree-level enriched queries --
anc = tree.ancestor_nodes("host01", 300)
chi = tree.child_nodes("host01", 200)
check("ancestor chain is root-first",
      [a["image"] for a in anc] == ["winword.exe", "powershell.exe"])
check("ancestor nodes carry pid/cmd/event_id",
      all(all(k in a for k in ("image", "pid", "ppid", "command_line", "event_id", "host")) for a in anc))
check("direct children resolved by pid",
      sorted(c["image"] for c in chi) == ["cmd.exe", "whoami.exe"])
check("missing pid returns empty chain", tree.ancestor_nodes("host01", 999) == [])
check("cross-host isolation", tree.ancestor_nodes("other-host", 300) == [])

# -- engine attach on a frozen Signal via replace --
sig = Signal(signal_id="s1", signal_type="powershell_sigma",
             host=HostRef(hostname="host01"), evidence_event_ids=["e3"])
out = _attach_process_context([sig], events, tree)
check("attach returns same count", len(out) == 1)
check("frozen signal enriched without mutation", sig.process_ancestors == [])
check("enriched signal has ancestors",
      [a["image"] for a in out[0].process_ancestors] == ["winword.exe", "powershell.exe"])
check("enriched signal serializes new fields",
      "process_ancestors" in out[0].to_dict() and "process_children" in out[0].to_dict())

# -- non-process / no-tree safety --
sig_noev = Signal(signal_id="s2", signal_type="email_phishing",
                  host=HostRef(hostname="host01"), evidence_event_ids=["zzz"])
out2 = _attach_process_context([sig_noev], events, tree)
check("signal with unknown event stays empty", out2[0].process_ancestors == [])
check("no tree returns input unchanged",
      _attach_process_context([sig], events, None)[0] is sig)

print(f"\n{'='*60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)
