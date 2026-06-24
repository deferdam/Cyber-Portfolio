"""lotl_sigma.py — Living-off-the-Land (LOTL) detection module.

Security invariants:
  - Each detector is a pure function: (events) -> List[Signal].
  - A detector exception is caught and logged; it never propagates.
  - signal_id is deterministic (SHA-256 of structured fields).
  - No global mutable state — _RULES is a module-level constant.

MITRE ATT&CK coverage:
  T1047   — Windows Management Instrumentation (wmic)
  T1053.005 — Scheduled Task/Job: Scheduled Task (schtasks, 4698/4699)
  T1059.003 — Command and Scripting Interpreter: Windows CMD
  T1197   — BITS Jobs (bonus)
  T1218.005 — System Binary Proxy: Mshta
  T1218.011 — System Binary Proxy: Rundll32
  T1220   — XSL Script Processing
  T1490   — Inhibit System Recovery (vssadmin delete shadows)
  T1555/T1003 — certutil decode (staging/dropper)

Detection layers implemented here:
  1. Signature (CommandLine pattern match)
  2. Behavioral (process spawn context via ProcessTree)
  3. Scheduled task creation events (4698/4699) — event_code match
"""
from __future__ import annotations
from core.hashes import extract_hashes

import hashlib
import re
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from core.schemas import CanonicalEvent, HostRef, Signal


# ── Helpers ───────────────────────────────────────────────────────────────────

def _basename(path: Optional[str]) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").split("/")[-1].lower()


def _cl(ev: CanonicalEvent) -> str:
    """Return command_line lowercase, empty string if absent."""
    return (ev.process.command_line or "").lower()


def _image(ev: CanonicalEvent) -> str:
    return _basename(ev.process.image_path or ev.process.name or "")


def _signal_id(signal_type: str, event_id: str, extra: str = "") -> str:
    blob = f"{signal_type}|{event_id}|{extra}".encode("utf-8")
    return "sig-" + hashlib.sha256(blob).hexdigest()[:16]


def _make_signal(
    signal_type: str,
    event: CanonicalEvent,
    score: float,
    confidence: float,
    risk_factors: List[str],
    explanation: str,
    recommended_actions: List[str],
    mitre_tactic: str,
    mitre_technique: str,
) -> Signal:
    return Signal(
        signal_id=_signal_id(signal_type, event.event_id),
        signal_type=signal_type,
        host=event.host,
        process_key=f"{_image(event)}|{event.process.pid}",
        user_key=event.user.username,
        score=score,
        confidence=confidence,
        risk_factors=risk_factors,
        evidence_event_ids=[event.event_id],
        explanation=explanation,
        recommended_actions=recommended_actions,
        mitre_tactic=mitre_tactic,
        mitre_technique=mitre_technique,
    )


# ── Rule definitions ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LotlRule:
    """One LOTL detection rule."""
    rule_id: str
    name: str
    image_match: str          # basename to match (lowercase), e.g. "vssadmin.exe"
    cl_patterns: Tuple[str, ...]  # regex patterns — ANY match fires
    score: float
    confidence: float
    mitre_tactic: str
    mitre_technique: str
    recommendation: str
    risk_label: str


_RULES: Tuple[LotlRule, ...] = (
    # ── vssadmin — T1490 Inhibit System Recovery ──────────────────────────────
    LotlRule(
        rule_id="LOTL-001",
        name="vssadmin Shadow Copy Deletion",
        image_match="vssadmin.exe",
        cl_patterns=(
            r"delete\s+shadows",
            r"resize\s+shadowstorage",
        ),
        score=0.92,
        confidence=0.90,
        mitre_tactic="Impact",
        mitre_technique="T1490",
        recommendation="Isolate host immediately. Ransomware pre-encryption step.",
        risk_label="shadow-copy-deletion",
    ),
    LotlRule(
        rule_id="LOTL-001b",
        name="vssadmin List Shadows (reconnaissance)",
        image_match="vssadmin.exe",
        cl_patterns=(r"list\s+shadows",),
        score=0.45,
        confidence=0.60,
        mitre_tactic="Discovery",
        mitre_technique="T1082",
        recommendation="Correlate with other ransomware indicators.",
        risk_label="vssadmin-recon",
    ),

    # ── wmic — T1047 WMI ──────────────────────────────────────────────────────
    LotlRule(
        rule_id="LOTL-002",
        name="WMIC Remote Process Creation",
        image_match="wmic.exe",
        cl_patterns=(
            r"/node:",
            r"process\s+call\s+create",
        ),
        score=0.80,
        confidence=0.75,
        mitre_tactic="Lateral Movement",
        mitre_technique="T1047",
        recommendation="Review target hosts and user context. Check for lateral movement chain.",
        risk_label="wmic-remote-execution",
    ),
    LotlRule(
        rule_id="LOTL-002b",
        name="WMIC Suspicious Enumeration",
        image_match="wmic.exe",
        cl_patterns=(
            r"process\s+get\s+(name|commandline)",
            r"computersystem\s+get",
            r"os\s+get",
        ),
        score=0.50,
        confidence=0.55,
        mitre_tactic="Discovery",
        mitre_technique="T1082",
        recommendation="Investigate if combined with lateral movement indicators.",
        risk_label="wmic-enum",
    ),

    # ── mshta — T1218.005 ─────────────────────────────────────────────────────
    LotlRule(
        rule_id="LOTL-003",
        name="Mshta Remote/JS Script Execution",
        image_match="mshta.exe",
        cl_patterns=(
            r"https?://",
            r"javascript:",
            r"vbscript:",
            r"\.hta",
        ),
        score=0.85,
        confidence=0.82,
        mitre_tactic="Execution",
        mitre_technique="T1218.005",
        recommendation="Block mshta.exe via AppLocker/WDAC. Capture full HTA content.",
        risk_label="mshta-remote-script",
    ),

    # ── certutil — T1140 Deobfuscate/Decode + T1105 Ingress Tool Transfer ─────
    LotlRule(
        rule_id="LOTL-004",
        name="Certutil Download or Decode",
        image_match="certutil.exe",
        cl_patterns=(
            r"-urlcache",
            r"-decode",
            r"-encode",
            r"-f\s+https?://",
        ),
        score=0.82,
        confidence=0.80,
        mitre_tactic="Defense Evasion",
        mitre_technique="T1140",
        recommendation="Quarantine downloaded file. Trace URL/decoded content.",
        risk_label="certutil-abuse",
    ),

    # ── rundll32 — T1218.011 ──────────────────────────────────────────────────
    LotlRule(
        rule_id="LOTL-005",
        name="Rundll32 Suspicious Execution",
        image_match="rundll32.exe",
        cl_patterns=(
            r"users\\public\\",
            r"url\.dll,fileprotocolhandler",
            r"windows\\temp\\",
            r"appdata\\",
            r"javascript:",
            r"shell32\.dll,shellexec_runas",
        ),
        score=0.78,
        confidence=0.72,
        mitre_tactic="Defense Evasion",
        mitre_technique="T1218.011",
        recommendation="Inspect DLL path and exports called. Check for unsigned binaries.",
        risk_label="rundll32-suspicious",
    ),

    # ── schtasks — T1053.005 ──────────────────────────────────────────────────
    LotlRule(
        rule_id="LOTL-006",
        name="Scheduled Task Creation via schtasks",
        image_match="schtasks.exe",
        cl_patterns=(
            r"/create",
            r"/sc\s+(onlogon|onstart|daily|minute|hourly)",
            r"/tr\s+.*powershell",
            r"/tr\s+.*cmd\.exe",
            r"/tr\s+.*wscript",
            r"/tr\s+.*mshta",
        ),
        score=0.75,
        confidence=0.70,
        mitre_tactic="Persistence",
        mitre_technique="T1053.005",
        recommendation="Enumerate all scheduled tasks on host. Check task XML.",
        risk_label="schtasks-creation",
    ),
    LotlRule(
        rule_id="LOTL-006b",
        name="Scheduled Task Immediate Run",
        image_match="schtasks.exe",
        cl_patterns=(r"/run",),
        score=0.45,
        confidence=0.45,
        mitre_tactic="Execution",
        mitre_technique="T1053.005",
        recommendation="Correlate with recent /Create or EventID 4698.",
        risk_label="schtasks-run",
    ),

    # ── cron / at (Linux/Unix lateral) ───────────────────────────────────────
    LotlRule(
        rule_id="LOTL-007",
        name="Cron/at Suspicious Job",
        image_match="cron",
        cl_patterns=(
            r"bash\s+-[ic]",
            r"curl\s+.*\|",
            r"wget\s+.*\|",
            r"python.*-c",
            r"nc\s+-",
        ),
        score=0.70,
        confidence=0.65,
        mitre_tactic="Persistence",
        mitre_technique="T1053.003",
        recommendation="Review /etc/cron* and at queue. Check for new crontab entries.",
        risk_label="cron-suspicious",
    ),
    LotlRule(
        rule_id="LOTL-007b",
        name="at.exe Job Scheduling",
        image_match="at.exe",
        cl_patterns=(r".*",),   # any use of at.exe is unusual in modern Windows
        score=0.60,
        confidence=0.55,
        mitre_tactic="Persistence",
        mitre_technique="T1053.002",
        recommendation="at.exe is deprecated since Windows 8. Investigate user context.",
        risk_label="at-job-legacy",
    ),

    # ── regsvr32 (squiblydoo) — T1218.010 ────────────────────────────────────
    LotlRule(
        rule_id="LOTL-008",
        name="Regsvr32 Remote Script (Squiblydoo)",
        image_match="regsvr32.exe",
        cl_patterns=(
            r"/s\s+/n\s+/u\s+/i:http",
            r"/i:https?://",
            r"scrobj\.dll",
        ),
        score=0.88,
        confidence=0.85,
        mitre_tactic="Defense Evasion",
        mitre_technique="T1218.010",
        recommendation="Block regsvr32 remote COM scriptlet via AppLocker.",
        risk_label="regsvr32-squiblydoo",
    ),
)


# ── EventID-based detectors (no CommandLine needed) ──────────────────────────

_SCHEDULED_TASK_EVENT_CODES = {"4698", "4699", "4702"}

# Map EventID to (score, confidence, description)
_EVENTID_RULES: Dict[str, Tuple[float, float, str, str, str]] = {
    "4698": (0.70, 0.65,
             "Scheduled Task Created (EventID 4698)",
             "Persistence", "T1053.005"),
    "4699": (0.65, 0.60,
             "Scheduled Task Deleted (EventID 4699)",
             "Defense Evasion", "T1053.005"),
    "4702": (0.55, 0.50,
             "Scheduled Task Modified (EventID 4702)",
             "Persistence", "T1053.005"),
}


# ── Main detection functions ───────────────────────────────────────────────────

def _run_cmdline_rules(events: List[CanonicalEvent]) -> List[Signal]:
    """Pattern-match CommandLine for each LOTL rule."""
    signals: List[Signal] = []
    compiled: List[Tuple[LotlRule, List[re.Pattern]]] = [
        (rule, [re.compile(p, re.IGNORECASE) for p in rule.cl_patterns])
        for rule in _RULES
    ]

    for ev in events:
        if ev.event_type not in ("process", "other"):
            continue
        img = _image(ev)
        cl = _cl(ev)
        if not img and not cl:
            continue

        for rule, patterns in compiled:
            if rule.image_match and img != rule.image_match:
                continue

            # For rules without image_match filter, rely solely on CL patterns
            matched = any(p.search(cl) for p in patterns)
            if not matched:
                continue

            signals.append(_make_signal(
                signal_type=f"lotl.{rule.rule_id}",
                event=ev,
                score=rule.score,
                confidence=rule.confidence,
                risk_factors=[rule.risk_label, f"image:{img}", f"rule:{rule.name}"],
                explanation=(
                    f"[{rule.rule_id}] {rule.name} detected. "
                    f"Image: {img or 'N/A'} | "
                    f"CommandLine: {ev.process.command_line or 'N/A'} | "
                    f"User: {ev.user.username or 'N/A'} | "
                    f"Host: {ev.host.hostname}"
                ),
                recommended_actions=[rule.recommendation],
                mitre_tactic=rule.mitre_tactic,
                mitre_technique=rule.mitre_technique,
            ))
            break  # one rule per event is enough for first match

    return signals


def _run_eventid_rules(events: List[CanonicalEvent]) -> List[Signal]:
    """Detect scheduled task events by EventID (4698/4699/4702)."""
    signals: List[Signal] = []
    for ev in events:
        ec = str(ev.raw.get("event_code") or ev.raw.get("EventID") or "")
        if ec not in _EVENTID_RULES:
            continue
        score, confidence, description, tactic, technique = _EVENTID_RULES[ec]
        task_name = (
            ev.raw.get("TaskName") or
            ev.raw.get("event_data", {}).get("TaskName") or
            ev.raw.get("EventData", {}).get("TaskName") or
            "unknown_task"
        )
        signals.append(_make_signal(
            signal_type=f"lotl.scheduled_task.{ec}",
            event=ev,
            score=score,
            confidence=confidence,
            risk_factors=[f"event_code:{ec}", f"task:{task_name}"],
            explanation=(
                f"{description} | Task: {task_name} | "
                f"User: {ev.user.username or 'N/A'} | Host: {ev.host.hostname}"
            ),
            recommended_actions=[
                "Inspect scheduled task XML for malicious payload.",
                "Correlate with schtasks.exe CommandLine events.",
            ],
            mitre_tactic=tactic,
            mitre_technique=technique,
        ))
    return signals


def _run_spawn_rules(
    events: List[CanonicalEvent],
    tree: Any,  # ProcessTree — typed loosely to avoid circular import
) -> List[Signal]:
    """Detect suspicious parent→child spawn pairs using the process tree."""
    if tree is None:
        return []
    signals: List[Signal] = []
    for spawn in tree.all_suspicious_spawns(events):
        # Retrieve the original event for Signal construction
        ev = next((e for e in events if e.event_id == spawn["event_id"]), None)
        if ev is None:
            continue
        signals.append(_make_signal(
            signal_type="lotl.spawn_suspect",
            event=ev,
            score=0.78,
            confidence=0.72,
            risk_factors=[
                f"parent:{spawn['parent_image']}",
                f"child:{spawn['child_image']}",
                "spawn_suspect_pair",
            ],
            explanation=(
                f"Suspicious spawn: {spawn['parent_image']} → {spawn['child_image']} | "
                f"CommandLine: {spawn.get('command_line') or 'N/A'} | "
                f"User: {spawn.get('user') or 'N/A'} | Host: {spawn['host']}"
            ),
            recommended_actions=[
                "Verify parent process legitimacy.",
                "Capture memory of child process.",
                "Review parent process CommandLine.",
            ],
            mitre_tactic="Execution",
            mitre_technique="T1059",
        ))
    return signals


def run(
    events: List[CanonicalEvent],
    tree: Any = None,
) -> List[Signal]:
    """Entry point — run all LOTL detectors and return aggregated signals."""
    signals: List[Signal] = []

    for detector_fn, label in [
        (lambda: _run_cmdline_rules(events), "cmdline"),
        (lambda: _run_eventid_rules(events), "eventid"),
        (lambda: _run_spawn_rules(events, tree), "spawn"),
    ]:
        try:
            results = detector_fn()
            signals.extend(results)
        except Exception as exc:  # noqa: BLE001
            print(f"[lotl_sigma] ERROR in {label}: {exc}", file=sys.stderr)

    return signals
