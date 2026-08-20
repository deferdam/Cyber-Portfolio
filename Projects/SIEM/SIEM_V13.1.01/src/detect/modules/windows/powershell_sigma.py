from __future__ import annotations
from core.hashes import extract_hashes

# timedelta imported but unused - removed
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import re

from core.schemas import CanonicalEvent, Signal
from core.ids import process_key

# -- Constants used by the temporal correlator --------------------------------
_RECON_IDENTITY_SEL = "selection_recon_identity"
_RECON_ENUM_SELS = {"selection_recon_enum"}

try:
    from core.ids import stable_event_id  # type: ignore
except Exception:
    stable_event_id = None  # type: ignore


# -- Data model ----------------------------------------------------------------

@dataclass(frozen=True)
class SimpleSigmaRule:
    """
    Immutable representation of a parsed Sigma rule.

    selections maps each selection block name to a (field, list_of_needles) tuple.
    Matching semantics: ANY needle in the list fires the selection (Sigma OR logic).

    Constraint: one field per selection block. If a block has two fields in the
    real Sigma YAML, the parser will only keep the last one. Document this if
    you extend the YAML.
    """
    title: str
    level: str
    selections: Dict[str, Tuple[str, List[str]]]


# -- File I/O ------------------------------------------------------------------

def _read_text(path: Path) -> str:
    """Read YAML as string. errors='replace' prevents crash on malformed bytes."""
    return path.read_text(encoding="utf-8", errors="replace")


# -- YAML parser ---------------------------------------------------------------

def _parse_simple_sigma_yaml(text: str) -> SimpleSigmaRule:
    """
    Minimal hand-written parser for Sigma YAML.

    Assumptions (hard constraints - will silently fail if violated):
      - Indentation is exactly 4/8/12 spaces (no tabs)
      - detection block is present
      - selection blocks start with "selection"
      - fields use the |contains modifier only

    State machine:
      START -> detection: found -> selection block -> field inline or list header -> list items
    """
    title = ""
    level = "medium"
    selections: Dict[str, Tuple[str, List[str]]] = {}

    in_detection = False
    current_sel: Optional[str] = None
    current_field: Optional[str] = None
    in_list_mode: bool = False

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        if re.match(r"^\s*title:\s*", line):
            title = line.split(":", 1)[1].strip().strip("'\"")
            continue

        if re.match(r"^\s*level:\s*", line):
            level = line.split(":", 1)[1].strip().strip("'\"")
            continue

        if re.match(r"^\s*detection:\s*$", line):
            in_detection = True
            current_sel = None
            current_field = None
            in_list_mode = False
            continue

        if not in_detection:
            continue

        # Selection block header - 4 spaces: "    selection_foo:"
        m_sel = re.match(r"^\s{4}([A-Za-z0-9_\-]+):\s*$", line)
        if m_sel:
            name = m_sel.group(1)
            current_sel = name if name.startswith("selection") else None
            current_field = None
            in_list_mode = False
            continue

        if not current_sel:
            continue

        # Field with inline single value - 8 spaces: "        Field|contains: 'value'"
        # Note: \s+ requires at least one char after colon, so raw_val is never empty here.
        # The dead branch (raw_val == "") has been removed.
        m_kv_inline = re.match(r"^\s{8}([A-Za-z0-9_]+)\|contains:\s+(.+)\s*$", line)
        if m_kv_inline:
            field = m_kv_inline.group(1).strip()
            needle = m_kv_inline.group(2).strip().strip("'\"")
            current_field = field
            in_list_mode = False
            selections[current_sel] = (field, [needle])
            continue

        # Field with no inline value - list follows on next lines: "        Field|contains:"
        m_kv_list_header = re.match(r"^\s{8}([A-Za-z0-9_]+)\|contains:\s*$", line)
        if m_kv_list_header:
            field = m_kv_list_header.group(1).strip()
            current_field = field
            in_list_mode = True
            selections[current_sel] = (field, [])
            continue

        # List item - 12 spaces: "            - 'value'"
        if in_list_mode and current_field:
            m_item = re.match(r"^\s{12}-\s+(.+)\s*$", line)
            if m_item:
                needle = m_item.group(1).strip().strip("'\"")
                sel_field, needles = selections.get(current_sel, (current_field, []))
                selections[current_sel] = (sel_field, needles + [needle])
                continue
            else:
                # Any non-list line exits list mode
                in_list_mode = False
                current_field = None

    if not selections:
        # Warn loudly: likely an indentation mismatch in the YAML
        import warnings
        warnings.warn(
            f"_parse_simple_sigma_yaml: no selections parsed from rule '{title or 'unknown'}'. "
            "Check YAML indentation (must be 4/8/12 spaces, no tabs).",
            RuntimeWarning,
            stacklevel=2,
        )

    if not title:
        title = "Suspicious PowerShell Script Block"

    return SimpleSigmaRule(title=title, level=level, selections=selections)


# -- Event filtering -----------------------------------------------------------

def _is_powershell_4104(ev: CanonicalEvent) -> bool:
    """
    Returns True if the event is a PowerShell Script Block Logging event (ID 4104).

    Three fallback paths handle different ingestion key naming conventions.
    Risk: if eid is malformed (e.g. "4104.0"), int() raises and the event is
    silently dropped. Acceptable for V1 - add a warning log if this causes issues.
    """
    raw = ev.raw or {}
    eid = raw.get("EventID") or raw.get("event_id") or raw.get("eventid") or raw.get("id")
    try:
        if eid is not None and int(eid) == 4104:
            return True
    except Exception:
        pass

    if (ev.event_type or "").lower() == "powershell" and str(eid) == "4104":
        return True

    if "powershell" in (ev.source or "").lower() and str(eid) == "4104":
        return True

    return False


# -- Field extraction ----------------------------------------------------------

def _get_field(ev: CanonicalEvent, field: str) -> str:
    """
    Map a Sigma field name to actual data in CanonicalEvent.

    Handles case variation for known fields (ScriptBlockText, CommandLine).
    Generic fallback uses raw.get(field) which is case-sensitive - known risk.
    """
    raw = ev.raw or {}
    f = field.lower()

    if f == "scriptblocktext":
        return str(
            raw.get("ScriptBlockText")
            or raw.get("script_block_text")
            or raw.get("scriptblocktext")
            or ""
        )

    if f == "commandline":
        cmd = getattr(ev.process, "command_line", None)
        if cmd:
            return str(cmd)
        return str(raw.get("CommandLine") or raw.get("command_line") or "")

    v = raw.get(field)
    return "" if v is None else str(v)


# -- Signal ID -----------------------------------------------------------------

def _make_signal_id(ev: CanonicalEvent, rule_title: str, matched: List[str]) -> str:
    """
    Deterministic signal ID.
    sorted(matched) ensures ["sel_a","sel_b"] and ["sel_b","sel_a"] produce
    the same ID - prevents duplicate signals on reprocessing.
    """
    if stable_event_id is not None:
        payload = {
            "kind": "signal",
            "type": "powershell_sigma",
            "rule": rule_title,
            "event_id": ev.event_id,
            "matched": ",".join(sorted(matched)),
            "host": ev.host.hostname,
        }
        return stable_event_id(payload)  # type: ignore[misc]
    return f"sig|powershell_sigma|{ev.event_id}|{','.join(sorted(matched))}"



# -- Temporal correlator -------------------------------------------------------

def correlate_recon_sequence(
    events: List[CanonicalEvent],
    existing_signals: List[Signal],
    window_seconds: int = 300,
) -> List[Signal]:
    """
    SIEM-level temporal correlator. Not a Sigma rule.

    Emits a 'recon_sequence' Signal when ALL of these are true:
      1. Signal A on host H matched selection_recon_identity (whoami-type)
      2. Signal B on the SAME host H matched selection_recon_enum (net user, etc.)
      3. |timestamp_A - timestamp_B| <= window_seconds (default: 5 minutes)

    Must be called AFTER run() by the SIEM orchestrator:
        signals = run(events, rule_path)
        correlated = correlate_recon_sequence(events, signals)
        all_signals = signals + correlated

    Design notes:
      - emitted_pairs prevents duplicate correlation signals in O(n2) loop
      - Detection relies on risk_factors string matching. If run() changes its
        risk_factor format, this correlator silently breaks. Mitigation: add a
        matched_selections field to Signal in a future schema version.
    """
    # Group powershell_sigma signals by host
    host_signals: Dict[str, List[Signal]] = defaultdict(list)
    for sig in existing_signals:
        if sig.signal_type == "powershell_sigma":
            host_signals[sig.host.hostname].append(sig)

    correlated: List[Signal] = []
    emitted_pairs: set = set()

    for hostname, sigs in host_signals.items():
        identity_sigs = [
            s for s in sigs
            if any(_RECON_IDENTITY_SEL in rf for rf in s.risk_factors)
        ]
        enum_sigs = [
            s for s in sigs
            if any(sel in rf for rf in s.risk_factors for sel in _RECON_ENUM_SELS)
        ]

        for id_sig in identity_sigs:
            for en_sig in enum_sigs:
                if id_sig.signal_id == en_sig.signal_id:
                    continue

                # Resolve source events to get timestamps
                id_ev = next(
                    (e for e in events if e.event_id in id_sig.evidence_event_ids), None
                )
                en_ev = next(
                    (e for e in events if e.event_id in en_sig.evidence_event_ids), None
                )

                if id_ev is None or en_ev is None:
                    continue

                # event_time_utc is typed as datetime in CanonicalEvent (schemas.py)
                # Required field - cannot be None by schema contract.
                delta = abs(
                    (id_ev.event_time_utc - en_ev.event_time_utc).total_seconds()
                )
                if delta > window_seconds:
                    continue

                pair_key = tuple(sorted([id_sig.signal_id, en_sig.signal_id]))
                if pair_key in emitted_pairs:
                    continue
                emitted_pairs.add(pair_key)

                all_event_ids = list(
                    dict.fromkeys(id_sig.evidence_event_ids + en_sig.evidence_event_ids)
                )

                corr_payload = {
                    "kind": "signal",
                    "type": "recon_sequence",
                    "host": hostname,
                    "id_sig": id_sig.signal_id,
                    "en_sig": en_sig.signal_id,
                }
                corr_id = (
                    stable_event_id(corr_payload)
                    if stable_event_id is not None
                    else f"sig|recon_seq|{id_sig.signal_id}|{en_sig.signal_id}"
                )

                correlated.append(
                    Signal(
                        signal_id=corr_id,
                        signal_type="recon_sequence",
                        host=id_sig.host,
                        process_key=id_sig.process_key,
                        score=min(1.0, max(id_sig.score, en_sig.score) + 0.2),
                        confidence=min(1.0, (id_sig.confidence + en_sig.confidence) / 2 + 0.15),
                        risk_factors=[
                            "Identity enumeration followed by account enumeration",
                            f"Time delta: {int(delta)}s (threshold: {window_seconds}s)",
                            f"Identity signal: {id_sig.signal_id}",
                            f"Enum signal: {en_sig.signal_id}",
                        ],
                        evidence_event_ids=all_event_ids,
                        explanation=(
                            f"Recon sequence detected on {hostname}: "
                            f"whoami-type command followed by account enumeration "
                            f"within {int(delta)}s."
                        ),
                        recommended_actions=[
                            "Investigate the process tree for both events.",
                            "Check for lateral movement or privilege escalation within +/-15 min.",
                            "Determine if this host is part of a known pentest scope.",
                        ],
                    )
                )

    return correlated


# -- Main entry point ----------------------------------------------------------

def run(events: List[CanonicalEvent], rule_paths: Optional[List[str]] = None) -> List[Signal]:
    """
    Match PowerShell 4104 events against one or more Sigma YAML files.

    rule_paths: list of YAML file paths to load. Defaults to powershell_suspicious.yaml.
    Missing files emit a warning and are skipped - the pipeline never stops on a missing file.

    Returns aggregated Signals from all loaded rules.
    Does NOT run temporal correlation - call correlate_recon_sequence() separately.

    Scoring: base 0.6 + 0.1 per matched selection, capped at 1.0.
    """
    import warnings
    if rule_paths is None:
        rule_paths = ["powershell_suspicious.yaml"]

    signals: List[Signal] = []  # accumulates across ALL files

    for rule_path in rule_paths:
        path = Path(rule_path)
        if not path.exists():
            warnings.warn(f"Sigma rule file not found: {rule_path}", RuntimeWarning, stacklevel=2)
            continue  # skip this file, keep going

        rule = _parse_simple_sigma_yaml(_read_text(path))

        for ev in events:
            if not _is_powershell_4104(ev):
                continue

            matched: List[str] = []
            for sel_name, (field, needles) in rule.selections.items():
                text = _get_field(ev, field)
                if text and any(needle in text for needle in needles):
                    matched.append(sel_name)

            if not matched:
                continue

            pname = getattr(ev.process, "name", None)
            pid   = getattr(ev.process, "pid", None)
            ppath = getattr(ev.process, "image_path", None) or getattr(ev.process, "path", None)
            pk = process_key(pname, pid, ppath)

            signal_id  = _make_signal_id(ev, rule.title, matched)
            confidence = min(1.0, 0.6 + 0.1 * len(matched))
            score      = confidence

            signals.append(Signal(
                signal_id=signal_id,
                signal_type="powershell_sigma",
                host=ev.host,
                process_key=pk,
                score=score,
                confidence=confidence,
                risk_factors=[f"Matched {m}" for m in matched],
                evidence_event_ids=[ev.event_id],
                file_hashes=extract_hashes(ev),
                explanation=f"PowerShell 4104 matched '{rule.title}' via {', '.join(matched)}",
                recommended_actions=[
                    "Inspect ScriptBlockText and decode if EncodedCommand is present.",
                    "Correlate with the parent process and network or file activity within 10 minutes.",
                    "Verify whether this is a known legitimate admin script.",
                ],
            ))

    return signals