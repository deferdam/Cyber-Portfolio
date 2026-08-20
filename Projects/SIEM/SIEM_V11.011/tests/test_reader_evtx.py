"""Tests for the EVTX ingestion reader."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ingest.evtx_reader import read as evtx_read, _parse_record, _HAVE_EVTX
from normalize.normalizer import normalize

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [ok]   {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}")


# Unit test of the XML mapping, independent of the python-evtx library.
sample_4688 = (
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    '<System><Provider Name="Microsoft-Windows-Security-Auditing"></Provider>'
    '<EventID>4688</EventID><TimeCreated SystemTime="2026-01-01T00:00:00.0Z"></TimeCreated>'
    '<Computer>WS-01</Computer></System>'
    '<EventData><Data Name="NewProcessId">0x1a4</Data>'
    '<Data Name="ProcessId">0x100</Data>'
    '<Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>'
    '<Data Name="CommandLine">cmd.exe /c whoami</Data>'
    '<Data Name="SubjectUserName">alice</Data></EventData></Event>'
)
rec = _parse_record(sample_4688)
check("4688 maps to event_type process", rec["event_type"] == "process")
check("NewProcessId hex converted to int", rec["pid"] == 0x1a4)
check("ProcessId hex maps to ppid", rec["ppid"] == 0x100)
check("image and command_line extracted", rec["process_path"].endswith("cmd.exe") and "whoami" in rec["command_line"])
check("Computer maps to host", rec["host"] == "WS-01")
check("source tagged evtx", rec["source"] == "evtx")

sample_4624 = (
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    '<System><EventID>4624</EventID><Computer>WS-01</Computer></System>'
    '<EventData><Data Name="TargetUserName">bob</Data>'
    '<Data Name="IpAddress">10.0.0.5</Data></EventData></Event>'
)
rec2 = _parse_record(sample_4624)
check("4624 maps to event_type auth", rec2["event_type"] == "auth")
check("logon username and ip extracted", rec2["username"] == "bob" and rec2["dest_ip"] == "10.0.0.5")

# Integration against the real sample file (requires python-evtx).
if _HAVE_EVTX:
    SAMPLE = ROOT / "samples" / "demo_windows.evtx"
    raw = list(evtx_read(str(SAMPLE)))
    check("parses the real evtx sample (many records)", len(raw) > 100)
    check("every record tagged source=evtx", all(r["source"] == "evtx" for r in raw))
    check("EventID extracted on every record", all(r.get("EventID") for r in raw))
    events = [normalize(r) for r in raw]
    check("all records normalize without error", len(events) == len(raw))
    check("event ids are unique enough", len({e.event_id for e in events}) > 100)
else:
    print("  [skip] python-evtx not installed; integration checks skipped")

print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)
