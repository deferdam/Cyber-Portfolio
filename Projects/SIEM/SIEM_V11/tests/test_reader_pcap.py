"""Tests for the PCAP ingestion reader and the suspicious-connection detector."""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ingest.pcap_reader import read as pcap_read, _HAVE_DPKT
from normalize.normalizer import normalize
from detect.engine import run_all
from detect.modules.imported import net_suspect

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


if not _HAVE_DPKT:
    print("  [skip] dpkt not installed; pcap checks skipped")
    print(f"\n{'=' * 60}")
    print(f"  Results: {PASS} passed, {FAIL} failed")
    sys.exit(0)

SAMPLE = ROOT / "samples" / "demo_capture.pcap"
raw = list(pcap_read(str(SAMPLE)))

check("parses 3 packets", len(raw) == 3)
check("every record tagged source=pcap", all(r["source"] == "pcap" for r in raw))
check("event_type is network", all(r["event_type"] == "network" for r in raw))
check("dest ports extracted", {r["dest_port"] for r in raw} == {4444, 443, 1337})
check("ips extracted", any(r.get("dest_ip") == "10.10.10.9" for r in raw))
check("protocol is TCP", all(r["protocol"] == "TCP" for r in raw))

events = [normalize(r) for r in raw]
check("normalizer produces 3 events", len(events) == 3)

sigs = net_suspect.run(events)
check("flags the two offensive ports (4444, 1337)", len(sigs) == 2)
check("does not flag benign port 443",
      all("443" not in s.explanation for s in sigs))
check("all signals are pcap.suspect_conn", all(s.signal_type == "pcap.suspect_conn" for s in sigs))

end = run_all(events)
check("engine routes pcap events through net_suspect",
      len([s for s in end if s.signal_type == "pcap.suspect_conn"]) == 2)

# Robustness: a non-pcap file raises a clear error, not a crash.
with tempfile.TemporaryDirectory() as d:
    junk = Path(d) / "junk.pcap"
    junk.write_text("this is not a pcap")
    try:
        list(pcap_read(str(junk)))
        check("invalid pcap raises a clear error", False)
    except RuntimeError:
        check("invalid pcap raises a clear error", True)

print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)
