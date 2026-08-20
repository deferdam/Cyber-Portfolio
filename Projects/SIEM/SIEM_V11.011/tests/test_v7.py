"""test_v7.py — v7 tests: hash propagation, email parsing, email detection.

Run:
    cd SIEM_V7
    export PYTHONPATH=src
    python tests/test_v7.py
"""
from __future__ import annotations
import sys, os, hashlib, tempfile, textwrap
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC  = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path: sys.path.insert(0, _SRC)

from core.schemas import CanonicalEvent, HostRef, UserRef, ProcessRef, FileRef, NetworkRef
from core.hashes import extract_hashes

PASS = 0; FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {name}")
    else:    FAIL += 1; print(f"  FAIL  {name}" + (f" - {detail}" if detail else ""))

def _ev(raw_extra=None, fp="", op=""):
    ts = datetime(2026,3,17,12,0,0,tzinfo=timezone.utc)
    raw = {"timestamp": ts.isoformat(), "source": "sysmon", "host": "h1",
           **(raw_extra or {})}
    return CanonicalEvent(
        event_id="t1", event_time_utc=ts, ingest_time_utc=ts,
        source="sysmon", event_type="process", host=HostRef(hostname="h1"),
        user=UserRef(username="user"),
        process=ProcessRef(name="test", pid=1, command_line="test"),
        file=FileRef(path=fp or None, operation=op or None),
        network=NetworkRef(), raw=raw)


print("\n-- 1. extract_hashes --")
ev_sysmon = _ev({"Hashes": "SHA256=abc123,MD5=def456,IMPHASH=ghi789"})
h = extract_hashes(ev_sysmon)
check("sysmon SHA256 parsed",  h.get("sha256") == "abc123")
check("sysmon MD5 parsed",     h.get("md5") == "def456")
check("sysmon IMPHASH parsed", h.get("imphash") == "ghi789")

ev_raw = _ev({"sha256": "deadbeef", "md5": "cafebabe"})
h2 = extract_hashes(ev_raw)
check("raw sha256 field", h2.get("sha256") == "deadbeef")
check("raw md5 field",    h2.get("md5") == "cafebabe")

ev_empty = _ev()
check("empty event -> empty dict", extract_hashes(ev_empty) == {})


print("\n-- 2. Signal file_hashes field --")
from core.schemas import Signal
sig = Signal(
    signal_id="s1", signal_type="test", host=HostRef(hostname="h1"),
    score=0.8, confidence=0.8,
    file_hashes={"sha256": "abc", "md5": "def"},
    evidence_event_ids=["e1"],
)
check("Signal carries file_hashes", sig.file_hashes == {"sha256": "abc", "md5": "def"})
check("Signal None file_hashes OK", Signal(signal_id="s2", signal_type="t",
    host=HostRef(hostname="h"), score=0.5, confidence=0.5).file_hashes is None)


print("\n-- 3. deduplicator merges file_hashes --")
from detect.deduplicator import merge
s1 = Signal(signal_id="d1", signal_type="a", host=HostRef(hostname="h"),
    score=0.7, confidence=0.7, evidence_event_ids=["ev-X"],
    file_hashes={"sha256": "abc123"})
s2 = Signal(signal_id="d2", signal_type="b", host=HostRef(hostname="h"),
    score=0.8, confidence=0.8, evidence_event_ids=["ev-X"],
    file_hashes={"md5": "def456"})
merged = merge([s1, s2])
check("2 signals merged", len(merged) == 1)
check("sha256 in merged", merged[0].file_hashes.get("sha256") == "abc123")
check("md5 in merged",    merged[0].file_hashes.get("md5") == "def456")


print("\n-- 4. email_parser --")
from ingest.email_parser import parse_eml

RISKY_EML = textwrap.dedent("""
From: attacker@evil.com
To: victim@corp.com
Subject: Invoice Q2
Date: Mon, 17 Mar 2026 12:00:00 +0000
Received-SPF: fail (domain of evil.com does not designate 1.2.3.4 as permitted sender)
DKIM-Signature:
Authentication-Results: mx.corp.com; dmarc=fail
Return-Path: bounce@different-evil.com
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain

Please find attached our invoice. Click http://bit.ly/abc123 for details.
Also see http://192.168.1.1/malware.exe

--BOUNDARY
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--BOUNDARY--
""").strip()

with tempfile.NamedTemporaryFile(suffix=".eml", mode="w", delete=False) as f:
    f.write(RISKY_EML)
    eml_path = f.name

events = parse_eml(eml_path)
os.unlink(eml_path)
check("parse_eml returns events",    len(events) >= 2)
attach_evs = [e for e in events if e.event_type == "file"]
header_evs = [e for e in events if e.event_type == "auth"]
check("attachment event created",    len(attach_evs) == 1)
check("header event created",        len(header_evs) == 1)
check("attachment filename correct", attach_evs[0].file.path == "invoice.exe")
check("sha256 computed",             extract_hashes(attach_evs[0]).get("sha256") is not None)
check("md5 computed",                extract_hashes(attach_evs[0]).get("md5") is not None)
check("SPF fail in header event",    "fail" in (header_evs[0].raw.get("received_spf","")).lower())
check("body_text captured",          "bit.ly" in (header_evs[0].raw.get("body_text","")))


print("\n-- 5. email_attachments detector --")
from detect.modules.email.email_attachments import run as attach_run
sigs = attach_run(events)
check("risky .exe attachment detected",
      any(s.signal_type == "email.risky_attachment" for s in sigs))
s = next((s for s in sigs if s.signal_type == "email.risky_attachment"), None)
check("file_hashes in attachment signal", bool(s and s.file_hashes))
check("sha256 in attachment signal hash", bool(s and s.file_hashes.get("sha256")))
check("MITRE T1566.001",               s and s.mitre_technique == "T1566.001")
check("score 0.75",                    s and s.score == 0.75)

benign_evs = [e for e in events if e.source == "email"]
# Replace extension with benign
import copy
from core.schemas import FileRef
benign_raw = {**attach_evs[0].raw, "attachment_name": "document.pdf"}
benign = CanonicalEvent(
    event_id="benign1", event_time_utc=attach_evs[0].event_time_utc,
    ingest_time_utc=attach_evs[0].ingest_time_utc,
    source="email", event_type="file", host=attach_evs[0].host,
    user=attach_evs[0].user, process=attach_evs[0].process,
    file=FileRef(path="document.pdf", operation="received", extension="pdf", directory=""),
    network=attach_evs[0].network, raw=benign_raw)
check(".pdf no signal", attach_run([benign]) == [])


print("\n-- 6. email_phishing detector --")
from detect.modules.email.email_phishing import run as phish_run
sigs_p = phish_run(events)
types_p = [s.signal_type for s in sigs_p]
check("suspicious headers signal",  "email.suspicious_headers" in types_p)
check("suspicious links signal",    "email.suspicious_links" in types_p)
header_sig = next((s for s in sigs_p if s.signal_type == "email.suspicious_headers"), None)
check("SPF fail in risk_factors",
      header_sig and any("spf" in f for f in header_sig.risk_factors))
check("DKIM missing in risk_factors",
      header_sig and any("dkim" in f for f in header_sig.risk_factors))
check("From/ReturnPath mismatch detected",
      header_sig and any("mismatch" in f for f in header_sig.risk_factors))
link_sig = next((s for s in sigs_p if s.signal_type == "email.suspicious_links"), None)
check("URL shortener detected",
      link_sig and any("shortener" in f for f in link_sig.risk_factors))
check("IP URL detected",
      link_sig and any("ip_based" in f for f in link_sig.risk_factors))

# Non-email event ignored
non_email = _ev({"source":"auditd"})
non_email = type(non_email)(**{**non_email.__dict__, "source":"auditd"})
check("non-email event ignored", phish_run([non_email]) == [])


print(f"\n{'='*60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL: sys.exit(1)
