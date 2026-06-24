"""test_v75.py — Tests for IMAP/POP3 live email ingestion (v7.5).

Uses unittest.mock to simulate IMAP and POP3 servers without network access.

Run:
    cd SIEM_V75
    export PYTHONPATH=src
    python tests/test_v75.py
"""
from __future__ import annotations

import sys, os, json, textwrap, tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC  = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path: sys.path.insert(0, _SRC)

PASS = 0; FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {name}")
    else:    FAIL += 1; print(f"  FAIL  {name}" + (f" - {detail}" if detail else ""))


# ── Shared: a minimal valid .eml as bytes ────────────────────────────────────
EML_BYTES = textwrap.dedent("""
From: attacker@evil.com
To: siem@corp.com
Subject: Urgent Invoice
Date: Mon, 17 Mar 2026 12:00:00 +0000
Received-SPF: fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="B"

--B
Content-Type: text/plain

See attached.

--B
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="payload.exe"
Content-Transfer-Encoding: base64

TVqQ==
--B--
""").strip().encode()


print("\n-- 1. parse_eml_bytes (refactor check) --")
from ingest.email_parser import parse_eml, parse_eml_bytes

events_from_bytes = parse_eml_bytes(EML_BYTES)
check("parse_eml_bytes returns events",    len(events_from_bytes) >= 2)
check("attachment event present",          any(e.event_type=="file" for e in events_from_bytes))
check("header event present",              any(e.event_type=="auth" for e in events_from_bytes))

import tempfile
with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as f:
    f.write(EML_BYTES); tmp = f.name
events_from_file = parse_eml(tmp)
os.unlink(tmp)
check("parse_eml still works (wrapper)",  len(events_from_file) >= 2)
check("bytes and file produce same count", len(events_from_bytes) == len(events_from_file))


print("\n-- 2. IMAPClient: fetch and parse --")
from ingest.imap_client import IMAPClient

IMAP_CFG = {
    "name": "test-imap", "host": "imap.test.com", "port": 993,
    "ssl": True, "username": "u@test.com",
    "password": "secret", "mailbox": "INBOX", "mark_seen": False,
}

with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
    seen_path = f.name
os.unlink(seen_path)

with patch("imaplib.IMAP4_SSL") as mock_ssl:
    mock_conn = MagicMock()
    mock_ssl.return_value = mock_conn

    # Setup mock responses
    mock_conn.search.return_value = ("OK", [b"1 2"])
    mock_conn.fetch.side_effect = [
        ("OK", [(b"1 (RFC822 {100})", EML_BYTES)]),
        ("OK", [(b"2 (RFC822 {100})", EML_BYTES)]),
    ]

    client = IMAPClient(IMAP_CFG, seen_path=seen_path)
    client.connect()
    check("IMAP4_SSL called with host+port", mock_ssl.called)
    check("login called",                    mock_conn.login.called)

    all_events = []
    for evs in client.fetch_new():
        all_events.extend(evs)
    client.disconnect()

check("IMAP: events fetched from 2 messages", len(all_events) >= 4)

# Check seen IDs persisted
check("seen_ids saved",     os.path.exists(seen_path))
seen_data = json.loads(open(seen_path).read()) if os.path.exists(seen_path) else []
check("2 msg IDs recorded", len(seen_data) == 2)

# Re-fetch: same IDs should be skipped
with patch("imaplib.IMAP4_SSL") as mock_ssl2:
    mock_conn2 = MagicMock()
    mock_ssl2.return_value = mock_conn2
    mock_conn2.search.return_value = ("OK", [b"1 2"])
    mock_conn2.fetch.return_value = ("OK", [(b"1 (RFC822 {100})", EML_BYTES)])

    client2 = IMAPClient(IMAP_CFG, seen_path=seen_path)
    client2.connect()
    second_events = []
    for evs in client2.fetch_new():
        second_events.extend(evs)
    client2.disconnect()

check("Already-seen IDs not reprocessed", len(second_events) == 0)
os.unlink(seen_path)


print("\n-- 3. POP3Client: fetch and parse --")
from ingest.pop3_client import POP3Client

POP_CFG = {
    "name": "test-pop3", "host": "pop.test.com", "port": 995,
    "ssl": True, "username": "u@test.com", "password": "secret",
}

with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
    seen_pop = f.name
os.unlink(seen_pop)

with patch("poplib.POP3_SSL") as mock_pop:
    mock_pconn = MagicMock()
    mock_pop.return_value = mock_pconn

    # list() returns (response, [b"1 500"], octets)
    mock_pconn.list.return_value = (b"+OK", [b"1 500"], 10)
    # uidl() returns (response, [b"1 ABCDEF123"], octets)
    mock_pconn.uidl.return_value  = (b"+OK", [b"1 ABCDEF123"], 10)
    # retr() returns (response, [lines...], octets)
    mock_pconn.retr.return_value  = (b"+OK", EML_BYTES.split(b"\n"), len(EML_BYTES))

    client_pop = POP3Client(POP_CFG, seen_path=seen_pop)
    client_pop.connect()
    check("POP3_SSL called",  mock_pop.called)
    check("user() called",    mock_pconn.user.called)
    check("pass_() called",   mock_pconn.pass_.called)

    pop_events = []
    for evs in client_pop.fetch_new():
        pop_events.extend(evs)
    client_pop.disconnect()

check("POP3: events fetched",         len(pop_events) >= 2)
seen_pop_data = json.loads(open(seen_pop).read()) if os.path.exists(seen_pop) else []
check("POP3 UID persisted (UIDL)",    "ABCDEF123" in seen_pop_data)

# Re-fetch: skip same UID
with patch("poplib.POP3_SSL") as mock_pop2:
    mock_pconn2 = MagicMock()
    mock_pop2.return_value = mock_pconn2
    mock_pconn2.list.return_value  = (b"+OK", [b"1 500"], 10)
    mock_pconn2.uidl.return_value  = (b"+OK", [b"1 ABCDEF123"], 10)
    mock_pconn2.retr.return_value  = (b"+OK", EML_BYTES.split(b"\n"), len(EML_BYTES))

    client_pop2 = POP3Client(POP_CFG, seen_path=seen_pop)
    client_pop2.connect()
    second_pop = []
    for evs in client_pop2.fetch_new():
        second_pop.extend(evs)
    client_pop2.disconnect()

check("POP3: already-seen UID skipped", len(second_pop) == 0)
os.unlink(seen_pop)


print("\n-- 4. Password resolution --")
from ingest.imap_client import IMAPClient as _IC
cfg_env = {**IMAP_CFG}
del cfg_env["password"]
cfg_env["password_env"] = "MY_TEST_IMAP_PWD"

os.environ["MY_TEST_IMAP_PWD"] = "from_env_var"
with patch("imaplib.IMAP4_SSL") as mock_env:
    mock_env.return_value = MagicMock()
    mock_env.return_value.search.return_value = ("OK", [b""])
    c = _IC(cfg_env, seen_path="/tmp/seen_test.json")
    check("password read from env var", c.password == "from_env_var")
del os.environ["MY_TEST_IMAP_PWD"]
if os.path.exists("/tmp/seen_test.json"): os.unlink("/tmp/seen_test.json")

try:
    c2 = _IC({**cfg_env, "password_env": "NONEXISTENT_VAR_XYZ"})
    check("missing env var raises ValueError", False)
except ValueError:
    check("missing env var raises ValueError", True)


print("\n-- 5. EmailPoller.run_once integration --")
from ingest.email_poller import EmailPoller

poller_cfg = {
    "poll_interval_seconds": 60,
    "output_path": "/tmp/test_email_alerts.jsonl",
    "seen_ids_dir": "/tmp",
    "accounts": [{
        "name": "test-poll", "protocol": "imap",
        "host": "imap.test.com", "port": 993, "ssl": True,
        "username": "u@test.com", "password": "secret",
        "mailbox": "INBOX", "mark_seen": False,
    }]
}

with patch("imaplib.IMAP4_SSL") as mock_poll:
    mc = MagicMock()
    mock_poll.return_value = mc
    mc.search.return_value = ("OK", [b"1"])
    mc.fetch.return_value  = ("OK", [(b"1 (RFC822 {100})", EML_BYTES)])

    poller = EmailPoller(poller_cfg)
    sigs   = poller.run_once()
    check("poller returns signals",    len(sigs) > 0)
    check("output file written",       os.path.exists("/tmp/test_email_alerts.jsonl"))

    if os.path.exists("/tmp/test_email_alerts.jsonl"):
        lines = open("/tmp/test_email_alerts.jsonl").readlines()
        check("JSONL has signal rows",     len(lines) > 0)
        row = json.loads(lines[0])
        check("file_hashes in JSONL row",  "file_hashes" in row)
        check("signal_type in JSONL row",  "signal_type" in row)
        os.unlink("/tmp/test_email_alerts.jsonl")

seen_poll = f"/tmp/seen_test-poll.json"
if os.path.exists(seen_poll): os.unlink(seen_poll)


print(f"\n{'='*60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL: sys.exit(1)
