"""Tests for the encryption-at-rest vault (v10 security foundation)."""
import importlib
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

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


def _fresh_vault():
    import core.vault as v
    importlib.reload(v)
    return v


# --- encryption OFF: plaintext, backward compatible ---
for k in ("SIEM_ENCRYPT", "SIEM_KEY", "SIEM_KEYFILE"):
    os.environ.pop(k, None)
v = _fresh_vault()
v.configure(tempfile.gettempdir())
check("encryption off by default", not v.active())
line = v.pack_line({"a": 1})
check("packs to plaintext JSON when off", line.startswith("{") and v.unpack_line(line) == {"a": 1})

# --- encryption ON with a passphrase ---
with tempfile.TemporaryDirectory() as d:
    os.environ["SIEM_ENCRYPT"] = "1"
    os.environ["SIEM_KEY"] = "correct horse battery staple"
    v = _fresh_vault()
    v.configure(d)
    check("vault active with passphrase", v.active())
    tok = v.pack_line({"secret": "rev-shell /dev/tcp"})
    check("packed line is NOT plaintext JSON", not tok.startswith("{"))
    check("token is ASCII", all(ord(c) < 128 for c in tok))
    check("round-trip decrypts correctly", v.unpack_line(tok) == {"secret": "rev-shell /dev/tcp"})
    check("salt file created beside data", (Path(d) / ".vault.salt").exists())

    # legacy plaintext line still readable when vault is on
    check("plaintext line still read when vault on", v.unpack_line('{"x": 2}') == {"x": 2})

    # wrong key fails closed
    os.environ["SIEM_KEY"] = "the WRONG passphrase entirely"
    v2 = _fresh_vault()
    v2.configure(d)   # same salt dir, different passphrase -> different key
    failed = False
    try:
        v2.unpack_line(tok)
    except Exception:
        failed = True
    check("wrong key fails closed (no garbage returned)", failed)

# --- fail-safe: encryption requested but no key -> refuse ---
os.environ["SIEM_ENCRYPT"] = "1"
os.environ.pop("SIEM_KEY", None)
os.environ.pop("SIEM_KEYFILE", None)
v = _fresh_vault()
refused = False
try:
    v.configure(tempfile.gettempdir())
except RuntimeError:
    refused = True
check("fail-safe: refuses to run encrypted with no key", refused)

# --- keyfile model (USB key) ---
with tempfile.TemporaryDirectory() as d:
    v = _fresh_vault()
    kf = v.generate_keyfile(Path(d) / "vault.key")
    os.environ["SIEM_ENCRYPT"] = "1"
    os.environ["SIEM_KEYFILE"] = kf
    os.environ.pop("SIEM_KEY", None)
    v = _fresh_vault()
    v.configure(d)
    tok = v.pack_line({"k": "v"})
    check("keyfile model round-trips", v.unpack_line(tok) == {"k": "v"})

# --- end to end: artifacts written via the reporter path are unreadable as plaintext ---
with tempfile.TemporaryDirectory() as d:
    os.environ["SIEM_ENCRYPT"] = "1"
    os.environ["SIEM_KEY"] = "operator passphrase"
    os.environ.pop("SIEM_KEYFILE", None)
    import core.vault as v
    importlib.reload(v)
    v.configure(d)
    from output.reporter import write_jsonl
    rows = [{"signal_type": "bash_sigma", "host": "h1", "cmd": "rev-shell /dev/tcp"}]
    write_jsonl(Path(d) / "signals.jsonl", rows)
    disk = (Path(d) / "signals.jsonl").read_text()
    check("reporter output hides sensitive fields on disk",
          "bash_sigma" not in disk and "/dev/tcp" not in disk)
    # read back the way the app does
    back = [v.unpack_line(ln) for ln in disk.splitlines() if ln.strip()]
    check("encrypted artifact reloads and decrypts", back == rows)

for k in ("SIEM_ENCRYPT", "SIEM_KEY", "SIEM_KEYFILE"):
    os.environ.pop(k, None)

print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)
