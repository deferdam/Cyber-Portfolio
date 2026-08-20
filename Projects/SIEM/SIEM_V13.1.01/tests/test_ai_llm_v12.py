"""v12.3 | LocalLLMExplainer tests. No real network: a fake transport is injected. Verifies
the anti-C2 loopback guard, off-by-default, prompt separation, output bounding, and graceful
degradation."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from core.ai.llm import LocalLLMExplainer, _is_loopback, MAX_EXPLANATION_CHARS

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1

# -- loopback detection --------------------------------------------------------------------
check("127.0.0.1 is loopback", _is_loopback("http://127.0.0.1:11434"))
check("localhost is loopback", _is_loopback("http://localhost:11434"))
check("::1 is loopback", _is_loopback("http://[::1]:11434"))
check("public host is NOT loopback", not _is_loopback("http://evil.example.com:11434"))
check("10.x host is NOT loopback", not _is_loopback("http://10.0.0.5:11434"))

# -- off by default ------------------------------------------------------------------------
off = LocalLLMExplainer(enabled=None, transport=lambda p: "should not be called")
# enabled=None reads env; SIEM_LLM_ENABLED is unset in the test env -> disabled
check("disabled by default returns None", off.explain("false_positive", 0.9, ["a"]) is None)

# -- non-loopback endpoint disables it even if asked to enable ------------------------------
bad = LocalLLMExplainer(endpoint="http://evil.example.com:11434", enabled=True,
                        transport=lambda p: "leaked")
check("non-loopback endpoint disables the explainer", bad.available() is False)
check("non-loopback disable has a reason", "loopback" in bad.reason.lower())
check("non-loopback explainer never calls transport",
      bad.explain("x", 0.5, ["f"]) is None)

# -- enabled with a fake transport: returns bounded text, uses untrusted separation ---------
captured = {}
def fake(prompt_text):
    captured["prompt"] = prompt_text
    return "The classifier flagged encoded PowerShell as suspicious."
llm = LocalLLMExplainer(endpoint="http://127.0.0.1:11434", enabled=True, transport=fake)
out = llm.explain("true_positive", 0.91, ["stype=powershell", "risk=encoded_command"])
check("enabled explainer returns the transport text", out and "PowerShell" in out)
check("prompt keeps ticket features in an untrusted section",
      "<<UNTRUSTED " in captured.get("prompt", ""))
check("prompt states the label is final (verdict not from the LLM)",
      "final" in captured.get("prompt", "").lower())

# -- output is bounded (untrusted, display-only) -------------------------------------------
big = LocalLLMExplainer(endpoint="http://127.0.0.1", enabled=True,
                        transport=lambda p: "x" * 99999)
check("output is capped to MAX_EXPLANATION_CHARS",
      len(big.explain("l", 0.5, ["f"])) == MAX_EXPLANATION_CHARS)

# -- graceful degradation: transport failure returns None, no crash ------------------------
dead = LocalLLMExplainer(endpoint="http://127.0.0.1", enabled=True, transport=lambda p: None)
check("transport returning None degrades to None", dead.explain("l", 0.5, ["f"]) is None)

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
