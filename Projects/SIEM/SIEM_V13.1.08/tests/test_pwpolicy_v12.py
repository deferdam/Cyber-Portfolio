"""pwpolicy.py tests: entropy floor, blocklist, and the class-diversity gate (v12.1.01)."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from core import pwpolicy

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1

# -- too short / empty ----------------------------------------------------------------------
check("empty password rejected", not pwpolicy.check("").ok)
check("short password rejected", not pwpolicy.check("Ab1!Ab1!").ok)

# -- blocklist / common patterns -------------------------------------------------------------
check("common password rejected", not pwpolicy.check("password123456").ok)
check("common word + trailing digits rejected", not pwpolicy.check("password12345").ok)

# -- low real entropy despite length (repeats, keyboard runs, sequences) ---------------------
check("long single-char repeat rejected", not pwpolicy.check("aaaaaaaaaaaaaaaaaaaa").ok)
check("keyboard run rejected", not pwpolicy.check("qwertyuiopasdfgh").ok)

# -- class diversity gate: strong entropy but a SINGLE character class must still fail -------
single_class_high_entropy = "correcthorsebatterystaplezebra"  # 31 lowercase-only chars
strength = pwpolicy.check(single_class_high_entropy)
check("single-class-only password rejected despite length",
      not strength.ok and "mix at least" in strength.reason)

two_classes = "correcthorsebatterystaple99"  # lower + digit only, 2 classes
check("two-class password rejected (need at least 3)", not pwpolicy.check(two_classes).ok)

# -- a real strong password: length + entropy + 3+ classes must pass -------------------------
strong = "Tr0ub4dour-Quux-Vault-71!"
strength = pwpolicy.check(strong)
check("strong mixed password accepted", strength.ok)
check("accepted password reports bits above floor", strength.bits >= pwpolicy.MIN_BITS)

# -- exactly at the 3-class floor (upper+lower+digit, no special) should pass if long enough -
three_classes = "CorrectHorseBattery77StapleZebra"
check("3-class password (no special) can pass with enough length",
      pwpolicy.check(three_classes).ok)

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
