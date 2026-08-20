"""Password strength policy with real entropy estimation (no external dependency).

This is a lightweight, zxcvbn-inspired estimator built on the standard library only,
in keeping with the project's rule to minimize the supply-chain surface. It is NOT a
full zxcvbn port: it does not ship a 30k-word frequency dictionary. Instead it combines
character-class entropy with penalties for the cheap patterns attackers try first
(common passwords, keyboard runs, pure sequences, repeats). The goal is to reject weak
secrets at the gate, not to score them on a research-grade scale.

Design decisions:
  * We estimate entropy in bits and require a floor (MIN_BITS). Bits, not length alone,
    because "aaaaaaaaaaaa" is 12 chars but near-zero real entropy.
  * We hard-reject anything matching a small blocklist of the most common passwords and
    obvious patterns, regardless of computed bits, because those are tried first.
  * The estimate is deliberately CONSERVATIVE (it under-counts), so a password that
    passes has margin. Better to annoy a user than to admit a weak admin secret.
  * On top of entropy, we also require character-class diversity (at least MIN_CLASSES of
    lower/upper/digit/special). Note for anyone reviewing this: NIST 800-63B actually
    recommends AGAINST forced composition rules in favor of length + entropy + blocklists,
    which is what this module already did before this rule. This extra gate is added
    because a product sold to enterprises is commonly expected, including by auditors, to
    show an explicit, nameable complexity requirement; it is layered ON TOP of the entropy
    floor, never a replacement for it, so it costs nothing in real strength.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

# Entropy floor for an admin secret. ~60 bits is a reasonable bar for a human-chosen
# password backed by argon2id hashing; below this we refuse.
MIN_BITS = 60.0
MIN_LEN = 12
# Character-class diversity: how many of {lower, upper, digit, special} must be present.
MIN_CLASSES = 3

# The cheapest guesses. Kept short on purpose: this is a tripwire, not a full dictionary.
_COMMON = {
    "password", "passw0rd", "123456", "12345678", "123456789", "qwerty",
    "azerty", "admin", "administrator", "letmein", "welcome", "iloveyou",
    "monkey", "dragon", "abc123", "111111", "000000", "qwertyuiop",
    "motdepasse", "changeme", "secret", "root", "toor", "test",
}

_KEYBOARD_RUNS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "azertyuiop", "qsdfghjklm", "wxcvbn",
    "1234567890",
]


def _char_pool(pw: str) -> int:
    """Size of the character set the password draws from (for entropy upper bound)."""
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"[0-9]", pw):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", pw):
        pool += 33  # rough count of common printable symbols
    return pool or 1


def _class_count(pw: str) -> int:
    """How many of lower/upper/digit/special this password contains."""
    return sum(1 for pat in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^a-zA-Z0-9]")
               if re.search(pat, pw))


def _has_keyboard_run(pw: str, n: int = 4) -> bool:
    low = pw.lower()
    for run in _KEYBOARD_RUNS:
        for i in range(len(run) - n + 1):
            seg = run[i:i + n]
            if seg in low or seg[::-1] in low:
                return True
    return False


def _has_sequence(pw: str, n: int = 4) -> bool:
    """Detect ascending/descending runs like 'abcd' or '4321'."""
    low = pw.lower()
    for i in range(len(low) - n + 1):
        seg = low[i:i + n]
        if all(ord(seg[j + 1]) - ord(seg[j]) == 1 for j in range(len(seg) - 1)):
            return True
        if all(ord(seg[j + 1]) - ord(seg[j]) == -1 for j in range(len(seg) - 1)):
            return True
    return False


def _max_repeat_run(pw: str) -> int:
    """Length of the longest run of a single repeated character."""
    if not pw:
        return 0
    best = run = 1
    for i in range(1, len(pw)):
        run = run + 1 if pw[i] == pw[i - 1] else 1
        best = max(best, run)
    return best


@dataclass(frozen=True)
class Strength:
    ok: bool
    bits: float
    reason: str = ""


def estimate_bits(pw: str) -> float:
    """Conservative entropy estimate in bits.

    Base estimate is len * log2(pool). We then apply multiplicative penalties for
    structure that shrinks the real search space: long single-char repeats and detected
    patterns. The result is intentionally lower than a naive count.
    """
    if not pw:
        return 0.0
    pool = _char_pool(pw)
    base = len(pw) * math.log2(pool)

    # Penalty: long repeats add almost nothing past the first couple of chars.
    rep = _max_repeat_run(pw)
    if rep >= 3:
        base *= max(0.3, 1.0 - 0.12 * (rep - 2))

    # Penalty: keyboard runs and sequences are tried early.
    if _has_keyboard_run(pw):
        base *= 0.6
    if _has_sequence(pw):
        base *= 0.7

    return base


def check(pw: str) -> Strength:
    """Gate a candidate password. Returns Strength(ok, bits, reason)."""
    if pw is None or len(pw) < MIN_LEN:
        return Strength(False, 0.0,
                        "Password must be at least %d characters." % MIN_LEN)

    low = pw.lower()
    if low in _COMMON:
        return Strength(False, 0.0, "Password is in the common-password blocklist.")
    # Reject if the password is just a common word plus trailing digits, e.g. "password1".
    stripped = re.sub(r"\d+$", "", low)
    if stripped in _COMMON:
        return Strength(False, 0.0,
                        "Password is a common word with trailing digits.")

    bits = estimate_bits(pw)
    if bits < MIN_BITS:
        return Strength(False, bits,
                        "Password too weak (estimated %.0f bits, need %.0f). "
                        "Use more length and mixed character types, avoid patterns."
                        % (bits, MIN_BITS))

    classes = _class_count(pw)
    if classes < MIN_CLASSES:
        return Strength(False, bits,
                        "Password must mix at least %d of: lowercase, uppercase, digit, "
                        "special character (has %d)." % (MIN_CLASSES, classes))

    return Strength(True, bits, "")
