"""Tests for v11.007: weekly update check (GitHub Releases, check-only, no download)."""
import sys
from datetime import datetime
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


from core import update_check as uc

# -- version parsing --------------------------------------------------------------
print("\n[version parsing]")
check("parses v-prefixed version", uc._parse_version("v11.6") == (11, 6))
check("parses bare version", uc._parse_version("11.006") == (11, 6))
check("parses three-part version", uc._parse_version("v11.6.2") == (11, 6, 2))
check("garbage yields empty tuple (fail-safe)", uc._parse_version("not-a-version") == ())
check("empty string yields empty tuple", uc._parse_version("") == ())
check("strips non-numeric suffix", uc._parse_version("v11.6-beta") == (11, 6))


# -- version comparison -------------------------------------------------------------
print("\n[version comparison]")
check("newer minor version detected", uc.is_newer("v11.7", "v11.6"))
check("older version not flagged as newer", not uc.is_newer("v11.5", "v11.6"))
check("equal versions not flagged as newer", not uc.is_newer("v11.6", "v11.6"))
check("newer major version detected", uc.is_newer("v12.0", "v11.9"))
check("garbage remote never flagged as newer (fail-safe)",
      not uc.is_newer("garbage", "v11.6"))
check("garbage local never flagged as newer (fail-safe)",
      not uc.is_newer("v11.7", "garbage"))


# -- check_for_update shape and fail-safety -----------------------------------------
print("\n[check_for_update]")
# Point at a domain that resolves but will not respond usefully, to exercise the
# fail-safe path without depending on network availability in the test environment.
result = uc.check_for_update("this-org-does-not-exist-xyz/this-repo-does-not-exist-xyz",
                             "v1.0")
check("result has all expected keys",
      set(result.keys()) == {"checked_at", "current", "latest",
                              "update_available", "releases_url"})
check("current version echoed back", result["current"] == "v1.0")
check("releases_url points at the repo's own Releases page",
      result["releases_url"].startswith("https://github.com/") and
      result["releases_url"].endswith("/releases"))
check("failed lookup never crashes, never claims an update", result["latest"] is None)
check("update_available is False on failed lookup", result["update_available"] is False)


# -- scheduler: due-time logic (Monday 17:00 by default) ----------------------------
print("\n[weekly scheduler]")
checker = uc.WeeklyUpdateChecker("someorg/somerepo", "v11.6", weekday=0, hour=17)
check("Monday at 17:00 is due", checker._due_now(datetime(2026, 7, 13, 17, 0)))
check("Monday at 17:59 is due (same hour)", checker._due_now(datetime(2026, 7, 13, 17, 59)))
check("Monday at 16:59 is NOT due", not checker._due_now(datetime(2026, 7, 13, 16, 59)))
check("Monday at 18:00 is NOT due", not checker._due_now(datetime(2026, 7, 13, 18, 0)))
check("Tuesday at 17:00 is NOT due", not checker._due_now(datetime(2026, 7, 14, 17, 0)))

check("no result before any check runs", checker.last_result is None)
r = checker.check_now()
check("check_now populates last_result", checker.last_result is not None)
check("check_now returns the same dict shape", set(r.keys()) == set(
    ["checked_at", "current", "latest", "update_available", "releases_url"]))

# custom schedule (e.g. a different day/hour) is respected
checker2 = uc.WeeklyUpdateChecker("x/y", "v1.0", weekday=4, hour=9)  # Friday 09:00
check("custom weekday/hour respected", checker2._due_now(datetime(2026, 7, 17, 9, 0)))
check("custom schedule rejects the default Monday slot",
      not checker2._due_now(datetime(2026, 7, 13, 17, 0)))


print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)
