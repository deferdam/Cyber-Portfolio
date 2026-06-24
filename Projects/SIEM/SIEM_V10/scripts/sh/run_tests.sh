#!/usr/bin/env bash
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$HERE/src"
PY=$(command -v python3 || command -v python || echo python3)
pass=0; fail=0
for f in "$HERE"/tests/test_*.py; do
  out=$("$PY" "$f" 2>&1)
  p=$(echo "$out" | grep -oiE '[0-9]+ passed' | tail -1 | grep -oE '[0-9]+'); fl=$(echo "$out" | grep -oiE '[0-9]+ failed' | tail -1 | grep -oE '[0-9]+')
  p=${p:-0}; fl=${fl:-0}; pass=$((pass+p)); fail=$((fail+fl))
  if [ "$fl" != "0" ]; then echo "[FAIL] $(basename "$f") ($p passed, $fl failed)"; else echo "[ ok ] $(basename "$f") ($p passed)"; fi
done
echo "-------------------------------------------"
echo "TOTAL: $pass passed, $fail failed"
[ "$fail" = "0" ] && echo "RESULT: ALL GREEN" || echo "RESULT: FAILURES PRESENT"
[ "$fail" = "0" ]
