#!/usr/bin/env bash
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$HERE/src"; export SIEM_MODE=showcase; export SIEM_HOST=127.0.0.1
PY=$(command -v python3 || command -v python || echo python3)
echo "[*] Mini SOAR | mode=SHOWCASE (sealed demo, fake data) | http://127.0.0.1:5000. Ctrl+C to stop."
"$PY" "$HERE/src/server/app.py"
