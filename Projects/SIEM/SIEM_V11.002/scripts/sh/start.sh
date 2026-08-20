#!/usr/bin/env bash
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$HERE/src"; export SIEM_MODE=local; export SIEM_HOST=127.0.0.1
PY=$(command -v python3 || command -v python || echo python3)
echo "[*] Mini SOAR | mode=LOCAL | http://127.0.0.1:5000 | browser opens itself. Ctrl+C to stop."
"$PY" "$HERE/src/server/app.py"
