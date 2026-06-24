#!/usr/bin/env bash
BASEDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="$BASEDIR/src"
PYEXE=$(command -v python3 || command -v python || echo python3)
echo "[*] Starting Mini SOAR at http://localhost:5000"
echo "[*] Press Ctrl+C to stop."
"$PYEXE" "$BASEDIR/src/server/app.py"
