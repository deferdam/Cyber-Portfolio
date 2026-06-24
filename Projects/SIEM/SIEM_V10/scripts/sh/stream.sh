#!/usr/bin/env bash
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$HERE/src"
PY=$(command -v python3 || command -v python || echo python3)
echo "[*] Streaming simulation (fake data). Start the app first (start), then refresh the UI."
"$PY" "$HERE/src/ingest/stream.py" "$@"
