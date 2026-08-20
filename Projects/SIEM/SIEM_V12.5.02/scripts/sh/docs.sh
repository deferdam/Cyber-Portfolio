#!/usr/bin/env bash
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INDEX="$HERE/docs/index.html"
echo "[*] Opening documentation: $INDEX"
( command -v xdg-open >/dev/null && xdg-open "$INDEX" ) || ( command -v open >/dev/null && open "$INDEX" ) || echo "[!] Open manually: $INDEX"
