#!/usr/bin/env bash
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$HERE/src"
PY=$(command -v python3 || command -v python || echo python3)
IN="${1:-$HERE/samples/demo_linux_attack.jsonl}"; OUT="${2:-$HERE/out/large}"; FMT="${3:-auto}"
echo "[*] Pipeline | input=$IN | out=$OUT | format=$FMT"
rm -f "$OUT/tickets.jsonl"
"$PY" -m ingest.replay --input "$IN" --out-dir "$OUT" --format "$FMT"
echo "[+] Done. Artifacts in $OUT"
