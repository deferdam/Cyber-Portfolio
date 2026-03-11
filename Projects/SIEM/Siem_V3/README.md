# Mini-SIEM (SOC-oriented) — V1
Goal: ingest -> normalize -> detect -> correlate -> alert with explainable timeline.

## Quickstart
```bash
python -m venv .venv
source .venv/bin/activate  # on Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Small sample
python -m ingest.replay --input /mnt/data/events.jsonl --out-dir /mnt/data/out_small

# Larger sample (includes network)
python -m ingest.replay --input /mnt/data/events_large.jsonl --out-dir /mnt/data/out_large
```

Outputs:
- `alerts.jsonl` (one JSON per alert)
- `signals.jsonl`
- `timeline_<alert_id>.jsonl`
