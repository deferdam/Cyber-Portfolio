# Ransomware Behavior Detector

This project detects ransomware activity by analyzing system behavior using both rule-based heuristics and machine learning.
It supports detection of both fast and slow ransomware patterns.

---

## Requirements

Python 3.10 or newer is recommended.

Install dependencies with:

```bash
pip install -r requirements.txt
```

---

## Project Structure

```
/v4
 ├─ ransomware_detector.py            → Heuristic detection engine
 ├─ ml_pipeline.py                    → Feature extraction and model utilities
 ├─ train.py                          → Training script for the ML model
 ├─ apply_model.py                    → Applies trained model to new reports
 ├─ events.jsonl                      → Input log file used for simulation/testing
 ├─ labels.json                       → Labels for supervised ML classification
 ├─ detection_report.json             → Output from ransomware_detector.py
 ├─ detection_report_with_ml.json     → Output after ML scoring
 ├─ requirements.txt
 └─ docs/
     ├─ index.md
     ├─ system_overview.md
     └─ version_history.md
```

---

## Setup and Usage

### Step 1: Run the behavior-based detector

This will analyze `events.jsonl` and generate a structured report:

```bash
python ransomware_detector.py
```

Expected output:

```
detection_report.json
```

---

### Step 2: Train the Machine Learning Model

Requires valid labels in `labels.json`:

```bash
python train.py
```

Expected output:

```
ransomware_model.joblib
```

The script will also print precision, recall, and other evaluation metrics.

---

### Step 3: Apply the Machine Learning Model

```bash
python apply_model.py
```

This produces:

```
detection_report_with_ml.json
```

That file includes:

- ML probability score
- Predicted label (benign / ransomware)
- Sorted ranking of most suspicious processes

---

## How to Test the System

1. Confirm these files exist:

| File | Purpose |
|------|---------|
| `events.jsonl` | Simulated or real logs |
| `labels.json` | Ground-truth classification |
| `detection_report.json` | Output from heuristic engine |
| `ransomware_model.joblib` | Trained ML model |

2. Run the full workflow:

```bash
python ransomware_detector.py
python train.py
python apply_model.py
```

3. Evaluate whether:

- Known ransomware receives a high score
- Normal applications are not flagged
- False positives are limited

---

## Notes

- Model performance is currently based on synthetic data.
- Real environments may require retraining and more diverse labeled datasets.
- Integration with SIEM or endpoint agents is possible in future versions.

---

## License
