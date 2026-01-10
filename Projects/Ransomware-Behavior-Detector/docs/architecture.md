# Architecture & Core Logic

## Project Title & Team Members

- **Project Name:** Ransomware Behavior Detection System (Hybrid Heuristic + Machine Learning)

## Overview

This project detects ransomware activity using:

- **Behavior‑based rules** (file access rate, extensions, integrity levels, network traffic)
- **Machine learning classification** using extracted features from detection reports

The model predicts the probability that a running process is ransomware and ranks processes by severity.

---

## Setup Instructions

### 1 Install Python (recommended: 3.10+)

Check version:

```bash
python --version
```

### 2 Create a Virtual Environment (optional but recommended)

```bash
python -m venv .venv
```

Activate it:

```bash
# Windows
.\.venv\Scripts\activate
# Linux/Mac
source .venv/bin/activate
```

### 3 Install Required Dependencies

```bash
pip install -r requirements.txt
```

---

## How to Run the System

### **Step 1 — Generate Detection Report (Heuristic Engine)**

Make sure an `events.jsonl` or `events_large.jsonl` file exists in the folder.

```bash
python ransomware_detector.py
```

Expected output: **detection_report.json**

---

### **Step 2 — Train the Machine Learning Model**

Requires:

- detection_report.json
- labels.json or labels_large.json

Run:

```bash
python train.py
```

Expected output:

- Console shows precision/recall metrics
- Model file saved as: `ransomware_model.joblib`

---

### **Step 3 — Apply the ML Model to Detection Report**

```bash
python apply_model.py
```

Expected output:

- `detection_report_with_ml.json`
- Contains ML ransomware probability per process

---

## Testing Process

1. Validate files exist:

| Required File | Exists |
|--------------|--------|
| events log (`events.jsonl`) | Yes / No |
| labels file (`labels.json`) | Yes / No |
| detection_report.json | Created after step 1 |
| ransomware_model.joblib | Created after training |

2. Run complete detection pipeline (`Step 1 → Step 3`).

3. Inspect:

- False positives
- False negatives
- ML score stability

---

## requirements.txt

Used for installation:

```
scikit-learn
joblib
```

---

## To Complete

- Team information
- Evaluation with real datasets
- Connection to SIEM / EDR logging pipeline

---

## Final Notes

This project is a framework to detect ransomware behavior—not a production‑ready EDR agent.  
Further improvements depend on real forensic log data and continued training.

