# System Overview

## 1. Executive Summary

The Ransomware Behavior Detector is a hybrid detection engine using behavioral heuristics and machine learning.  
It monitors system logs and detects both fast-acting ransomware and slow encryption attempts.

The system analyzes:
- File system operations
- Process metadata (privilege level, execution path)
- File extension patterns
- High-frequency file modification bursts
- Suspicious network behavior

Machine learning improves accuracy and reduces false positive alerts by learning from labeled reports.

---------------------------------------------

## 2. Technical Design and Architecture

### Architecture Diagram

```
Raw logs (.jsonl)
    ↓
Heuristic Detector (ransomware_detector.py)
    ↓
detection_report.json
    ↓
Machine Learning Training (train.py, ml_pipeline.py)
    ↓
ransomware_model.joblib
    ↓
apply_model.py
    ↓
detection_report_with_ml.json
```

### Major Modules

| Module | Purpose |
|--------|---------|
| ransomware_detector.py | Extracts behavioral indicators and creates a structured detection report |
| ml_pipeline.py | Converts the detection report into ML feature vectors |
| train.py | Trains the RandomForest model from labeled examples |
| apply_model.py | Scores processes based on ransomware probability using the trained model |

---------------------------------------------

## 3. Security Analysis

### Threat Model

| Behavior Type | Detection Supported |
|---------------|---------------------|
| Fast encryption ransomware | Yes |
| Slow encryption ransomware | Yes |
| Abnormal execution paths | Yes |
| Privilege escalation detection | Yes |
| Suspicious outbound connections | Yes |

### Assumptions

- Logging is reliable and includes timestamps and file metadata.
- Process names and PIDs stay consistent during logging.
- Labeled examples exist for machine learning training.

### Limitations

- Evasion is still theoretically possible.
- Real-world performance depends on data quality.
- The system issues alerts but does not block execution.

---------------------------------------------

## 4. Testing Methodology and Results

A synthetic dataset was created to simulate ransomware behavior and normal system usage.

Evaluation metrics produced by the trained model:

| Metric | Value |
|--------|-------|
| Precision | 1.00 |
| Recall | 1.00 |
| Accuracy | 1.00 |

These results were obtained in a synthetic testing environment. Real-world datasets will produce lower accuracy and require periodic retraining.

---------------------------------------------

## 5. Team Roles and Contributions

Format will be completed later:

- Member 1 – Responsibilities TBD
- Member 2 – Responsibilities TBD
- Member 3 – Responsibilities TBD

---------------------------------------------

## 6. References and Dataset Sources

- MITRE ATT&CK Framework: T1486 Encryption for Impact
- Sysinternals Sysmon Logging Format
- Research papers on ransomware behavioral classification
- Dataset Type: Synthetic simulated intrusion and ransomware logs
