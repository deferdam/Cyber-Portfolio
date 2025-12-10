# Welcome to the Ransomware Behavior Detector Documentation

This documentation covers the structure, purpose, and usage of the Ransomware Behavior Detector (Version 4).

The system combines:
- Behavior-based heuristics (file modification patterns, suspicious extensions, privilege context, network activity)
- Machine Learning classification (RandomForest model)
- Detection support for both fast and slow ransomware behavior

Use the navigation menu to access:
- System architecture and methodology
- Version comparison (v1 → v4)
- Setup, testing, and deployment instructions
- Research references and dataset information

---------------------------------------------

## Quick Start

If you have not installed dependencies yet:

```
pip install -r requirements.txt
```

Then generate your first detection:

```
python ransomware_detector.py
```

Train the machine learning model:

```
python train.py
```

Apply the model to classify suspicious processes:

```
python apply_model.py
```

---------------------------------------------

## Documentation Sections

| Page | Content |
|------|---------|
| System Overview | Full project report including architecture, testing, threat model, and dataset |
| Version History | Summary of differences between v1, v2, v3, and v4 |
| README | Installation and usage instructions |

If something looks incomplete, check the System Overview page.
