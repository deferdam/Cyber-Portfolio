# Version History

This project evolved over four iterations:

| Version | Description |
|---------|-------------|
| v1 | Early detection attempts based solely on file modification patterns. No scoring, no ML. |
| v2 | Improved heuristic detection with behavior patterns but no slow ransomware support. |
| v3 | Added full scoring logic to heuristics. Detects more types of ransomware, still no ML. |
| v4 (Current) | Full hybrid system: heuristics, scoring, slow ransomware support, and machine learning classification. |

The latest version produces a ranked report identifying the most likely ransomware process based on probability and behavioral scoring.
