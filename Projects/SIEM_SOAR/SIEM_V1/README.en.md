# Mini SIEM, Sigma-Based Detection Engine

> Behavioral detection engine built for learning and lab use.  
> Defensive scope only. No malware binaries hosted.

---

## 1. Executive Summary

Mini SIEM is a lightweight detection engine that ingests Windows logs and scores them against Sigma-based behavioral rules.

It does not rely on hash signatures. It detects behavior patterns, which means it catches obfuscated or renamed variants that signature-based tools miss.

The engine analyzes:
- Windows Event Logs (Sysmon, PowerShell Script Block, Security)
- PowerShell execution patterns
- Process creation and parent-child relationships
- Behavioral indicators weighted into a risk score (0–100)

Current detection coverage:
- Suspicious PowerShell execution (EncodedCommand, IEX, DownloadString, WebClient)
- Ransomware behavioral patterns (mass rename, shadow copy deletion, suspicious extension bursts)

**Status: v1 complete. v2 in development.**

---

## 2. Architecture

```
Log sources (Windows Event Logs / Sysmon / PowerShell / JSON-Syslog)
    ↓
Normalizer, log parsing and field extraction
    ↓
Sigma rule engine, pattern matching
    ↓
Behavioral scorer, weighted indicator aggregation
    ↓
JSON alert output
    {
      "score": 85,
      "classification": "potential_malware_execution",
      "indicators": [...],
      "date": "2025-04-23T09:15:32Z"
    }
```

### Modules

| Module | Purpose |
|--------|---------|
| `normalizer.py` | Parses raw logs into structured events |
| `sigma_engine.py` | Loads and evaluates Sigma rules against events |
| `scorer.py` | Aggregates matched indicators into a weighted risk score |
| `correlator.py` | Links related events across time window |
| `reporter.py` | Outputs structured JSON alerts |

---

## 3. Detection Rules, v1

### PowerShell Detection (Event ID 4104, Script Block Logging)

Triggers on any of the following patterns:

| Indicator | Severity |
|-----------|----------|
| `-EncodedCommand` | High |
| `Invoke-Expression` | High |
| `DownloadString` + external URL | Critical |
| `WebClient` instantiation | Medium |
| `whoami` / identity enumeration | Medium |

**Condition:** `1 of selection*`, one indicator is sufficient to trigger.  
**Known false positives:** legitimate admin scripts using WebClient or IEX, scheduled inventory tasks.  
**Planned fix (v2):** weighted scoring per indicator to reduce false positive rate.

### Ransomware Behavioral Detection

Triggers on:

| Indicator | Weight |
|-----------|--------|
| High file rename rate | High |
| Suspicious extension patterns | High |
| Mass encryption activity | Critical |
| Shadow copy deletion | Critical |
| Abnormal process spawning | Medium |

---

## 4. Limitations

| Limitation | Detail |
|------------|--------|
| Lab environment only | Not tested against production log volumes |
| Requires proper log ingestion | Sysmon and Script Block Logging must be enabled |
| v1 false positive rate | `1 of selection*` condition is intentionally broad |
| No blocking capability | Detection and alerting only, no automated response |
| Evasion possible | Advanced actors can bypass behavioral rules |

---

## 5. Threat Model

| Behavior | Detected |
|----------|----------|
| Obfuscated PowerShell execution | Yes |
| Remote payload download | Yes |
| In-memory execution (fileless) | Partial |
| Fast-acting ransomware | Yes |
| Slow encryption ransomware | Yes |
| Shadow copy deletion | Yes |
| Privilege escalation via PS | Partial |

---

## 6. Roadmap

- [x] Sigma rule engine, PowerShell detection
- [x] Ransomware behavioral detector
- [ ] Weighted scoring per indicator (v2)
- [ ] Persistence detection (scheduled tasks, registry keys)
- [ ] Multi-source correlation across time window
- [ ] Basic web UI for alert review

---

## 7. References

- MITRE ATT&CK: T1059.001 (PowerShell), T1486 (Data Encrypted for Impact)
- Sigma rule specification: https://github.com/SigmaHQ/sigma
- Sysmon logging format: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Windows Event ID 4104, Script Block Logging

---

> **Defensive & educational content only.**  
> Built in an isolated lab environment. No live systems were used.
