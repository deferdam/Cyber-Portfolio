# Mini SIEM — Sigma-Based Detection Engine

> Behavioral detection engine built for learning and lab use.  
> Defensive scope only. No malware binaries hosted.

---

## 1. Executive Summary

Mini SIEM v3 extends the detection engine with multi-format log source support, process tree modeling, and a set of LOTL (*Living off the Land*) rules aligned with the MITRE ATT&CK framework.

It does not rely on hash signatures. It detects behavior patterns — which means it catches obfuscated or renamed variants that signature-based tools miss.

The engine analyzes:
- Windows Event Logs, syslog RFC 3164/5424, CEF, NXLog and Winlogbeat
- PowerShell execution patterns (Script Block Logging, EventID 4104)
- LOTL binaries: vssadmin, wmic, mshta, certutil, rundll32, schtasks, regsvr32
- Parent-child process relationships (suspicious spawns)
- Behavioral indicators weighted into a risk score (0–100), tagged with MITRE ATT&CK

Current detection coverage:
- Suspicious PowerShell execution (EncodedCommand, IEX, AMSI bypass, download cradles)
- Ransomware behavioral patterns (mass rename, shadow copy deletion, suspicious extension bursts)
- LOTL binaries (8 rules, Execution / Persistence / Defense Evasion / Impact tactics)
- Suspicious spawns (32 parent→child pairs — Office, WMI, loaders)
- Scheduled tasks via EventID 4698/4699/4702

**Status: v3 complete. v4 in development.**

---

## 2. Architecture

```
Log sources (Windows / Sysmon / PowerShell / RFC 3164 / RFC 5424 / CEF / NXLog / Winlogbeat)
    ↓
Syslog parser — auto-format detection
    ↓
Normalizer — field extraction into CanonicalEvent (immutable)
    ↓
Process Tree — parent→child index (2-pass build)
    ↓
3-layer detection engine
  ├── Layer 1 — Signature   : ransomware_v4
  ├── Layer 2 — Behavioral  : powershell_sigma + lotl_sigma + spawn suspects
  └── Layer 3 — Correlation : temporal recon → exec sequences
    ↓
Correlator — signal aggregation into alerts with severity
    ↓
JSON alert output
    {
      "score": 92,
      "mitre_tactic": "Impact",
      "mitre_technique": "T1490",
      "classification": "vssadmin_shadow_deletion",
      "indicators": [...],
      "date": "2025-04-23T09:15:32Z"
    }
```

### Modules

| Module | Purpose |
|--------|---------|
| `syslog_parser.py` | Parses RFC 3164, RFC 5424, CEF, JSON NXLog/Winlogbeat |
| `normalizer.py` | Converts raw events into immutable CanonicalEvent |
| `process_tree.py` | Builds parent→child index, detects suspicious spawns |
| `lotl_sigma.py` | 8 LOTL rules + EventID 4698/4699 + spawn suspects |
| `powershell_sigma.py` | Sigma YAML rules + temporal recon correlation |
| `engine.py` | 3-layer orchestrator with per-layer error isolation |
| `correlator.py` | Signals → Alerts with calculated severity |
| `reporter.py` | JSONL export — events, signals, alerts, timelines |

---

## 3. Detection Rules — v3

### PowerShell Detection (EventID 4104 — Script Block Logging)

| Indicator | Severity |
|-----------|----------|
| `-EncodedCommand` | High |
| `Invoke-Expression` / `IEX` | High |
| `DownloadString` + external URL | Critical |
| `WebClient` instantiation | Medium |
| AMSI bypass (`amsiInitFailed`, `AmsiScanBuffer`) | Critical |
| Obfuscation (backtick, char cast, string concat) | High |
| `whoami` / identity enumeration | Medium |

### LOTL Detection

| Rule | Binary | MITRE Tactic | Score |
|------|--------|-------------|-------|
| LOTL-001 | vssadmin.exe | Impact — T1490 | 0.92 |
| LOTL-002 | wmic.exe | Lateral Movement — T1047 | 0.80 |
| LOTL-003 | mshta.exe | Execution — T1218.005 | 0.85 |
| LOTL-004 | certutil.exe | Defense Evasion — T1140 | 0.82 |
| LOTL-005 | rundll32.exe | Defense Evasion — T1218.011 | 0.78 |
| LOTL-006 | schtasks.exe | Persistence — T1053.005 | 0.75 |
| LOTL-007 | cron / at.exe | Persistence — T1053.003 | 0.70 |
| LOTL-008 | regsvr32.exe | Defense Evasion — T1218.010 | 0.88 |

### Ransomware Behavioral Detection

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
| No legitimacy baseline | No historical context — false positives on admin activity |
| No blocking capability | Detection and alerting only — no automated response |
| Evasion possible | Advanced actors can bypass behavioral rules |
| Partial correlation | Only one temporal sequence type detected (PowerShell recon) |

---

## 5. Threat Model

| Behavior | Detected |
|----------|----------|
| Obfuscated PowerShell execution | Yes |
| Remote payload download | Yes |
| In-memory execution (fileless) | Partial |
| AMSI bypass | Yes |
| Fast-acting ransomware | Yes |
| Slow encryption ransomware | Yes |
| Shadow copy deletion | Yes |
| Lateral movement via WMI | Yes |
| Persistence via scheduled tasks | Yes |
| Suspicious spawn (Office → PowerShell) | Yes |
| Privilege escalation via PS | Partial |

---

## 6. Roadmap

- [x] Sigma rule engine — PowerShell detection
- [x] Ransomware behavioral detector
- [x] Multi-format syslog support (RFC 3164, RFC 5424, CEF, NXLog, Winlogbeat)
- [x] Process tree — parent→child modeling
- [x] 8 LOTL rules with MITRE ATT&CK tagging
- [x] Suspicious spawn detection (32 pairs)
- [x] 3-layer engine with per-layer error isolation
- [ ] Multi-file Sigma rules per domain (v4)
- [ ] Advanced persistence detection (registry Run, WMI subscription)
- [ ] Linux detection (chmod +s, cron, reverse shell)
- [ ] Deferred enrichment — URLVoid, WHOIS, IP geolocation (v6)
- [ ] Legitimacy baseline to reduce false positives (v7)

---

## 7. References

- MITRE ATT&CK: T1059.001 (PowerShell), T1486 (Ransomware), T1490 (Shadow Copy), T1047 (WMI), T1218 (LOLBIN)
- Sigma rule specification: https://github.com/SigmaHQ/sigma
- Sysmon logging format: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Windows Event ID 4104 — Script Block Logging
- CEF Specification: https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdoc/common-event-format-v25/common-event-format-v25.pdf

---

> **Defensive & educational content only.**  
> Built in an isolated lab environment. No live systems were used.
