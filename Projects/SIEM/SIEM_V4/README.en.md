# Mini SIEM — Sigma-Based Detection Engine

> Behavioral detection engine built for learning and lab use.  
> Defensive scope only. No malware binaries hosted.

---

## 1. Executive Summary

Mini SIEM v4 introduces a multi-file Sigma rule loader and three new detection domains: Windows persistence, privilege escalation, and suspicious Linux/Unix commands.

It does not rely on hash signatures. It detects behavior patterns — which means it catches obfuscated or renamed variants that signature-based tools miss.

The engine analyzes:
- Windows Event Logs, syslog RFC 3164/5424, CEF, NXLog and Winlogbeat
- PowerShell Script Blocks (EventID 4104) — obfuscation, AMSI bypass, download cradles
- Persistence mechanisms: registry Run keys, WMI subscription, startup folder, inline schtasks
- Privilege escalation: admin group manipulation, UAC bypass, credential dumping
- Suspicious Linux/Unix commands: chmod +s, cron, curl pipe bash, reverse shells
- Parent-child process relationships and LOTL binaries

Current detection coverage:
- Suspicious PowerShell execution — 4 Sigma files by domain
- Ransomware behavioral patterns
- LOTL binaries (8 rules, MITRE ATT&CK)
- Windows persistence — 6 techniques detected
- Privilege escalation — 5 techniques detected
- Linux commands — 8 detection categories

**Status: v4 complete. v5 in development (extended Linux detection — auditd).**

---

## 2. Architecture

```
Log sources (Windows / Sysmon / PowerShell / RFC 3164 / RFC 5424 / CEF / NXLog / Winlogbeat)
    ↓
Syslog parser — auto-format detection
    ↓
Normalizer — field extraction into immutable CanonicalEvent
    ↓
Process Tree — parent→child index (2-pass build)
    ↓
3-layer detection engine
  ├── Layer 1 — Signature   : ransomware_v4
  ├── Layer 2 — Behavioral  : powershell_sigma (4 YAML files) + lotl_sigma + spawn suspects
  └── Layer 3 — Correlation : temporal recon → exec sequences
    ↓
Correlator — signal aggregation into alerts with severity
    ↓
JSON alert output
    {
      "score": 88,
      "mitre_tactic": "Persistence",
      "mitre_technique": "T1547.001",
      "classification": "registry_run_key_persistence",
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
| `powershell_sigma.py` | Multi-file Sigma YAML loader |
| `engine.py` | 3-layer orchestrator — declares `_PS_RULE_FILES` |
| `correlator.py` | Signals → Alerts with calculated severity |
| `reporter.py` | JSONL export — events, signals, alerts, timelines |

### PowerShell Sigma Files

| File | Domain | MITRE Techniques |
|------|--------|-----------------|
| `ps_scriptblock.yaml` | Script Block 4104 — encoding, IEX, AMSI, recon | T1059.001, T1027, T1562 |
| `ps_persistence.yaml` | Registry Run, WMI sub, startup, inline schtasks | T1547.001, T1053.005, T1546.003 |
| `ps_privilege_escalation.yaml` | Admin group add, UAC bypass, credential dump | T1098, T1548.002, T1003 |
| `linux_suspicious.yaml` | chmod +s, cron, curl pipe bash, reverse shell | T1059.004, T1053.003, T1222.002 |

---

## 3. Detection Rules — v4

### PowerShell Script Block (EventID 4104)

| Indicator | Severity |
|-----------|----------|
| `-EncodedCommand` / `-enc` | High |
| `Invoke-Expression` / `IEX` | High |
| AMSI bypass (`amsiInitFailed`, `AmsiScanBuffer`) | Critical |
| `-ExecutionPolicy Bypass` | High |
| `DownloadString` / `Invoke-WebRequest` | Critical |
| Obfuscation (backtick, char cast, `-join`) | High |
| `whoami` / identity enumeration | Medium |

### Windows Persistence

| Indicator | MITRE Technique |
|-----------|----------------|
| Registry `CurrentVersion\Run` write | T1547.001 |
| `-WindowStyle Hidden` / `-NonInteractive` | T1564.003 |
| Inline `Register-ScheduledTask` | T1053.005 |
| `New-Service` / `sc create` | T1543.003 |
| WMI Event Subscription (`__EventFilter`) | T1546.003 |
| Drop in Startup folder | T1547.001 |

### Privilege Escalation

| Indicator | MITRE Technique |
|-----------|----------------|
| `net localgroup administrators` / `Add-LocalGroupMember` | T1098 |
| `Add-ADGroupMember` / `net group "Domain Admins"` | T1098 |
| `net user /add` / `New-LocalUser` | T1136.001 |
| `fodhelper` / `eventvwr` / UAC bypass | T1548.002 |
| `Invoke-Mimikatz` / `sekurlsa` | T1003 |

### Suspicious Linux Commands

| Indicator | MITRE Technique |
|-----------|----------------|
| `chmod +s` / `chmod 4755` (setuid) | T1222.002 |
| `* * * * * curl` / `crontab -` | T1053.003 |
| `curl.*\|.*bash` / `wget.*\|.*sh` | T1059.004 |
| `bash -i >& /dev/tcp` (reverse shell) | T1059.004 |
| Write to `/etc/passwd` / `/etc/shadow` | T1098 |
| `setenforce 0` / `ufw disable` | T1562.001 |

---

## 4. Limitations

| Limitation | Detail |
|------------|--------|
| Lab environment only | Not tested against production log volumes |
| Requires proper log ingestion | Sysmon and Script Block Logging must be enabled |
| No legitimacy baseline | False positives on admin activity and deployments |
| No signal deduplication | One event may produce multiple distinct Signals |
| No blocking capability | Detection and alerting only — no automated response |
| Linux in CommandLine mode only | No auditd / syscall integration yet (v5) |
| Evasion possible | Advanced actors can bypass behavioral rules |

---

## 5. Threat Model

| Behavior | Detected |
|----------|----------|
| Obfuscated PowerShell execution | Yes |
| Remote payload download | Yes |
| In-memory execution (fileless) | Partial |
| AMSI bypass | Yes |
| Fast / slow ransomware | Yes |
| Shadow copy deletion | Yes |
| Registry Run persistence | Yes |
| WMI Event Subscription persistence | Yes |
| Local / domain admin group add | Yes |
| UAC bypass (fodhelper, eventvwr) | Yes |
| Credential dump (Mimikatz) | Yes |
| Linux reverse shell | Yes |
| chmod +s setuid escalation | Yes |
| Lateral movement via WMI | Yes |
| Suspicious spawn (Office → PowerShell) | Yes |

---

## 6. Roadmap

- [x] Sigma rule engine — PowerShell detection
- [x] Ransomware behavioral detector
- [x] Multi-format syslog support (RFC 3164, RFC 5424, CEF, NXLog, Winlogbeat)
- [x] Process tree — parent→child modeling
- [x] 8 LOTL rules with MITRE ATT&CK tagging
- [x] Multi-file Sigma loader per domain
- [x] Windows persistence detection (registry Run, WMI sub, startup)
- [x] Privilege escalation detection (admin group, UAC bypass, credential dump)
- [x] Linux command detection (chmod +s, cron, reverse shell)
- [ ] Extended Linux detection — auditd, PAM, systemd (v5)
- [ ] Signal deduplication + aggregated scoring (v5.5)
- [ ] Deferred enrichment — URLVoid, WHOIS, IP geolocation (v6)
- [ ] Legitimacy baseline to reduce false positives (v7)
- [ ] SOAR — automated response (v8)

---

## 7. References

- MITRE ATT&CK: T1059.001 (PowerShell), T1486 (Ransomware), T1490 (Shadow Copy), T1047 (WMI), T1218 (LOLBIN), T1547.001 (Registry Run), T1548.002 (UAC Bypass), T1003 (Credential Dumping)
- Sigma rule specification: https://github.com/SigmaHQ/sigma
- Sysmon logging format: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Windows Event ID 4104 — Script Block Logging
- LOLBAS Project: https://lolbas-project.github.io
- GTFOBins (Linux): https://gtfobins.github.io

---

> **Defensive & educational content only.**  
> Built in an isolated lab environment. No live systems were used.
