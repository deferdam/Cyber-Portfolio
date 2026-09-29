# Mini SIEM, Sigma-Based Detection Engine

> Behavioral detection engine built for learning and lab use.
> Defensive scope only. No malware binaries hosted.

---

## 1. Executive Summary

Mini SIEM v6 adds local AI service integrity detection (Ollama, LM Studio, llama.cpp, vLLM, LocalAI), using MITRE ATLAS instead of MITRE ATT&CK for this domain.

It does not rely on hash signatures. It detects behavior patterns, which means it catches obfuscated or renamed variants that signature-based tools miss.

The engine analyzes:
- Windows Event Logs, syslog RFC 3164/5424, CEF, NXLog and Winlogbeat
- PowerShell Script Blocks (EventID 4104): obfuscation, AMSI bypass, download cradles
- Persistence mechanisms: registry Run keys, WMI subscription, startup folder, inline schtasks
- Privilege escalation: admin group manipulation, UAC bypass, credential dumping
- Suspicious Linux/Unix commands: chmod +s, cron, curl pipe bash, reverse shells
- Auditd kernel-level events: EXECVE, SYSCALL, PATH
- Linux authentication logs: SSH, PAM, sudo
- Local AI service integrity: model replacement, port swap, local MITM
- Parent-child process relationships and LOTL binaries

Current detection coverage:
- Suspicious PowerShell execution: 4 Sigma files by domain
- Ransomware behavioral patterns (Windows and Linux)
- LOTL binaries (8 rules, MITRE ATT&CK)
- Windows persistence: 6 techniques detected
- Windows privilege escalation: 5 techniques detected
- Linux commands: 8 detection categories
- Auditd kernel-level: sensitive file access, chmod setuid, account creation, memory injection
- Linux auth: SSH brute force, root login, dangerous sudo, authorized_keys modification
- Offensive tools: credential tools, lateral movement, tunneling, network sniffers
- Local AI: model file integrity, port/process anomaly, local MITM proxy

**Status: v6 complete. v7 in development (legitimacy baseline).**

---

## 2. Architecture

```
Log sources (Windows / Sysmon / PowerShell / RFC 3164 / RFC 5424 / CEF / NXLog / Winlogbeat
             auditd EXECVE/SYSCALL/PATH / auth.log PAM/SSH/sudo
             local AI service logs: Ollama, LM Studio, llama.cpp, vLLM, LocalAI)
    |
Syslog parser: auto-format detection
    |
Normalizer v5: source-based routing
  |- auditd  -> EXECVE args reconstruction (a0/a1/a2...), hex decoding, uid/auid mapping
  |- auth    -> syslog message parsing (SSH/sudo/PAM regex)
  |- others  -> unchanged v4 path (Windows/Sysmon/generic)
    |
CanonicalEvent (immutable)
    |
OS-conditional detection (platform.system())
  |- Windows
  |     |- Layer 1 Signature    : ransomware_v4
  |     |- Layer 2 Behavioral   : powershell_sigma (4 YAML) + lotl_sigma + spawn suspects
  |     |- Layer 3 Correlation  : temporal recon -> exec sequences
  |- Linux
        |- Layer 1 Signature    : ransomware_linux
        |- Layer 2 Behavioral   : bash_sigma (3 YAML) + linux_auditd
        |- Layer 3 Auth correl. : linux_auth (temporal brute force)
    |
Local AI detection (unconditional, Windows AND Linux)
  |- ai_network   : port swap, unexpected process on AI port, local MITM
  |- ai_integrity : model file hashing (.gguf/.bin/.safetensors), self-learned baseline
    |
Deduplicator: redundant Signal merging + score aggregation (max + 0.05 per source)
    |
Correlator: signal aggregation into alerts with severity
    |
JSONL output (events, signals, alerts, timelines)
```

### Modules

| Module | Purpose |
|--------|---------|
| `syslog_parser.py` | Parses RFC 3164, RFC 5424, CEF, JSON NXLog/Winlogbeat |
| `normalizer.py` | Source-based routing: auditd / auth / generic -> CanonicalEvent |
| `process_tree.py` | Builds parent->child index, detects suspicious spawns |
| `lotl_sigma.py` | 8 LOTL rules + EventID 4698/4699 + spawn suspects |
| `powershell_sigma.py` | Multi-file Sigma YAML loader (Windows) |
| `bash_sigma.py` | Multi-file Sigma YAML loader (Linux) |
| `linux_auditd.py` | 5 auditd detectors: sensitive files, chmod setuid, useradd, connect, EXECVE |
| `linux_auth.py` | 4 auth detectors: SSH brute force, root login, sudo, authorized_keys |
| `ransomware_linux.py` | Linux-adapted ransomware detection (/tmp, uid=0, encryption tools) |
| `ai_baseline.py` | Pre-trained AI baselines (Ollama, LM Studio...) + anti-poisoning learning |
| `ai_network.py` | Port swap detection, unexpected process on AI port, local MITM |
| `ai_integrity.py` | Model file hashing, replacement detection (poisoned/backdoored model) |
| `deduplicator.py` | Signal merging on shared event_id, score = max + 0.05 x (n sources - 1) |
| `engine.py` | OS-conditional dispatch + unconditional AI detection + deduplication |
| `correlator.py` | Signals -> Alerts with calculated severity |
| `reporter.py` | JSONL export: events, signals, alerts, timelines |

### Sigma Files

| File | OS | Domain | Techniques |
|------|-----|--------|-----------|
| `ps_scriptblock.yaml` | Windows | Script Block 4104: encoding, IEX, AMSI, recon | T1059.001, T1027, T1562 |
| `ps_persistence.yaml` | Windows | Registry Run, WMI sub, startup, inline schtasks | T1547.001, T1053.005, T1546.003 |
| `ps_privilege_escalation.yaml` | Windows | Admin group add, UAC bypass, credential dump | T1098, T1548.002, T1003 |
| `linux_suspicious.yaml` | Linux | chmod +s, cron, curl pipe bash, reverse shell | T1059.004, T1053.003, T1222.002 |
| `linux_auditd.yaml` | Linux | Privesc tools, container escape, kernel exploits, LD_PRELOAD | T1548, T1003, T1574.006, T1543.002 |
| `linux_auth.yaml` | Linux | SSH failure, root login, dangerous sudo, authorized_keys | T1110, T1078.003, T1548.003 |
| `ai_model_integrity.yaml` | Windows/Linux | Model file writes, bind on known AI ports | AML.T0018, AML.T0012 |

---

## 3. Local AI Detection (v6)

### Covered Frameworks (pre-trained baselines)

| Framework | Default Port | Model Paths |
|-----------|--------------|-------------|
| Ollama | 11434 | `~/.ollama/models/` |
| LM Studio | 1234 | `~/LM Studio/models/` |
| llama.cpp (llama-server) | 8080 | `/opt/models/`, `~/models/` |
| vLLM | 8000 | `/opt/vllm/models/` |
| LocalAI | 8080 | `/usr/share/local-ai/models/` |

### Detectors

| Indicator | ATLAS Technique | Score |
|-----------|-----------------|-------|
| Unexpected process binding known AI port (server replacement) | AML.T0012 | 0.90 |
| Unexpected process connecting to known AI port (local MITM proxy) | AML.T0040 | 0.70 |
| Model file hash modified (poisoned/backdoored model) | AML.T0018 | 0.92 |

### Baseline Anti-Poisoning

Auto-learning (`ai_baseline.observe()`) only records an observation if it matches a pre-trained framework (expected process_name AND port). An observation outside the pre-trained baseline triggers an immediate signal and is **never** learned, preventing baseline poisoning if a MITM is already active at first run.

---

## 4. Detection Rules, v5/v6

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

### Windows Privilege Escalation

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
| `\| bash` / `\| sh` (pipe exec) | T1059.004 |
| `bash -i >& /dev/tcp` (reverse shell) | T1059.004 |
| Write to `/etc/passwd` / `/etc/shadow` | T1098 |
| `setenforce 0` / `ufw disable` | T1562.001 |

### Auditd Kernel-Level Detection

| Indicator | MITRE Technique |
|-----------|----------------|
| Access to `/etc/shadow`, `/etc/sudoers`, `authorized_keys` | T1003.008 |
| chmod syscall with mode 4xxx/6xxx (setuid/setgid) | T1548.001 |
| `useradd -o -u 0` (root clone) | T1136.001 |
| `connect()` syscall from bash/python/perl | T1071.001 |
| `/dev/tcp/`, `nc -e /bin/bash`, `socat EXEC` | T1059.004 |
| `LD_PRELOAD=`, `/etc/ld.so.preload` | T1574.006 |
| `dirtycow`, `dirty_pipe`, `CVE-2022-0847` | T1068 |
| `mimipenguin`, `lazagne`, `linpeas`, `pspy` | T1003 |
| `bloodhound`, `crackmapexec`, `kerbrute` | T1087 |
| `chisel`, `ligolo`, `frpc` (tunneling) | T1572 |

### Linux Auth Detection

| Indicator | Threshold / MITRE Technique |
|-----------|---------------------------|
| SSH brute force | 5 failures within 120 seconds, T1110.001 |
| Direct SSH root login | Single occurrence, T1078.003 |
| `sudo /bin/bash`, `sudo -s`, `sudo /usr/bin/vim` | Dangerous command, T1548.003 |
| `authorized_keys` modification | Write/create operation, T1098.004 |

---

## 5. Limitations

| Limitation | Detail |
|------------|--------|
| Lab environment only | Not tested against production log volumes |
| Requires proper log ingestion | Sysmon (Windows) and auditd (Linux) must be enabled |
| No general legitimacy baseline | False positives on admin activity and deployments |
| No blocking capability | Detection and alerting only, no automated response |
| Evasion possible | Advanced actors can bypass behavioral rules |
| `systemctl enable`: high FP rate | Requires correlation with other signals before action |
| Local AI: post-compromise detection only | Does not detect MITM installation, only its active presence |
| Local AI: baseline covers 5 frameworks | Custom/in-house frameworks not covered by default |

---

## 6. Threat Model

| Behavior | Detected |
|----------|----------|
| Obfuscated PowerShell execution | Yes |
| Remote payload download | Yes |
| In-memory execution (fileless) | Partial |
| AMSI bypass | Yes |
| Fast / slow ransomware | Yes (Windows + Linux) |
| Shadow copy deletion | Yes |
| Registry Run persistence | Yes |
| WMI Event Subscription persistence | Yes |
| Systemd service persistence | Yes |
| Local / domain admin group add | Yes |
| UAC bypass (fodhelper, eventvwr) | Yes |
| Credential dump (Mimikatz / mimipenguin) | Yes |
| Linux reverse shell | Yes |
| chmod +s setuid escalation | Yes |
| Lateral movement via WMI | Yes |
| SSH brute force | Yes (temporal correlation) |
| Direct SSH root login | Yes |
| Offensive Linux tools (bloodhound, chisel...) | Yes |
| Kernel exploit (DirtyCow, Dirty Pipe) | Yes (by name) |
| Container escape | Yes |
| Suspicious spawn (Office -> PowerShell) | Yes |
| Redundant signals merged | Yes (deduplicator v5.5) |
| Local AI model replacement | Yes (hash mismatch) |
| Local AI service port swap | Yes |
| Local AI MITM proxy | Yes (post-compromise) |

---

## 7. Roadmap

- [x] Sigma rule engine, PowerShell detection
- [x] Ransomware behavioral detector (Windows)
- [x] Multi-format syslog support (RFC 3164, RFC 5424, CEF, NXLog, Winlogbeat)
- [x] Process tree, parent->child modeling
- [x] 8 LOTL rules with MITRE ATT&CK tagging
- [x] Multi-file Sigma loader per domain
- [x] Windows persistence detection (registry Run, WMI sub, startup)
- [x] Windows privilege escalation detection (admin group, UAC bypass, credential dump)
- [x] Linux command detection (chmod +s, cron, reverse shell)
- [x] Extended Linux detection: auditd, PAM, systemd (v5)
- [x] Auditd normalization: EXECVE args reconstruction, hex decoding, source routing
- [x] Linux ransomware detector (/tmp, uid=0, encryption tools, ransom notes)
- [x] Sigma rules: linux_auditd.yaml (kernel exploits, offensive tools, tunneling)
- [x] Signal deduplication + aggregated scoring (v5.5)
- [x] Local AI integrity detection: ai_network, ai_integrity, pre-trained baselines (v6)
- [x] Local AI MITM detection (port swap, unexpected process)
- [ ] Legitimacy baseline to reduce false positives (v7)
- [ ] SOAR: automated response (v8)

---

## 8. References

- MITRE ATT&CK: T1059.001 (PowerShell), T1486 (Ransomware), T1490 (Shadow Copy), T1047 (WMI), T1218 (LOLBIN), T1547.001 (Registry Run), T1548.002 (UAC Bypass), T1003 (Credential Dumping), T1068 (Kernel Exploit), T1572 (Tunneling)
- MITRE ATLAS: AML.T0012 (Valid Accounts - local pivot), AML.T0018 (Backdoor ML Model), AML.T0040 (Network Traffic Capture)
- Sigma rule specification: https://github.com/SigmaHQ/sigma
- Sysmon logging format: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Windows Event ID 4104: Script Block Logging
- RFC 3164 / RFC 5424: Syslog Protocol
- Linux auditd documentation: https://linux.die.net/man/8/auditd
- MITRE ATT&CK Framework: https://attack.mitre.org
- MITRE ATLAS Framework: https://atlas.mitre.org

---

> **Defensive & educational content only.**
> Built in an isolated lab environment. No live systems were used.
