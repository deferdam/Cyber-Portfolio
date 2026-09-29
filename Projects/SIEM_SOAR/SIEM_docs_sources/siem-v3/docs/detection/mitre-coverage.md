# Couverture MITRE ATT&CK

## Matrice de couverture v2

| Tactique | Technique | ID | Module | Score max |
|----------|-----------|----|--------|-----------|
| **Initial Access** | — | — | — | — |
| **Execution** | Command and Scripting Interpreter: PowerShell | T1059.001 | powershell_sigma | 0.85 |
| **Execution** | Command and Scripting Interpreter: Windows CMD | T1059.003 | lotl_sigma (spawn) | 0.78 |
| **Execution** | Windows Management Instrumentation | T1047 | lotl_sigma LOTL-002 | 0.80 |
| **Execution** | System Binary Proxy: Mshta | T1218.005 | lotl_sigma LOTL-003 | 0.85 |
| **Execution** | System Binary Proxy: Regsvr32 | T1218.010 | lotl_sigma LOTL-008 | 0.88 |
| **Execution** | System Binary Proxy: Rundll32 | T1218.011 | lotl_sigma LOTL-005 | 0.78 |
| **Persistence** | Scheduled Task/Job: Scheduled Task | T1053.005 | lotl_sigma LOTL-006 | 0.75 |
| **Persistence** | Scheduled Task/Job: At | T1053.002 | lotl_sigma LOTL-007b | 0.60 |
| **Persistence** | Scheduled Task/Job: Cron | T1053.003 | lotl_sigma LOTL-007 | 0.70 |
| **Defense Evasion** | Deobfuscate/Decode Files | T1140 | lotl_sigma LOTL-004 | 0.82 |
| **Defense Evasion** | System Binary Proxy: Mshta | T1218.005 | lotl_sigma LOTL-003 | 0.85 |
| **Defense Evasion** | System Binary Proxy: Rundll32 | T1218.011 | lotl_sigma LOTL-005 | 0.78 |
| **Defense Evasion** | System Binary Proxy: Regsvr32 | T1218.010 | lotl_sigma LOTL-008 | 0.88 |
| **Defense Evasion** | Obfuscated Files or Information | T1027 | powershell_sigma | 0.70 |
| **Discovery** | System Information Discovery | T1082 | lotl_sigma LOTL-001b/002b | 0.50 |
| **Discovery** | Account Discovery | T1087 | powershell_sigma (recon) | 0.80 |
| **Lateral Movement** | Windows Management Instrumentation | T1047 | lotl_sigma LOTL-002 | 0.80 |
| **Command and Control** | Ingress Tool Transfer | T1105 | lotl_sigma LOTL-004 | 0.82 |
| **Command and Control** | Web Protocols | T1071.001 | powershell_sigma (download cradle) | 0.75 |
| **Impact** | Inhibit System Recovery | T1490 | lotl_sigma LOTL-001 | 0.92 |
| **Impact** | Data Encrypted for Impact | T1486 | ransomware_v4 | 1.00 |

## Lacunes identifiées

| Tactique | Technique | ID | Raison de l'absence |
|----------|-----------|----|---------------------|
| Credential Access | OS Credential Dumping | T1003 | Pas de détection LSASS / mimikatz |
| Credential Access | Credentials from Password Stores | T1555 | Non implémenté |
| Discovery | Network Scanning | T1046 | Pas d'analyse de flux réseau |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | Non implémenté |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Détection C2 partielle (IP non privées) |
| Collection | Archive Collected Data | T1560 | Non implémenté |

## Kill chains couvertes

### Ransomware (couverture élevée)

```
T1059.001 PowerShell dropper
    ↓
T1140 certutil decode payload
    ↓
T1490 vssadmin delete shadows       ← Signal critique 0.92
    ↓
T1486 mass file encryption          ← Alert critical
```

### Macro Office → Backdoor (couverture partielle)

```
T1059.001 Maldoc macro → powershell (spawn suspect)  ← Signal 0.78
    ↓
T1053.005 schtasks persistence                        ← Signal 0.75
    ↓
T1047 wmic lateral movement                           ← Signal 0.80
```

!!! info "Corrélation automatique v3"
    La détection automatique des kill chains multi-tactiques sera implémentée en v3. En v2, les Signals MITRE sont disponibles dans `signals.jsonl` pour une corrélation manuelle ou via un outil externe (Elastic, Splunk).

## Requêtes Splunk complémentaires

Les requêtes Splunk suivantes complètent la détection SIEM pour les mêmes techniques.

### PowerShell suspicious (T1059.001)

```spl
index=wineventlog OR index=sysmon (EventCode=4688 OR EventCode=1 OR EventCode=4104)
(CommandLine="*IEX*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*-Exec Bypass*"
 OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*DownloadString*")
| stats count values(Host) as hosts values(User) as users by CommandLine
```

### WMIC lateral movement (T1047)

```spl
index=sysmon OR index=wineventlog (EventCode=1 OR EventCode=4688)
(CommandLine="*wmic*process call create*" OR CommandLine="*wmic /node:*")
| stats count values(Host) as hosts values(ParentImage) as parents by CommandLine
```

### Scheduled task creation (T1053.005)

```spl
index=wineventlog (EventCode=4698 OR EventCode=4699)
OR index=sysmon EventCode=1 CommandLine="*schtasks* /Create*"
| stats count by host, user, EventCode, TaskName, CommandLine
```
