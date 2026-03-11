# Interpréter les signaux v2

## Nouveaux champs MITRE ATT&CK

En v2, chaque Signal porte deux nouveaux champs :

```json
{
  "signal_id":      "sig-a1b2c3d4e5f6a7b8",
  "signal_type":    "lotl.LOTL-001",
  "mitre_tactic":   "Impact",
  "mitre_technique":"T1490",
  "score":          0.92,
  "confidence":     0.90,
  "risk_factors":   ["shadow-copy-deletion", "image:vssadmin.exe", "rule:vssadmin Shadow Copy Deletion"],
  "evidence_event_ids": ["abc123def456..."],
  "explanation":    "[LOTL-001] vssadmin Shadow Copy Deletion detected. Image: vssadmin.exe | CommandLine: vssadmin delete shadows /all /quiet | User: SYSTEM | Host: WIN-SRV01",
  "recommended_actions": ["Isoler la machine immédiatement. Ransomware pre-encryption step."]
}
```

## Décoder le signal_type

| Préfixe | Module | Couche |
|---------|--------|--------|
| `ransomware_behavior` | ransomware_v4 | Signature |
| `ps.` | powershell_sigma | Behavioral |
| `ps.recon_sequence` | powershell_sigma | Corrélation |
| `lotl.LOTL-XXX` | lotl_sigma | Behavioral |
| `lotl.scheduled_task.*` | lotl_sigma | Behavioral (EventID) |
| `lotl.spawn_suspect` | lotl_sigma + process_tree | Behavioral |

## Trier les signaux par priorité

```bash
# Signaux par score décroissant
cat out/signals.jsonl | python -c "
import json, sys
sigs = [json.loads(l) for l in sys.stdin if l.strip()]
for s in sorted(sigs, key=lambda x: -x['score']):
    print(f\"{s['score']:.2f} [{s['mitre_technique']:12}] {s['signal_type']} - {s['host']['hostname']}\")
"
```

## Regrouper par tactique MITRE

```bash
cat out/signals.jsonl | python -c "
import json, sys
from collections import defaultdict
by_tactic = defaultdict(list)
for line in sys.stdin:
    if line.strip():
        s = json.loads(line)
        by_tactic[s.get('mitre_tactic', 'Unknown')].append(s)
for tactic, sigs in sorted(by_tactic.items()):
    print(f'\n=== {tactic} ({len(sigs)} signals) ===')
    for s in sorted(sigs, key=lambda x: -x['score']):
        print(f'  {s[\"score\"]:.2f} {s[\"mitre_technique\"]} {s[\"signal_type\"]}')
"
```

## Signaux de spawn suspect

```json
{
  "signal_type": "lotl.spawn_suspect",
  "mitre_tactic": "Execution",
  "mitre_technique": "T1059",
  "score": 0.78,
  "risk_factors": ["parent:winword.exe", "child:powershell.exe", "spawn_suspect_pair"],
  "explanation": "Suspicious spawn: winword.exe → powershell.exe | CommandLine: powershell -enc SGVsbG8= | User: jdoe | Host: WIN-SRV01"
}
```

Le champ `explanation` contient toujours : parent image → child image, CommandLine, User, Host.

## Signaux de tâche planifiée (EventID)

```json
{
  "signal_type": "lotl.scheduled_task.4698",
  "mitre_tactic": "Persistence",
  "mitre_technique": "T1053.005",
  "score": 0.70,
  "risk_factors": ["event_code:4698", "task:MicrosoftUpdateHelper"],
  "explanation": "Scheduled Task Created (EventID 4698) | Task: MicrosoftUpdateHelper | User: jdoe | Host: WIN-SRV01"
}
```

!!! tip "Corrélation manuelle"
    Un EventID 4698 isolé peut être légitime. Croiser avec un Signal `lotl.LOTL-006` (schtasks /Create) sur le même host dans la même fenêtre temporelle augmente significativement la confidence.
