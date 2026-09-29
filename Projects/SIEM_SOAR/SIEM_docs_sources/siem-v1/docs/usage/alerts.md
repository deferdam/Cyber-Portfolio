# Interpréter les alertes

## Lecture d'une alerte

```json
{
  "alert_id":   "ALERT_rw_powershell.exe|4288|c:/windows/system32/...",
  "title":      "Possible ransomware activity (critical)",
  "severity":   "critical",
  "confidence": 0.92,
  "host":       {"hostname": "WIN-SRV01"},
  "process_key":"powershell.exe|4288|c:/windows/system32/...",
  "summary":    "Ransomware heuristic score=0.92 confidence=0.92",
  "reasoning": [
    "Risk factor matched: mass_file_write",
    "Risk factor matched: vss_deletion",
    "Risk factor matched: suspicious_extension",
    "Process powershell.exe (PID 4288): 45 unique files written in 60s..."
  ],
  "suggested_actions": [
    "Isoler la machine WIN-SRV01 du réseau",
    "Lancer une analyse forensique mémoire sur PID 4288",
    "Vérifier les derniers fichiers modifiés"
  ]
}
```

### Décoder le process_key

Le `process_key` est au format `name|pid|path` (tout en minuscules) :

```
powershell.exe|4288|c:/windows/system32/windowspowershell/v1.0/powershell.exe
```

### Décoder l'alert_id

```
ALERT_rw_powershell.exe|4288|...
       ↑                ↑
       "rw_" = ransomware signal
                        process_key
```

## Matrice sévérité / action

| Sévérité | Score | Délai d'action | Premières actions |
|----------|-------|----------------|-------------------|
| `critical` | ≥ 0.85 | **Immédiat** | Isolation réseau, snapshot mémoire |
| `high` | 0.60–0.84 | < 1 heure | Investigation, collecte d'artefacts |
| `medium` | 0.40–0.59 | < 4 heures | Analyse des logs, corrélation manuelle |
| `low` | 0.30–0.39 | Planifié | Surveillance renforcée, baseline check |

## Utiliser les timelines

Pour chaque alerte, un fichier `timeline_ALERT_*.jsonl` est produit :

```bash
# Afficher la timeline d'une alerte
cat out/large/timeline_ALERT_rw_*.jsonl | python -m json.tool
```

La timeline contient les événements sources triés par `event_time_utc`, ce qui permet de reconstruire la séquence exacte des actions du processus suspect.

## Signaux sans alerte

Les signaux PowerShell (`ps.*`) apparaissent dans `signals.jsonl` mais pas dans `alerts.jsonl` en v1. Pour les consulter :

```bash
# Lister tous les signaux PowerShell
grep '"signal_type": "ps\.' out/large/signals.jsonl
```

Ces signaux sont des indicateurs à corréler manuellement avec d'autres événements sur le même host.
