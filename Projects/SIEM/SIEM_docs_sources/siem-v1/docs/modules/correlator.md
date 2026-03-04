# Corrélation & Export

## correlator.py

### Politique de corrélation v1

Le corrélateur v1 implémente une politique simple et déterministe : tout Signal de type `ransomware_behavior` avec un score suffisant génère une Alert.

```python
def correlate(signals: List[Signal]) -> List[Alert]:
    for s in signals:
        if s.signal_type != "ransomware_behavior":
            continue  # seuls les signaux ransomware sont promus
        if s.score < 0.3:
            continue  # seuil minimal
        ...
```

!!! note "PowerShell non promu en v1"
    Les signaux PowerShell (`ps.*`) ne génèrent pas d'Alerts en v1. Ils apparaissent dans `signals.jsonl` mais pas dans `alerts.jsonl`. C'est une limitation délibérée : la corrélation multi-signal (ransomware + PowerShell sur le même host) est prévue pour v2.

### Calcul de sévérité

```python
def _severity_from_score(score: float) -> str:
    if score >= 0.85: return "critical"
    if score >= 0.60: return "high"
    if score >= 0.40: return "medium"
    return "low"
```

### Structure d'une Alert

```python
Alert(
    alert_id   = f"ALERT_{s.signal_id}",
    title      = f"Possible ransomware activity ({severity})",
    severity   = severity,
    confidence = s.confidence,
    host       = s.host,
    process_key = s.process_key,
    summary    = f"Ransomware heuristic score={s.score:.2f}",
    reasoning  = [f"Risk factor matched: {rf}" for rf in s.risk_factors] + [s.explanation],
    timeline_event_ids = s.evidence_event_ids,
    suggested_actions  = s.recommended_actions,
    related_signals    = [s.signal_id],
)
```

---

## reporter.py

### Artefacts produits

`export(out_dir, events, signals, alerts)` écrit quatre types de fichiers :

#### normalized_events.jsonl

Tous les `CanonicalEvent` sérialisés. Utile pour :
- Rejouer l'analyse avec des règles modifiées
- Alimenter un autre outil (Elastic, Splunk) avec des données normalisées
- Audit et forensique post-incident

#### signals.jsonl

Tous les `Signal` produits par les détecteurs, y compris ceux non promus en alerte.

#### alerts.jsonl

Uniquement les `Alert` — c'est ce fichier qui doit être consommé par le SOC en priorité.

#### timeline_ALERT_*.jsonl

Un fichier par alerte, contenant les événements qui la composent triés chronologiquement :

```json
[
  {
    "event_id": "abc123",
    "event_time_utc": "2024-01-15T12:00:01Z",
    "event_type": "process",
    "process_name": "powershell.exe",
    "pid": 4288,
    "operation": null,
    "file_path": null,
    "dest_ip": null,
    "dest_port": null
  },
  {
    "event_id": "def456",
    "event_time_utc": "2024-01-15T12:00:05Z",
    "event_type": "file",
    "process_name": "powershell.exe",
    "pid": 4288,
    "operation": "write",
    "file_path": "C:/Users/victim/important.docx.encrypted",
    ...
  }
]
```

Ces timelines sont directement exploitables pour une reconstruction de kill chain sans outil supplémentaire.
