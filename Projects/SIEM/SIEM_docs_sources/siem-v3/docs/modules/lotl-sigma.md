# Détection LOTL — lotl_sigma.py

## Vue d'ensemble

`lotl_sigma.py` implémente la détection des binaires *Living off the Land* (LOTL) — des exécutables légitimes Windows détournés par des attaquants pour exécuter du code malveillant en contournant les défenses basées sur les signatures.

Le module combine trois types de détection :
1. **Pattern CommandLine** — regex sur les arguments passés aux binaires LOTL
2. **EventID** — détection par code d'événement (4698/4699/4702 pour les tâches planifiées)
3. **Spawn suspects** — via `ProcessTree`

## Structure d'une règle LOTL

```python
@dataclass(frozen=True)
class LotlRule:
    rule_id: str              # ex: "LOTL-001"
    name: str                 # ex: "vssadmin Shadow Copy Deletion"
    image_match: str          # basename à matcher, ex: "vssadmin.exe"
    cl_patterns: Tuple[str, ...]  # regex — ANY match déclenche la règle
    score: float              # 0.0–1.0
    confidence: float         # 0.0–1.0
    mitre_tactic: str         # ex: "Impact"
    mitre_technique: str      # ex: "T1490"
    recommendation: str
    risk_label: str
```

## Calcul du signal_id

```python
def _signal_id(signal_type, event_id, extra=""):
    blob = f"{signal_type}|{event_id}|{extra}".encode("utf-8")
    return "sig-" + hashlib.sha256(blob).hexdigest()[:16]
```

Déterministe : le même événement déclenchant la même règle produit toujours le même `signal_id`.

## Fonctions de détection

### `_run_cmdline_rules(events)`

Applique chaque `LotlRule` à chaque événement dont `event_type` est `process` ou `other`.

```python
for ev in events:
    img = _image(ev)     # basename de process.image_path
    cl = _cl(ev)         # command_line lowercase

    for rule, patterns in compiled:
        if rule.image_match and img != rule.image_match:
            continue  # filtrage rapide par image
        if any(p.search(cl) for p in patterns):
            # émet un Signal
            break  # une seule règle par événement (première qui match)
```

Le `break` après le premier match évite les doublons si plusieurs règles ciblent le même binaire.

### `_run_eventid_rules(events)`

Détecte les EventID de tâches planifiées (4698/4699/4702) sans analyse de CommandLine.

```python
_EVENTID_RULES = {
    "4698": (0.70, 0.65, "Scheduled Task Created", "Persistence", "T1053.005"),
    "4699": (0.65, 0.60, "Scheduled Task Deleted", "Defense Evasion", "T1053.005"),
    "4702": (0.55, 0.50, "Scheduled Task Modified", "Persistence", "T1053.005"),
}
```

Le nom de la tâche est extrait depuis `ev.raw` via plusieurs chemins possibles (NXLog, Winlogbeat, flat) :

```python
task_name = (
    ev.raw.get("TaskName") or
    ev.raw.get("event_data", {}).get("TaskName") or
    ev.raw.get("EventData", {}).get("TaskName") or
    "unknown_task"
)
```

### `_run_spawn_rules(events, tree)`

Délègue à `tree.all_suspicious_spawns(events)` et crée un Signal pour chaque paire suspecte trouvée.

```python
for spawn in tree.all_suspicious_spawns(events):
    ev = next((e for e in events if e.event_id == spawn["event_id"]), None)
    signals.append(_make_signal(
        signal_type="lotl.spawn_suspect",
        mitre_tactic="Execution",
        mitre_technique="T1059",
        score=0.78, confidence=0.72,
        ...
    ))
```

## API

### `run(events, tree=None) -> List[Signal]`

Point d'entrée principal. Exécute les trois détecteurs avec isolation d'erreurs :

```python
for detector_fn, label in [
    (lambda: _run_cmdline_rules(events), "cmdline"),
    (lambda: _run_eventid_rules(events), "eventid"),
    (lambda: _run_spawn_rules(events, tree), "spawn"),
]:
    try:
        signals.extend(detector_fn())
    except Exception as exc:
        print(f"[lotl_sigma] ERROR in {label}: {exc}", file=sys.stderr)
```

Le paramètre `tree` est optionnel — si `None`, le détecteur de spawns est ignoré silencieusement.
