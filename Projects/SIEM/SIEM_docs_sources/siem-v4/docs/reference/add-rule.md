# Ajouter une règle Sigma

## Procédure complète en 3 étapes

### Étape 1 — Créer le fichier YAML

```yaml
# src/detect/modules/ps_mon_domaine.yaml
title: Mon titre descriptif
id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx  # UUID v4 unique
description: Ce que détecte cette règle
status: experimental
author: Ton nom
date: 2026-XX-XX
logsource:
    product: windows
    service: powershell
    EventID: 4104

detection:
    selection_mon_pattern:
        ScriptBlockText|contains:
            - 'pattern1'
            - 'pattern2'
    condition: 1 of selection_*

falsepositives:
    - Cas légitimes connus

level: high  # low / medium / high / critical

tags:
    - attack.tactic_name
    - attack.tXXXX
```

### Étape 2 — Ajouter dans engine.py

```python
# src/detect/engine.py
_PS_RULE_FILES = [
    str(_MODULES_DIR / "ps_scriptblock.yaml"),
    str(_MODULES_DIR / "ps_persistence.yaml"),
    str(_MODULES_DIR / "ps_privilege_escalation.yaml"),
    str(_MODULES_DIR / "ps_mon_domaine.yaml"),     # ← ici
    str(_MODULES_DIR / "powershell_suspicious.yaml"),
]
```

### Étape 3 — Tester

```bash
# Créer un event de test
echo '{"timestamp":"2024-01-15T12:00:00Z","host":"TEST","event_type":"other","source":"powershell","raw":{"ScriptBlockText":"pattern1 et pattern2 dans le même script"}}' > test_event.jsonl

cd SIEM
set PYTHONPATH=src
python -m ingest.replay --format json --input test_event.jsonl --out-dir out/test

# Vérifier le signal
cat out/test/signals.jsonl | python -m json.tool | grep -A5 "mon_domaine\|mon titre"
```

## Checklist avant validation

- [ ] L'UUID est unique (générer avec `python -c "import uuid; print(uuid.uuid4())"`)
- [ ] Les patterns sont testés sur des événements réels (pas de faux positifs immédiats)
- [ ] Les faux positifs connus sont documentés
- [ ] Le tag MITRE ATT&CK est correct et vérifié sur https://attack.mitre.org
- [ ] Le niveau (`level`) reflète la réalité (ne pas tout mettre `high`)
