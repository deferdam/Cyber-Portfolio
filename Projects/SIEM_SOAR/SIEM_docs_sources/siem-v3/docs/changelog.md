# Changelog v1 → v2

## Résumé des changements

### Nouveaux fichiers

| Fichier | Rôle |
|---------|------|
| `src/ingest/syslog_parser.py` | Parseur syslog multi-format (RFC 3164, RFC 5424, CEF, JSON) |
| `src/normalize/process_tree.py` | Modélisation des relations parent→enfant |
| `src/detect/modules/lotl_sigma.py` | 8 règles LOTL avec MITRE ATT&CK tagging |

### Fichiers modifiés

| Fichier | Changement |
|---------|-----------|
| `src/core/schemas.py` | `Signal` : ajout `mitre_tactic: str` et `mitre_technique: str` |
| `src/detect/engine.py` | Architecture 3 couches + isolation d'erreurs + process tree |
| `src/ingest/replay.py` | Flag `--format [json|syslog|auto]` + support stdin (`--input -`) |
| `run_siem.bat` | Activation automatique `auditpol` + mode `syslog` |

---

## Détail par composant

### schemas.py — Signal enrichi MITRE

```python
# Avant (v1)
@dataclass(frozen=True)
class Signal:
    signal_id: str
    signal_type: str
    ...
    recommended_actions: List[str]

# Après (v2) — deux champs ajoutés
@dataclass(frozen=True)
class Signal:
    ...
    recommended_actions: List[str]
    mitre_tactic: str = ""      # ex: "Execution", "Lateral Movement"
    mitre_technique: str = ""   # ex: "T1059.001", "T1218.005"
```

Les champs ont une valeur par défaut `""` — rétrocompatibilité totale avec les Signals existants (ransomware, PowerShell) qui ne les renseignent pas.

---

### engine.py — Architecture 3 couches

```python
# v1 — plat, sans isolation
def run_all(events):
    signals.extend(ransomware_v4.run(events))
    ps_signals = powershell_sigma.run(events, rule_path="...")
    signals.extend(ps_signals)
    signals.extend(powershell_sigma.correlate_recon_sequence(events, ps_signals))
    return signals

# v2 — couches explicites, try/except par couche, process tree partagé
def run_all(events):
    tree = build_tree(events)           # pré-calcul partagé

    # Couche 1 : Signature
    try: signals.extend(ransomware_v4.run(events))
    except Exception as e: log(e)

    # Couche 2 : Behavioral
    try:
        ps_signals = powershell_sigma.run(events, ...)
        signals.extend(ps_signals)
    except Exception as e: log(e); ps_signals = []

    try: signals.extend(lotl_sigma.run(events, tree=tree))
    except Exception as e: log(e)

    # Couche 3 : Corrélation
    try: signals.extend(powershell_sigma.correlate_recon_sequence(events, ps_signals))
    except Exception as e: log(e)

    return signals
```

**Impact** : une règle LOTL défaillante (ex : regex invalide) n'interrompt plus le pipeline entier.

---

### replay.py — Multi-format + stdin

```bash
# v1
python -m ingest.replay --input events.jsonl --out-dir out/

# v2 — --format est nouveau, --input - est nouveau
python -m ingest.replay --format json   --input events.jsonl   --out-dir out/
python -m ingest.replay --format syslog --input security.log   --out-dir out/
python -m ingest.replay --format auto   --input mixed.log      --out-dir out/
cat live.log | python -m ingest.replay  --format syslog --input - --out-dir out/
```

Le mode `auto` (défaut) tente JSON d'abord, puis syslog par ligne. Il assure la rétrocompatibilité totale : un pipeline v1 existant fonctionne sans modification.

---

### run_siem.bat — auditpol automatique

```bat
# Nouveau dans v2 — activé si le script est lancé en Administrateur
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
reg add "HKLM\...\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
auditpol /set /subcategory:"Process Termination" /success:enable /failure:disable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

Si le script n'est pas lancé en Administrateur, les commandes `auditpol` sont ignorées avec un avertissement — le pipeline continue.

---

## Migration v1 → v2

Aucun changement de comportement pour les utilisateurs existants :

1. Le mode `--format auto` détecte et traite les fichiers `events.jsonl` v1 sans modification
2. Les `Signal` existants (ransomware, PowerShell) ont `mitre_tactic=""` et `mitre_technique=""` — valeurs vides, pas de rupture
3. `run_siem.bat small` et `run_siem.bat large` fonctionnent identiquement

!!! success "Rétrocompatibilité totale"
    Un pipeline v1 existant fonctionne en v2 sans aucune modification.
