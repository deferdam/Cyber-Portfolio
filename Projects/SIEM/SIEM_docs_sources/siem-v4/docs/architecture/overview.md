# Vue d'ensemble v4

## Principe central : séparation politique / mécanisme

```
engine.py          → POLITIQUE : quels fichiers Sigma charger
powershell_sigma.py → MÉCANISME : comment parser et détecter
```

`engine.py` déclare `_PS_RULE_FILES`. `powershell_sigma.py` ne sait pas combien de fichiers existent — il reçoit une liste et la parcourt. Pour ajouter une règle demain, **un seul fichier est modifié** : `engine.py`.

## Résolution des chemins

En v3, les chemins YAML étaient relatifs au répertoire courant d'exécution (`cwd`). Lancer le pipeline depuis un répertoire différent cassait silencieusement la détection.

En v4, les chemins sont résolus relativement à `engine.py` lui-même :

```python
_MODULES_DIR = Path(__file__).parent / "modules"
```

`__file__` est le chemin absolu de `engine.py`. `parent / "modules"` est donc toujours le bon répertoire, indépendamment du cwd.

## Comportement sur fichier manquant

```
Fichier manquant → RuntimeWarning sur stderr → continue (fichier ignoré)
Pas de fichier manquant → silence
Tous les fichiers manquants → 0 signaux PowerShell, pipeline continue
```

Aucun fichier manquant ne plante le pipeline. Le SOC doit surveiller les warnings stderr pour détecter une règle silencieusement absente.

## Cycle de vie d'un événement PowerShell 4104

```
CanonicalEvent (event_type=other, source=powershell)
    ↓
_is_powershell_4104(ev) → True
    ↓
for rule_path in _PS_RULE_FILES:         ← 4 fichiers
    rule = parse YAML
    for sel_name, (field, needles) in rule.selections:
        text = ScriptBlockText or CommandLine
        if any(needle in text):
            matched.append(sel_name)
    if matched:
        score = min(1.0, 0.6 + 0.1 * len(matched))
        → Signal(signal_type="powershell_sigma", ...)
```

Le score augmente avec le nombre de sélections matchées. Un événement qui matche `selection_encoded` + `selection_amsi_bypass` + `selection_download` dans le même script block obtient `0.6 + 0.3 = 0.9`.
