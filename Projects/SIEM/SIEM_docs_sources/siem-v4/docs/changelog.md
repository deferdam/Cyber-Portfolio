# Changelog v3 → v4

## Bug corrigé dans `powershell_sigma.run()`

La version uploadée contenait trois bugs cumulés dans la boucle de chargement multi-fichiers :

```python
# ❌ Version avec bugs
for rule_path in rule_paths:
    path = Path(rule_path)
    if not path.exists():
        return []              # bug 1 : exit total si UN fichier manque

    rule = _parse_simple_sigma_yaml(_read_text(path))
    signals: List[Signal] = []  # bug 2 : reset à chaque itération

    for ev in events:
        ...

    return signals             # bug 3 : return dans la boucle → seul le 1er fichier traité
```

```python
# ✓ Version corrigée
signals: List[Signal] = []    # hors de la boucle

for rule_path in rule_paths:
    path = Path(rule_path)
    if not path.exists():
        warnings.warn(...)
        continue               # skip ce fichier, continue les autres

    rule = _parse_simple_sigma_yaml(_read_text(path))

    for ev in events:
        ...
        signals.append(...)

return signals                 # hors de la boucle
```

## Changements fichiers

### `powershell_sigma.py`

Signature de `run()` mise à jour :

```python
# Avant
def run(events, rule_path: str = "powershell_suspicious.yaml") -> List[Signal]:

# Après
def run(events, rule_paths: Optional[List[str]] = None) -> List[Signal]:
    if rule_paths is None:
        rule_paths = ["powershell_suspicious.yaml"]
```

### `engine.py`

Deux changements :

**1. Résolution des chemins YAML relative au module** (plus de dépendance au cwd) :

```python
_MODULES_DIR = Path(__file__).parent / "modules"

_PS_RULE_FILES = [
    str(_MODULES_DIR / "ps_scriptblock.yaml"),
    str(_MODULES_DIR / "ps_persistence.yaml"),
    str(_MODULES_DIR / "ps_privilege_escalation.yaml"),
    str(_MODULES_DIR / "powershell_suspicious.yaml"),
]
```

**2. Passage de la liste à `powershell_sigma.run()`** :

```python
# Avant
ps_signals = powershell_sigma.run(events, rule_path="powershell_suspicious.yaml")

# Après
ps_signals = powershell_sigma.run(events, rule_paths=_PS_RULE_FILES)
```

### Nouveaux fichiers YAML

| Fichier | Règles principales |
|---------|-------------------|
| `ps_scriptblock.yaml` | Encoded, IEX, download, AMSI bypass, exec bypass, recon |
| `ps_persistence.yaml` | Hidden window, registry Run, startup folder, WMI subscription, schtasks inline |
| `ps_privilege_escalation.yaml` | Local/domain admin add, UAC bypass, token manipulation, credential dump |
| `linux_suspicious.yaml` | chmod +s, cron, curl pipe bash, reverse shell, /etc/passwd, firewall disable |
