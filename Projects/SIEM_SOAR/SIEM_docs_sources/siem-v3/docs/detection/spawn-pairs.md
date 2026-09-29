# Paires de spawns suspects

32 paires parent→enfant définies dans `process_tree.py:_SUSPICIOUS_SPAWNS`.

## Logique de détection

```python
_SUSPICIOUS_SET: FrozenSet[Tuple[str, str]] = frozenset(
    (p.lower(), c.lower()) for p, c in _SUSPICIOUS_SPAWNS
)

def is_spawn_suspect(parent_image, child_image) -> bool:
    p = _basename(parent_image)
    c = _basename(child_image)
    return (p, c) in _SUSPICIOUS_SET  # O(1)
```

La comparaison est **directionnelle** (parent, enfant) et **par basename en minuscules**. Un chemin complet est accepté — seul le basename est utilisé pour la comparaison.

## Tableau complet des paires

### Office → Shell (macro malveillante)

| Parent | Enfant | Contexte |
|--------|--------|----------|
| winword.exe | powershell.exe | Macro Word → PowerShell dropper |
| winword.exe | cmd.exe | Macro Word → CMD |
| winword.exe | wscript.exe | Macro Word → WSH |
| winword.exe | mshta.exe | Macro Word → HTA |
| excel.exe | powershell.exe | Macro Excel → PowerShell |
| excel.exe | cmd.exe | Macro Excel → CMD |
| excel.exe | wscript.exe | Macro Excel → WSH |
| excel.exe | mshta.exe | Macro Excel → HTA |
| outlook.exe | powershell.exe | Pièce jointe Outlook |
| outlook.exe | cmd.exe | Pièce jointe Outlook |

### Navigateurs → Shell (phishing / drive-by)

| Parent | Enfant | Contexte |
|--------|--------|----------|
| chrome.exe | powershell.exe | Téléchargement malveillant |
| firefox.exe | powershell.exe | Téléchargement malveillant |
| iexplore.exe | powershell.exe | Drive-by / ActiveX |
| iexplore.exe | cmd.exe | Drive-by / ActiveX |

### Loaders LOTL → Shell

| Parent | Enfant | Contexte |
|--------|--------|----------|
| mshta.exe | powershell.exe | HTA → PowerShell stager |
| mshta.exe | cmd.exe | HTA → CMD |
| wscript.exe | powershell.exe | WSH → PowerShell |
| cscript.exe | powershell.exe | WSH → PowerShell |
| rundll32.exe | powershell.exe | DLL → PowerShell |
| regsvr32.exe | powershell.exe | Squiblydoo → PowerShell |
| regsvr32.exe | cmd.exe | Squiblydoo → CMD |

### Processus système → Shell (compromission de service)

| Parent | Enfant | Contexte |
|--------|--------|----------|
| services.exe | cmd.exe | Service malveillant → CMD |
| lsass.exe | cmd.exe | Credential dumper → CMD |
| svchost.exe | cmd.exe | Service compromis → CMD |
| svchost.exe | powershell.exe | Service compromis → PowerShell |
| taskeng.exe | powershell.exe | Task engine → PowerShell (AT/schtasks) |
| msiexec.exe | powershell.exe | Installer malveillant → PowerShell |
| msiexec.exe | cmd.exe | Installer malveillant → CMD |

### WMI (mouvement latéral)

| Parent | Enfant | Contexte |
|--------|--------|----------|
| wmiprvse.exe | powershell.exe | WMI remote exec → PowerShell |
| wmiprvse.exe | cmd.exe | WMI remote exec → CMD |
| wmiprvse.exe | wscript.exe | WMI remote exec → WSH |

### SQL Server (injection)

| Parent | Enfant | Contexte |
|--------|--------|----------|
| sqlservr.exe | cmd.exe | xp_cmdshell activation |
| sqlservr.exe | powershell.exe | xp_cmdshell → PowerShell |

## Faux positifs connus

!!! warning "Cas légitimes pouvant déclencher cette règle"
    - **Déploiement logiciel via SCCM/Intune** : `msiexec.exe → powershell.exe` peut être légitime lors d'un déploiement
    - **Développeurs** : `excel.exe → powershell.exe` peut être un script de test automatisé
    - **Administrateurs** : `wscript.exe → powershell.exe` peut être un script d'administration

    Dans ces cas, la baseline de légitimité (v3) permettra de filtrer les occurrences récurrentes sur des machines et des utilisateurs connus.

## Ajouter une paire personnalisée

Modifier `_SUSPICIOUS_SPAWNS` dans `process_tree.py` :

```python
_SUSPICIOUS_SPAWNS: List[Tuple[str, str]] = [
    # ... paires existantes ...
    ("myapp.exe", "powershell.exe"),  # Ajout personnalisé
]
```

Les modifications sont prises en compte au prochain lancement sans autre changement.
