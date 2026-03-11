# ps_persistence.yaml

**Fichier :** `src/detect/modules/ps_persistence.yaml`  
**EventID :** 4104  
**Focus :** Mécanismes d'établissement de persistance depuis PowerShell

## Sélections

| Sélection | Patterns clés | MITRE |
|---|---|---|
| `selection_hidden` | `-WindowStyle Hidden`, `-w hidden`, `-NonInteractive` | T1564.003 |
| `selection_install` | `--install`, `New-Service`, `sc create` | T1543.003 |
| `selection_registry_run` | `HKCU:\...\Run`, `HKLM:\...\Run`, `RunOnce` | T1547.001 |
| `selection_startup_folder` | `\Start Menu\Programs\Startup`, `SpecialFolder.Startup` | T1547.001 |
| `selection_schtask_inline` | `Register-ScheduledTask`, `New-ScheduledTaskAction` | T1053.005 |
| `selection_wmi_subscription` | `__EventFilter`, `CommandLineEventConsumer` | T1546.003 |

## Points d'attention

**`-WindowStyle Hidden`** est le pattern le plus fréquemment rencontré en pratique — quasi-systématiquement présent dans les scripts de backdoor. Score de base 0.6 pour ce seul match.

**WMI Event Subscription** (`__EventFilter` + `__EventConsumer` + `__FilterToConsumerBinding`) est la technique de persistance la plus discrète sous Windows — elle survit aux redémarrages et n'apparaît pas dans `schtasks /query`. Score recommandé à rehausser manuellement si ces trois patterns apparaissent ensemble.

## Faux positifs

- Outils de déploiement SCCM/Intune créant des services via `New-Service`
- Logiciels légitimes s'enregistrant au démarrage via registry Run
