# Mini SIEM — Moteur de détection comportementale Sigma

> Moteur de détection comportementale construit en lab, à des fins d'apprentissage.  
> Périmètre défensif uniquement. Aucun binaire malveillant hébergé.

---

## 1. Résumé

Mini SIEM v3 étend le moteur de détection avec le support multi-format des sources de logs, la modélisation des arbres de processus, et un ensemble de règles LOTL (*Living off the Land*) alignées sur le framework MITRE ATT&CK.

Il ne repose pas sur des signatures par hash. Il détecte des patterns comportementaux — ce qui lui permet de détecter des variantes obfusquées ou renommées que les outils à base de signatures manquent.

Le moteur analyse :
- Les logs Windows, syslog RFC 3164/5424, CEF, NXLog et Winlogbeat
- Les patterns d'exécution PowerShell (Script Block Logging, EventID 4104)
- Les binaires LOTL : vssadmin, wmic, mshta, certutil, rundll32, schtasks, regsvr32
- Les relations parent-enfant entre processus (spawn suspects)
- Des indicateurs comportementaux pondérés en score de risque (0–100), taggés MITRE ATT&CK

Couverture actuelle :
- Exécution PowerShell suspecte (EncodedCommand, IEX, AMSI bypass, download cradles)
- Patterns comportementaux ransomware (mass rename, suppression shadow copies, extension suspecte)
- Binaires LOTL (8 règles, tactiques Execution / Persistence / Defense Evasion / Impact)
- Spawn suspects (32 paires parent→enfant — Office, WMI, loaders)
- Tâches planifiées via EventID 4698/4699/4702

**Statut : v3 terminée. v4 en développement.**

---

## 2. Architecture

```
Sources de logs (Windows / Sysmon / PowerShell / RFC 3164 / RFC 5424 / CEF / NXLog / Winlogbeat)
    ↓
Parseur syslog — auto-détection de format
    ↓
Normaliseur — extraction des champs en CanonicalEvent (immuable)
    ↓
Process Tree — index parent→enfant (2 passes)
    ↓
Moteur de détection 3 couches
  ├── Couche 1 — Signature    : ransomware_v4
  ├── Couche 2 — Behaviorale  : powershell_sigma + lotl_sigma + spawn suspects
  └── Couche 3 — Corrélation  : séquences temporelles recon → exec
    ↓
Corrélateur — agrégation en alertes avec sévérité
    ↓
Sortie JSON
    {
      "score": 92,
      "mitre_tactic": "Impact",
      "mitre_technique": "T1490",
      "classification": "vssadmin_shadow_deletion",
      "indicators": [...],
      "date": "2025-04-23T09:15:32Z"
    }
```

### Modules

| Module | Rôle |
|--------|------|
| `syslog_parser.py` | Parse RFC 3164, RFC 5424, CEF, JSON NXLog/Winlogbeat |
| `normalizer.py` | Convertit les événements bruts en CanonicalEvent (frozen) |
| `process_tree.py` | Construit l'index parent→enfant, détecte les spawn suspects |
| `lotl_sigma.py` | 8 règles LOTL + EventID 4698/4699 + spawn suspects |
| `powershell_sigma.py` | Règles Sigma YAML + corrélation recon temporelle |
| `engine.py` | Orchestrateur 3 couches avec isolation d'erreurs |
| `correlator.py` | Signals → Alerts avec sévérité calculée |
| `reporter.py` | Export JSONL — events, signals, alerts, timelines |

---

## 3. Règles de détection — v3

### Détection PowerShell (EventID 4104 — Script Block Logging)

| Indicateur | Sévérité |
|-----------|----------|
| `-EncodedCommand` | High |
| `Invoke-Expression` / `IEX` | High |
| `DownloadString` + URL externe | Critical |
| Instanciation `WebClient` | Medium |
| AMSI bypass (`amsiInitFailed`, `AmsiScanBuffer`) | Critical |
| Obfuscation (backtick, char cast, string concat) | High |
| `whoami` / énumération d'identité | Medium |

### Détection LOTL

| Règle | Binaire | Tactique MITRE | Score |
|-------|---------|---------------|-------|
| LOTL-001 | vssadmin.exe | Impact — T1490 | 0.92 |
| LOTL-002 | wmic.exe | Lateral Movement — T1047 | 0.80 |
| LOTL-003 | mshta.exe | Execution — T1218.005 | 0.85 |
| LOTL-004 | certutil.exe | Defense Evasion — T1140 | 0.82 |
| LOTL-005 | rundll32.exe | Defense Evasion — T1218.011 | 0.78 |
| LOTL-006 | schtasks.exe | Persistence — T1053.005 | 0.75 |
| LOTL-007 | cron / at.exe | Persistence — T1053.003 | 0.70 |
| LOTL-008 | regsvr32.exe | Defense Evasion — T1218.010 | 0.88 |

### Détection comportementale ransomware

| Indicateur | Poids |
|-----------|-------|
| Taux élevé de renommage de fichiers | High |
| Patterns d'extensions suspects | High |
| Activité de chiffrement de masse | Critical |
| Suppression des shadow copies | Critical |
| Spawning de processus anormal | Medium |

---

## 4. Limitations

| Limitation | Détail |
|------------|--------|
| Environnement lab uniquement | Non testé sur des volumes de logs de production |
| Nécessite une ingestion correcte | Sysmon et Script Block Logging doivent être activés |
| Pas de baseline de légitimité | Absence de contexte historique — faux positifs sur activités admin |
| Pas de capacité de blocage | Détection et alerting uniquement — pas de réponse automatisée |
| Évasion possible | Un attaquant avancé peut contourner les règles comportementales |
| Corrélation partielle | Un seul type de séquence temporelle détecté (recon PowerShell) |

---

## 5. Modèle de menace

| Comportement | Détecté |
|----------|----------|
| Exécution PowerShell obfusquée | Oui |
| Téléchargement de payload distant | Oui |
| Exécution en mémoire (fileless) | Partiel |
| AMSI bypass | Oui |
| Ransomware rapide | Oui |
| Ransomware lent | Oui |
| Suppression des shadow copies | Oui |
| Mouvement latéral via WMI | Oui |
| Persistance via tâches planifiées | Oui |
| Spawn suspect (Office → PowerShell) | Oui |
| Escalade de privilèges via PS | Partiel |

---

## 6. Roadmap

- [x] Moteur de règles Sigma — détection PowerShell
- [x] Détecteur comportemental ransomware
- [x] Support multi-format syslog (RFC 3164, RFC 5424, CEF, NXLog, Winlogbeat)
- [x] Process tree — modélisation parent→enfant
- [x] 8 règles LOTL avec tagging MITRE ATT&CK
- [x] Détection spawn suspects (32 paires)
- [x] Architecture 3 couches avec isolation d'erreurs
- [ ] Règles Sigma multi-fichiers par domaine (v4)
- [ ] Détection de persistance avancée (registry Run, WMI subscription)
- [ ] Détection Linux (chmod +s, cron, reverse shell)
- [ ] Enrichissement différé — URLVoid, WHOIS, géoloc IP (v6)
- [ ] Baseline de légitimité pour réduire les faux positifs (v7)

---

## 7. Références

- MITRE ATT&CK : T1059.001 (PowerShell), T1486 (Ransomware), T1490 (Shadow Copy), T1047 (WMI), T1218 (LOLBIN)
- Spécification des règles Sigma : https://github.com/SigmaHQ/sigma
- Format de log Sysmon : https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Windows Event ID 4104 — Script Block Logging
- CEF Specification : https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdoc/common-event-format-v25/common-event-format-v25.pdf

---

> **Contenu défensif et éducatif uniquement.**  
> Construit en environnement lab isolé. Aucun système de production utilisé.
