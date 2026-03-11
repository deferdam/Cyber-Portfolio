# Mini SIEM, Moteur de détection comportementale Sigma

> Moteur de détection comportementale construit en lab, à des fins d'apprentissage.  
> Périmètre défensif uniquement. Aucun binaire malveillant hébergé.

---

## 1. Résumé

Mini SIEM v4 introduit un chargeur Sigma multi-fichiers et trois nouveaux domaines de détection : persistance Windows, élévation de privilèges, et commandes Linux/Unix suspectes.

Il ne repose pas sur des signatures par hash. Il détecte des patterns comportementaux, ce qui lui permet de détecter des variantes obfusquées ou renommées que les outils à base de signatures manquent.

Le moteur analyse :
- Les logs Windows, syslog RFC 3164/5424, CEF, NXLog et Winlogbeat
- Les Script Blocks PowerShell (EventID 4104) : obfuscation, AMSI bypass, download cradles
- Les mécanismes de persistance : registry Run, WMI subscription, startup folder, schtasks inline
- L'élévation de privilèges : ajout groupe admin, UAC bypass, credential dump
- Les commandes Linux/Unix suspectes : chmod +s, cron, curl pipe bash, reverse shell
- Les relations parent-enfant entre processus et les binaires LOTL

Couverture actuelle :
- Exécution PowerShell suspecte : 4 fichiers Sigma par domaine
- Patterns comportementaux ransomware
- Binaires LOTL (8 règles, MITRE ATT&CK)
- Persistance Windows : 6 techniques détectées
- Élévation de privilèges : 5 techniques détectées
- Commandes Linux : 8 catégories détectées

**Statut : v4 terminée. v5 en développement (détection Linux étendue, auditd).**

---

## 2. Architecture

```
Sources de logs (Windows / Sysmon / PowerShell / RFC 3164 / RFC 5424 / CEF / NXLog / Winlogbeat)
    ↓
Parseur syslog : auto-détection de format
    ↓
Normaliseur, extraction des champs en CanonicalEvent (immuable)
    ↓
Process Tree, index parent→enfant (2 passes)
    ↓
Moteur de détection 3 couches
  ├── Couche 1, Signature    : ransomware_v4
  ├── Couche 2, Behaviorale  : powershell_sigma (4 fichiers YAML) + lotl_sigma + spawn suspects
  └── Couche 3, Corrélation  : séquences temporelles recon → exec
    ↓
Corrélateur, agrégation en alertes avec sévérité
    ↓
Sortie JSON
    {
      "score": 88,
      "mitre_tactic": "Persistence",
      "mitre_technique": "T1547.001",
      "classification": "registry_run_key_persistence",
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
| `powershell_sigma.py` | Chargeur Sigma multi-fichiers YAML |
| `engine.py` | Orchestrateur 3 couches  déclare `_PS_RULE_FILES` |
| `correlator.py` | Signals → Alerts avec sévérité calculée |
| `reporter.py` | Export JSONL, events, signals, alerts, timelines |

### Fichiers Sigma PowerShell

| Fichier | Domaine | Techniques MITRE |
|---------|---------|-----------------|
| `ps_scriptblock.yaml` | Script Block 4104, encodage, IEX, AMSI, recon | T1059.001, T1027, T1562 |
| `ps_persistence.yaml` | Registry Run, WMI sub, startup, schtasks inline | T1547.001, T1053.005, T1546.003 |
| `ps_privilege_escalation.yaml` | Admin group add, UAC bypass, credential dump | T1098, T1548.002, T1003 |
| `linux_suspicious.yaml` | chmod +s, cron, curl pipe bash, reverse shell | T1059.004, T1053.003, T1222.002 |

---

## 3. Règles de détection, v4

### Script Block PowerShell (EventID 4104)

| Indicateur | Sévérité |
|-----------|----------|
| `-EncodedCommand` / `-enc` | High |
| `Invoke-Expression` / `IEX` | High |
| AMSI bypass (`amsiInitFailed`, `AmsiScanBuffer`) | Critical |
| `-ExecutionPolicy Bypass` | High |
| `DownloadString` / `Invoke-WebRequest` | Critical |
| Obfuscation (backtick, char cast, `-join`) | High |
| `whoami` / énumération d'identité | Medium |

### Persistance Windows

| Indicateur | Technique MITRE |
|-----------|----------------|
| Écriture clé registry `CurrentVersion\Run` | T1547.001 |
| `-WindowStyle Hidden` / `-NonInteractive` | T1564.003 |
| `Register-ScheduledTask` inline | T1053.005 |
| `New-Service` / `sc create` | T1543.003 |
| WMI Event Subscription (`__EventFilter`) | T1546.003 |
| Dépôt dans le dossier Startup | T1547.001 |

### Élévation de privilèges

| Indicateur | Technique MITRE |
|-----------|----------------|
| `net localgroup administrators` / `Add-LocalGroupMember` | T1098 |
| `Add-ADGroupMember` / `net group "Domain Admins"` | T1098 |
| `net user /add` / `New-LocalUser` | T1136.001 |
| `fodhelper` / `eventvwr` / UAC bypass | T1548.002 |
| `Invoke-Mimikatz` / `sekurlsa` | T1003 |

### Commandes Linux suspectes

| Indicateur | Technique MITRE |
|-----------|----------------|
| `chmod +s` / `chmod 4755` (setuid) | T1222.002 |
| `* * * * * curl` / `crontab -` | T1053.003 |
| `curl.*\|.*bash` / `wget.*\|.*sh` | T1059.004 |
| `bash -i >& /dev/tcp` (reverse shell) | T1059.004 |
| Écriture `/etc/passwd` / `/etc/shadow` | T1098 |
| `setenforce 0` / `ufw disable` | T1562.001 |

---

## 4. Limitations

| Limitation | Détail |
|------------|--------|
| Environnement lab uniquement | Non testé sur des volumes de logs de production |
| Nécessite une ingestion correcte | Sysmon et Script Block Logging doivent être activés |
| Pas de baseline de légitimité | Faux positifs sur activités admin et déploiement |
| Pas de déduplication des signaux | Un événement peut générer plusieurs Signals distincts |
| Pas de capacité de blocage | Détection et alerting uniquement, pas de réponse automatisée |
| Linux en mode CommandLine uniquement | Pas encore d'intégration auditd / syscall (v5) |
| Évasion possible | Un attaquant avancé peut contourner les règles comportementales |

---

## 5. Modèle de menace

| Comportement | Détecté |
|----------|----------|
| Exécution PowerShell obfusquée | Oui |
| Téléchargement de payload distant | Oui |
| Exécution en mémoire (fileless) | Partiel |
| AMSI bypass | Oui |
| Ransomware rapide / lent | Oui |
| Suppression des shadow copies | Oui |
| Persistance registry Run | Oui |
| Persistance WMI subscription | Oui |
| Ajout utilisateur admin local / domaine | Oui |
| UAC bypass (fodhelper, eventvwr) | Oui |
| Credential dump (Mimikatz) | Oui |
| Reverse shell Linux | Oui |
| chmod +s (setuid escalation) | Oui |
| Mouvement latéral via WMI | Oui |
| Spawn suspect (Office → PowerShell) | Oui |

---

## 6. Roadmap

- [x] Moteur de règles Sigma, détection PowerShell
- [x] Détecteur comportemental ransomware
- [x] Support multi-format syslog (RFC 3164, RFC 5424, CEF, NXLog, Winlogbeat)
- [x] Process tree, modélisation parent→enfant
- [x] 8 règles LOTL avec tagging MITRE ATT&CK
- [x] Chargeur Sigma multi-fichiers par domaine
- [x] Détection persistance Windows (registry Run, WMI sub, startup)
- [x] Détection élévation de privilèges (admin group, UAC bypass, credential dump)
- [x] Détection commandes Linux (chmod +s, cron, reverse shell)
- [ ] Détection Linux étendue, auditd, PAM, systemd (v5)
- [ ] Déduplication des Signals + scoring agrégé (v5.5)
- [ ] Enrichissement différé, URLVoid, WHOIS, géoloc IP (v6)
- [ ] Baseline de légitimité pour réduire les faux positifs (v7)
- [ ] SOAR, réponse automatique (v8)

---

## 7. Références

- MITRE ATT&CK : T1059.001 (PowerShell), T1486 (Ransomware), T1490 (Shadow Copy), T1047 (WMI), T1218 (LOLBIN), T1547.001 (Registry Run), T1548.002 (UAC Bypass), T1003 (Credential Dumping)
- Spécification des règles Sigma : https://github.com/SigmaHQ/sigma
- Format de log Sysmon : https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Windows Event ID 4104, Script Block Logging
- LOLBAS Project : https://lolbas-project.github.io
- GTFOBins (Linux) : https://gtfobins.github.io

---

> **Contenu défensif et éducatif uniquement.**  
> Construit en environnement lab isolé. Aucun système de production utilisé.
