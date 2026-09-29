# Mini SIEM, Moteur de détection comportementale Sigma

> Moteur de détection comportementale construit en lab, à des fins d'apprentissage.  
> Périmètre défensif uniquement. Aucun binaire malveillant hébergé.

---

## 1. Résumé

Mini SIEM v5 étend le moteur de détection avec un pipeline Linux complet : sources auditd, normalisation des événements PAM/SSH/auditd EXECVE, et quatre nouveaux modules de détection Linux.

Il ne repose pas sur des signatures par hash. Il détecte des patterns comportementaux, ce qui lui permet de détecter des variantes obfusquées ou renommées que les outils à base de signatures manquent.

Le moteur analyse :
- Les logs Windows, syslog RFC 3164/5424, CEF, NXLog et Winlogbeat
- Les Script Blocks PowerShell (EventID 4104) : obfuscation, AMSI bypass, download cradles
- Les mécanismes de persistance : registry Run, WMI subscription, startup folder, schtasks inline
- L'élévation de privilèges : ajout groupe admin, UAC bypass, credential dump
- Les commandes Linux/Unix suspectes : chmod +s, cron, curl pipe bash, reverse shell
- Les événements auditd au niveau kernel : EXECVE, SYSCALL, PATH
- Les logs d'authentification Linux : SSH, PAM, sudo
- Les relations parent-enfant entre processus et les binaires LOTL

Couverture actuelle :
- Exécution PowerShell suspecte : 4 fichiers Sigma par domaine
- Patterns comportementaux ransomware (Windows et Linux)
- Binaires LOTL (8 règles, MITRE ATT&CK)
- Persistance Windows : 6 techniques détectées
- Élévation de privilèges : 5 techniques détectées
- Commandes Linux : 8 catégories détectées
- Auditd kernel-level : accès fichiers sensibles, chmod setuid, création compte, injection mémoire
- Auth Linux : brute force SSH, root login, sudo dangereux, modification authorized_keys
- Outils offensifs : credential tools, lateral movement, tunneling, sniffers réseau

**Statut : v5 terminée. v5.5 en développement (déduplication des Signals).**

---

## 2. Architecture

```
Sources de logs (Windows / Sysmon / PowerShell / RFC 3164 / RFC 5424 / CEF / NXLog / Winlogbeat
                 auditd EXECVE/SYSCALL/PATH / auth.log PAM/SSH/sudo)
    ↓
Parseur syslog : auto-détection de format
    ↓
Normaliseur v5 : routage par source
  ├── auditd  → reconstruction args EXECVE (a0/a1/a2…), décodage hex, uid/auid
  ├── auth    → parsing messages syslog (regex SSH/sudo/PAM)
  └── autres  → chemin v4 inchangé (Windows/Sysmon/générique)
    ↓
CanonicalEvent (immuable)
    ↓
Détection conditionnelle par OS (platform.system())
  ├── Windows
  │     ├── Layer 1 — Signature    : ransomware_v4
  │     ├── Layer 2 — Behavioral   : powershell_sigma (4 YAML) + lotl_sigma + spawn suspects
  │     └── Layer 3 — Corrélation  : séquences temporelles recon → exec
  └── Linux
        ├── Layer 1 — Signature    : ransomware_linux
        ├── Layer 2 — Behavioral   : bash_sigma (3 YAML) + linux_auditd
        └── Layer 3 — Auth correl. : linux_auth (brute force temporel)
    ↓
Corrélateur, agrégation en alertes avec sévérité
    ↓
Sortie JSONL (events, signals, alerts, timelines)
```

### Modules

| Module | Rôle |
|--------|------|
| `syslog_parser.py` | Parse RFC 3164, RFC 5424, CEF, JSON NXLog/Winlogbeat |
| `normalizer.py` | Routage par source : auditd / auth / générique → CanonicalEvent |
| `process_tree.py` | Construit l'index parent→enfant, détecte les spawn suspects |
| `lotl_sigma.py` | 8 règles LOTL + EventID 4698/4699 + spawn suspects |
| `powershell_sigma.py` | Chargeur Sigma multi-fichiers YAML (Windows) |
| `bash_sigma.py` | Chargeur Sigma multi-fichiers YAML (Linux) |
| `linux_auditd.py` | 5 détecteurs auditd : fichiers sensibles, chmod setuid, useradd, connect, EXECVE |
| `linux_auth.py` | 4 détecteurs auth : brute force SSH, root login, sudo, authorized_keys |
| `ransomware_linux.py` | Détection ransomware adaptée Linux (/tmp, uid=0, outils chiffrement) |
| `engine.py` | Dispatch conditionnel OS + orchestrateur 3 couches |
| `correlator.py` | Signals → Alerts avec sévérité calculée |
| `reporter.py` | Export JSONL : events, signals, alerts, timelines |

### Fichiers Sigma

| Fichier | OS | Domaine | Techniques MITRE |
|---------|-----|---------|-----------------|
| `ps_scriptblock.yaml` | Windows | Script Block 4104, encodage, IEX, AMSI, recon | T1059.001, T1027, T1562 |
| `ps_persistence.yaml` | Windows | Registry Run, WMI sub, startup, schtasks inline | T1547.001, T1053.005, T1546.003 |
| `ps_privilege_escalation.yaml` | Windows | Admin group add, UAC bypass, credential dump | T1098, T1548.002, T1003 |
| `linux_suspicious.yaml` | Linux | chmod +s, cron, curl pipe bash, reverse shell | T1059.004, T1053.003, T1222.002 |
| `linux_auditd.yaml` | Linux | Privesc tools, container escape, kernel exploits, LD_PRELOAD | T1548, T1003, T1574.006, T1543.002 |
| `linux_auth.yaml` | Linux | SSH failure, root login, sudo dangereux, authorized_keys | T1110, T1078.003, T1548.003 |

---

## 3. Règles de détection, v5

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

### Élévation de privilèges Windows

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
| `\| bash` / `\| sh` (pipe exec) | T1059.004 |
| `bash -i >& /dev/tcp` (reverse shell) | T1059.004 |
| Écriture `/etc/passwd` / `/etc/shadow` | T1098 |
| `setenforce 0` / `ufw disable` | T1562.001 |

### Détection auditd kernel-level

| Indicateur | Technique MITRE |
|-----------|----------------|
| Accès `/etc/shadow`, `/etc/sudoers`, `authorized_keys` | T1003.008 |
| chmod syscall avec mode 4xxx/6xxx (setuid/setgid) | T1548.001 |
| `useradd -o -u 0` (clone root) | T1136.001 |
| `connect()` syscall depuis bash/python/perl | T1071.001 |
| `/dev/tcp/`, `nc -e /bin/bash`, `socat EXEC` | T1059.004 |
| `LD_PRELOAD=`, `/etc/ld.so.preload` | T1574.006 |
| `dirtycow`, `dirty_pipe`, `CVE-2022-0847` | T1068 |
| `mimipenguin`, `lazagne`, `linpeas`, `pspy` | T1003 |
| `bloodhound`, `crackmapexec`, `kerbrute` | T1087 |
| `chisel`, `ligolo`, `frpc` (tunneling) | T1572 |

### Détection auth Linux

| Indicateur | Seuil / Technique MITRE |
|-----------|------------------------|
| Brute force SSH | 5 échecs en 120 secondes — T1110.001 |
| Root login SSH direct | Présence unique — T1078.003 |
| `sudo /bin/bash`, `sudo -s`, `sudo /usr/bin/vim` | Commande dangereuse — T1548.003 |
| Modification `authorized_keys` | Opération write/create — T1098.004 |

---

## 4. Limitations

| Limitation | Détail |
|------------|--------|
| Environnement lab uniquement | Non testé sur des volumes de logs de production |
| Nécessite une ingestion correcte | Sysmon (Windows) et auditd (Linux) doivent être activés |
| Pas de baseline de légitimité | Faux positifs sur activités admin et déploiement |
| Pas de déduplication des signaux | Un événement peut générer plusieurs Signals distincts (v5.5) |
| Pas de capacité de blocage | Détection et alerting uniquement, pas de réponse automatisée |
| Évasion possible | Un attaquant avancé peut contourner les règles comportementales |
| `systemctl enable` : taux de FP élevé | Corrélation avec d'autres signaux nécessaire avant intervention |

---

## 5. Modèle de menace

| Comportement | Détecté |
|----------|----------|
| Exécution PowerShell obfusquée | Oui |
| Téléchargement de payload distant | Oui |
| Exécution en mémoire (fileless) | Partiel |
| AMSI bypass | Oui |
| Ransomware rapide / lent | Oui (Windows + Linux) |
| Suppression des shadow copies | Oui |
| Persistance registry Run | Oui |
| Persistance WMI subscription | Oui |
| Persistance systemd service | Oui |
| Ajout utilisateur admin local / domaine | Oui |
| UAC bypass (fodhelper, eventvwr) | Oui |
| Credential dump (Mimikatz / mimipenguin) | Oui |
| Reverse shell Linux | Oui |
| chmod +s (setuid escalation) | Oui |
| Mouvement latéral via WMI | Oui |
| Brute force SSH | Oui (corrélation temporelle) |
| Root login SSH direct | Oui |
| Outils offensifs Linux (bloodhound, chisel…) | Oui |
| Kernel exploit (DirtyCow, Dirty Pipe) | Oui (par nom) |
| Container escape | Oui |
| Spawn suspect (Office → PowerShell) | Oui |

---

## 6. Roadmap

- [x] Moteur de règles Sigma, détection PowerShell
- [x] Détecteur comportemental ransomware (Windows)
- [x] Support multi-format syslog (RFC 3164, RFC 5424, CEF, NXLog, Winlogbeat)
- [x] Process tree, modélisation parent→enfant
- [x] 8 règles LOTL avec tagging MITRE ATT&CK
- [x] Chargeur Sigma multi-fichiers par domaine
- [x] Détection persistance Windows (registry Run, WMI sub, startup)
- [x] Détection élévation de privilèges Windows (admin group, UAC bypass, credential dump)
- [x] Détection commandes Linux (chmod +s, cron, reverse shell)
- [x] Détection Linux étendue : auditd, PAM, systemd (v5)
- [x] Normalisation auditd : reconstruction EXECVE args, décodage hex, routing par source
- [x] Détecteur ransomware Linux (/tmp, uid=0, outils chiffrement, ransom notes)
- [x] Règles Sigma : linux_auditd.yaml (kernel exploits, outils offensifs, tunneling)
- [ ] Déduplication des Signals + scoring agrégé (v5.5)
- [ ] Enrichissement différé : URLVoid, WHOIS, géoloc IP (v6)
- [ ] Baseline de légitimité pour réduire les faux positifs (v7)
- [ ] SOAR : réponse automatique (v8)

---

## 7. Références

- MITRE ATT&CK : T1059.001 (PowerShell), T1486 (Ransomware), T1490 (Shadow Copy), T1047 (WMI), T1218 (LOLBIN), T1547.001 (Registry Run), T1548.002 (UAC Bypass), T1003 (Credential Dumping), T1068 (Kernel Exploit), T1572 (Tunneling)
Les autres sont gardé pour ne pas être utilisé a mauvaise essiant.

---

> **Contenu défensif et éducatif uniquement.**  
> Construit en environnement lab isolé. Aucun système de production utilisé.
