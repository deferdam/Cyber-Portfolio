# Mini SIEM, Moteur de détection comportementale Sigma

> Moteur de détection comportementale construit en lab, à des fins d'apprentissage.
> Périmètre défensif uniquement. Aucun binaire malveillant hébergé.

---

## Démarrage rapide

Lanceur universel (détecte l'OS automatiquement):

| Action | Commande |
| --- | --- |
| Lancer l'application | `python launch.py` |
| Streaming (fausses données) | `python launch.py stream` |
| Ouvrir la documentation | `python launch.py docs` |
| Lancer les tests | `python launch.py tests` |
| Traiter un fichier | `python launch.py pipeline <fichier>` |

Les scripts par plateforme sont rangés dans `scripts/sh`, `scripts/bat` et
`scripts/ps1`. L'application démarre en local sur `http://127.0.0.1:5000` et ouvre le
navigateur seule. Le mode serveur multi-utilisateurs n'est pas encore implémenté (v10).
La documentation complète est dans `docs/` (developer, security, usage, tech watch).

Formats d'entrée en local: json, syslog, csv, Elastic/ECS, Snort, EVTX, PCAP. EVTX et
PCAP requièrent `python-evtx` et `dpkt` (voir requirements.txt) et restent locaux.

## Chiffrement au repos (optionnel)

Les artefacts sensibles (tickets, signaux, événements) peuvent être chiffrés sur disque.
Désactivé par défaut. Pour l'activer:

| Étape | Commande |
| --- | --- |
| Générer une clé (modèle clé USB) | `python -m core.vault keygen /chemin/vault.key` |
| Lancer avec la clé | `SIEM_ENCRYPT=1 SIEM_KEYFILE=/chemin/vault.key python launch.py local` |
| Ou avec une passphrase | `SIEM_ENCRYPT=1 SIEM_KEY="ma passphrase" python launch.py local` |

Le chiffrement utilise Fernet (AES plus HMAC, authentifié) de la bibliothèque `cryptography`.
Sans la clé les fichiers sont illisibles, et l'app refuse de démarrer en mode chiffré sans
clé. La clé ne doit jamais etre stockée avec les données.

---

## 1. Résumé

Mini SIEM v6 ajoute la détection d'intégrité des services IA locaux (Ollama, LM Studio, llama.cpp, vLLM, LocalAI), en s'appuyant sur MITRE ATLAS plutôt que MITRE ATT&CK pour ce domaine.

Il ne repose pas sur des signatures par hash. Il détecte des patterns comportementaux, ce qui lui permet de détecter des variantes obfusquées ou renommées que les outils à base de signatures manquent.

Le moteur analyse :
- Les logs Windows, syslog RFC 3164/5424, CEF, NXLog et Winlogbeat
- Les Script Blocks PowerShell (EventID 4104) : obfuscation, AMSI bypass, download cradles
- Les mécanismes de persistance : registry Run, WMI subscription, startup folder, schtasks inline
- L élévation de privilèges : ajout groupe admin, UAC bypass, credential dump
- Les commandes Linux/Unix suspectes : chmod +s, cron, curl pipe bash, reverse shell
- Les événements auditd au niveau kernel : EXECVE, SYSCALL, PATH
- Les logs d authentification Linux : SSH, PAM, sudo
- L intégrité des services IA locaux : remplacement de modèle, port swap, MITM local
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
- IA locale : intégrité fichiers modèle, anomalie port/process, MITM proxy local

**Statut : v6 terminée. v7 en développement (baseline de légitimité).**

---

## 2. Architecture

```
Sources de logs (Windows / Sysmon / PowerShell / RFC 3164 / RFC 5424 / CEF / NXLog / Winlogbeat
                 auditd EXECVE/SYSCALL/PATH / auth.log PAM/SSH/sudo
                 logs services IA locaux : Ollama, LM Studio, llama.cpp, vLLM, LocalAI)
    |
Parseur syslog : auto-détection de format
    |
Normaliseur v5 : routage par source
  |- auditd  -> reconstruction args EXECVE (a0/a1/a2...), décodage hex, uid/auid
  |- auth    -> parsing messages syslog (regex SSH/sudo/PAM)
  |- autres  -> chemin v4 inchangé (Windows/Sysmon/générique)
    |
CanonicalEvent (immuable)
    |
Détection conditionnelle par OS (platform.system())
  |- Windows
  |     |- Layer 1 Signature    : ransomware_v4
  |     |- Layer 2 Behavioral   : powershell_sigma (4 YAML) + lotl_sigma + spawn suspects
  |     |- Layer 3 Corrélation  : séquences temporelles recon -> exec
  |- Linux
        |- Layer 1 Signature    : ransomware_linux
        |- Layer 2 Behavioral   : bash_sigma (3 YAML) + linux_auditd
        |- Layer 3 Auth correl. : linux_auth (brute force temporel)
    |
Détection IA locale (inconditionnelle, Windows ET Linux)
  |- ai_network   : port swap, process inattendu sur port IA, MITM local
  |- ai_integrity : hash fichiers modèle (.gguf/.bin/.safetensors), baseline auto-apprise
    |
Déduplicateur : fusion des Signals redondants + scoring agrégé (max + 0.05 par source)
    |
Corrélateur : agrégation en alertes avec sévérité
    |
Sortie JSONL (events, signals, alerts, timelines)
```

### Modules

| Module | Rôle |
|--------|------|
| `syslog_parser.py` | Parse RFC 3164, RFC 5424, CEF, JSON NXLog/Winlogbeat |
| `normalizer.py` | Routage par source : auditd / auth / générique -> CanonicalEvent |
| `process_tree.py` | Construit l index parent->enfant, détecte les spawn suspects |
| `lotl_sigma.py` | 8 règles LOTL + EventID 4698/4699 + spawn suspects |
| `powershell_sigma.py` | Chargeur Sigma multi-fichiers YAML (Windows) |
| `bash_sigma.py` | Chargeur Sigma multi-fichiers YAML (Linux) |
| `linux_auditd.py` | 5 détecteurs auditd : fichiers sensibles, chmod setuid, useradd, connect, EXECVE |
| `linux_auth.py` | 4 détecteurs auth : brute force SSH, root login, sudo, authorized_keys |
| `ransomware_linux.py` | Détection ransomware adaptée Linux (/tmp, uid=0, outils chiffrement) |
| `ai_baseline.py` | Baselines IA pré-entraînées (Ollama, LM Studio...) + apprentissage anti-poisoning |
| `ai_network.py` | Détection port swap, process inattendu sur port IA, MITM local |
| `ai_integrity.py` | Hash fichiers modèle, détection remplacement (modèle empoisonné/backdoor) |
| `deduplicator.py` | Fusion des Signals sur même event_id, score = max + 0.05 x (n sources - 1) |
| `engine.py` | Dispatch conditionnel OS + détection IA inconditionnelle + déduplication |
| `correlator.py` | Signals -> Alerts avec sévérité calculée |
| `reporter.py` | Export JSONL : events, signals, alerts, timelines |

### Fichiers Sigma

| Fichier | OS | Domaine | Techniques |
|---------|-----|---------|-----------|
| `ps_scriptblock.yaml` | Windows | Script Block 4104, encodage, IEX, AMSI, recon | T1059.001, T1027, T1562 |
| `ps_persistence.yaml` | Windows | Registry Run, WMI sub, startup, schtasks inline | T1547.001, T1053.005, T1546.003 |
| `ps_privilege_escalation.yaml` | Windows | Admin group add, UAC bypass, credential dump | T1098, T1548.002, T1003 |
| `linux_suspicious.yaml` | Linux | chmod +s, cron, curl pipe bash, reverse shell | T1059.004, T1053.003, T1222.002 |
| `linux_auditd.yaml` | Linux | Privesc tools, container escape, kernel exploits, LD_PRELOAD | T1548, T1003, T1574.006, T1543.002 |
| `linux_auth.yaml` | Linux | SSH failure, root login, sudo dangereux, authorized_keys | T1110, T1078.003, T1548.003 |
| `ai_model_integrity.yaml` | Windows/Linux | Ecriture fichiers modele, bind sur ports IA connus | AML.T0018, AML.T0012 |

---

## 3. Détection IA locale (v6)

### Frameworks couverts (baselines pré-entraînées)

| Framework | Port par défaut | Chemins modèle |
|-----------|-----------------|----------------|
| Ollama | 11434 | `~/.ollama/models/` |
| LM Studio | 1234 | `~/LM Studio/models/` |
| llama.cpp (llama-server) | 8080 | `/opt/models/`, `~/models/` |
| vLLM | 8000 | `/opt/vllm/models/` |
| LocalAI | 8080 | `/usr/share/local-ai/models/` |

### Détecteurs

| Indicateur | Technique ATLAS | Score |
|-----------|-----------------|-------|
| Process inattendu bind sur port IA connu (remplacement serveur) | AML.T0012 | 0.90 |
| Process inattendu connect vers port IA connu (MITM proxy local) | AML.T0040 | 0.70 |
| Hash fichier modèle modifié (modèle empoisonné/backdoor) | AML.T0018 | 0.92 |

### Anti-poisoning de la baseline

L apprentissage automatique (`ai_baseline.observe()`) n enregistre une observation que si elle correspond à un framework pré-entraîné (process_name ET port attendus). Une observation hors baseline pré-entraînée déclenche un signal immédiat et n est **jamais** apprise, ce qui empêche l empoisonnement de la baseline si un MITM est déjà actif au moment du premier run.

---

## 4. Règles de détection, v5/v6

### Script Block PowerShell (EventID 4104)

| Indicateur | Sévérité |
|-----------|----------|
| `-EncodedCommand` / `-enc` | High |
| `Invoke-Expression` / `IEX` | High |
| AMSI bypass (`amsiInitFailed`, `AmsiScanBuffer`) | Critical |
| `-ExecutionPolicy Bypass` | High |
| `DownloadString` / `Invoke-WebRequest` | Critical |
| Obfuscation (backtick, char cast, `-join`) | High |
| `whoami` / énumération d identité | Medium |

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
| Brute force SSH | 5 échecs en 120 secondes, T1110.001 |
| Root login SSH direct | Présence unique, T1078.003 |
| `sudo /bin/bash`, `sudo -s`, `sudo /usr/bin/vim` | Commande dangereuse, T1548.003 |
| Modification `authorized_keys` | Opération write/create, T1098.004 |

---

## 5. Limitations

| Limitation | Détail |
|------------|--------|
| Environnement lab uniquement | Non testé sur des volumes de logs de production |
| Nécessite une ingestion correcte | Sysmon (Windows) et auditd (Linux) doivent être activés |
| Pas de baseline de légitimité générale | Faux positifs sur activités admin et déploiement |
| Pas de capacité de blocage | Détection et alerting uniquement, pas de réponse automatisée |
| Évasion possible | Un attaquant avancé peut contourner les règles comportementales |
| `systemctl enable` : taux de FP élevé | Corrélation avec d autres signaux nécessaire avant intervention |
| IA locale : détection post-compromission uniquement | Ne détecte pas l installation d un MITM, seulement sa présence active |
| IA locale : baseline limitée à 5 frameworks | Frameworks custom/maison non couverts par défaut |

---

## 6. Modèle de menace

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
| Outils offensifs Linux (bloodhound, chisel...) | Oui |
| Kernel exploit (DirtyCow, Dirty Pipe) | Oui (par nom) |
| Container escape | Oui |
| Spawn suspect (Office -> PowerShell) | Oui |
| Signals redondants fusionnés | Oui (deduplicator v5.5) |
| Remplacement modèle IA local | Oui (hash mismatch) |
| Port swap service IA local | Oui |
| MITM proxy local sur service IA | Oui (post-compromission) |

---

## 7. Roadmap

- [x] Moteur de règles Sigma, détection PowerShell
- [x] Détecteur comportemental ransomware (Windows)
- [x] Support multi-format syslog (RFC 3164, RFC 5424, CEF, NXLog, Winlogbeat)
- [x] Process tree, modélisation parent->enfant
- [x] 8 règles LOTL avec tagging MITRE ATT&CK
- [x] Chargeur Sigma multi-fichiers par domaine
- [x] Détection persistance Windows (registry Run, WMI sub, startup)
- [x] Détection élévation de privilèges Windows (admin group, UAC bypass, credential dump)
- [x] Détection commandes Linux (chmod +s, cron, reverse shell)
- [x] Détection Linux étendue : auditd, PAM, systemd (v5)
- [x] Normalisation auditd : reconstruction EXECVE args, décodage hex, routing par source
- [x] Détecteur ransomware Linux (/tmp, uid=0, outils chiffrement, ransom notes)
- [x] Règles Sigma : linux_auditd.yaml (kernel exploits, outils offensifs, tunneling)
- [x] Déduplication des Signals + scoring agrégé (v5.5)
- [x] Détection intégrité IA locale : ai_network, ai_integrity, baselines pré-entraînées (v6)
- [x] Détection MITM local sur services IA (port swap, process inattendu)
- [ ] Baseline de légitimité pour réduire les faux positifs (v7)
- [ ] SOAR : réponse automatique (v8)

---

## 8. Références

- MITRE ATT&CK : T1059.001 (PowerShell), T1486 (Ransomware), T1490 (Shadow Copy), T1047 (WMI), T1218 (LOLBIN), T1547.001 (Registry Run), T1548.002 (UAC Bypass), T1003 (Credential Dumping), T1068 (Kernel Exploit), T1572 (Tunneling)
- MITRE ATLAS : AML.T0012 (Valid Accounts - local pivot), AML.T0018 (Backdoor ML Model), AML.T0040 (Network Traffic Capture)
- Spécification des règles Sigma : https://github.com/SigmaHQ/sigma
- Format de log Sysmon : https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Windows Event ID 4104 : Script Block Logging
- RFC 3164 / RFC 5424 : Syslog Protocol
- Documentation auditd Linux : https://linux.die.net/man/8/auditd
- MITRE ATT&CK Framework : https://attack.mitre.org
- MITRE ATLAS Framework : https://atlas.mitre.org

---

> **Contenu défensif et éducatif uniquement.**
> Construit en environnement lab isolé. Aucun système de production utilisé.
