# v7 — SOAR (Réponse automatique)

## Périmètre

Le SOAR (Security Orchestration, Automation and Response) est la couche qui **agit** en réponse aux Alerts — là où le SIEM se contente de détecter et de notifier.

## Actions prévues

| Action | Condition déclenchante | Risque |
|--------|----------------------|--------|
| Block IP (firewall) | Alert `critical` + IP externe connue | Moyen — faux positifs possibles |
| Kill process | Signal ransomware score ≥ 0.95 | Élevé — peut interrompre un processus légitime |
| Isoler machine (réseau) | Alert `critical` + ransomware confirmé | Élevé — interruption de service |
| Revoke user session | Credential dump détecté | Moyen |
| Chmod -x sur fichier | Exécutable déposé dans /tmp | Faible |

## Prérequis impératifs avant v7

1. **Taux de faux positifs < 5%** — une réponse automatique sur un faux positif est souvent pire que l'attaque elle-même (interruption de production)
2. **Enrichissement v6 opérationnel** — la confidence d'un Signal doit être élevée avant toute action
3. **Mode dry-run** — toute action SOAR doit pouvoir être simulée sans effet réel
4. **Audit log des actions** — chaque action automatique doit être tracée (qui, quoi, quand, pourquoi)

## Architecture prévue

```
alerts.jsonl
    ↓
soar/
├── orchestrator.py    # Lit les Alerts, décide des actions
├── firewall.py        # iptables / Windows Firewall
├── process_killer.py  # kill -9 / taskkill
├── network_isolator.py
└── audit_logger.py    # Log de toutes les actions
```

!!! danger "Ne jamais automatiser sans baseline"
    Un SOAR sans baseline de légitimité (v7/v8) va bloquer des IPs légitimes et tuer des processus système. La baseline est un prérequis non négociable.
