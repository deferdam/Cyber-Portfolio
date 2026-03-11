# Mini-SIEM v4 — Documentation

<div style="background: linear-gradient(135deg, #1a1a3e 0%, #2d3561 50%, #1e3a5f 100%); padding: 2rem; border-radius: 12px; margin-bottom: 2rem;">
<h2 style="color: #7c9ef8; margin: 0 0 0.5rem 0;">🛡️ Mini-SIEM v4</h2>
<p style="color: #a8b8e8; margin: 0;">Multi-file Sigma · Persistence · Privilege Escalation · Linux Detection</p>
</div>

## Apports de la v4

| Fonctionnalité | v3 | v4 |
|---|---|---|
| Fichiers Sigma PowerShell | 1 (`powershell_suspicious.yaml`) | **4 fichiers** par domaine |
| Détection Script Block (4104) | Partielle | ✓ Complète — obfuscation, AMSI, exec bypass |
| Persistance | ✗ | ✓ Registry Run, WMI subscription, startup |
| Élévation de privilèges | ✗ | ✓ Admin group add, UAC bypass, credential dump |
| Linux / Unix | ✗ | ✓ chmod +s, cron, reverse shell, /etc/passwd |
| Chargeur Sigma | `rule_path: str` (1 fichier) | `rule_paths: List[str]` (N fichiers) |
| Résolution des chemins YAML | Relatif au cwd | ✓ Relatif au module (`__file__`) |
| Isolation erreur fichier manquant | `return []` (exit total) | ✓ `continue` (skip + warning) |

## Architecture v4

```
engine.py
  ├── _PS_RULE_FILES = [            ← liste déclarative, seul endroit à modifier
  │     ps_scriptblock.yaml
  │     ps_persistence.yaml
  │     ps_privilege_escalation.yaml
  │     powershell_suspicious.yaml
  │   ]
  │
  ├── Layer 1 — Signature      : ransomware_v4
  ├── Layer 2 — Behavioral     : powershell_sigma(rule_paths) + lotl_sigma
  └── Layer 3 — Correlation    : correlate_recon_sequence
```

## Fichiers ajoutés

```
src/detect/modules/
├── ps_scriptblock.yaml           # Nouveau — Script Block 4104 complet
├── ps_persistence.yaml           # Nouveau — Persistance Windows
├── ps_privilege_escalation.yaml  # Nouveau — Élévation de privilèges
└── linux_suspicious.yaml         # Nouveau — Commandes Linux suspectes
```

## Lancement

```bat
run_siem.bat large
```

Aucun changement de CLI. Les nouvelles règles sont chargées automatiquement.

## Roadmap

| Version | Contenu | Statut |
|---------|---------|--------|
| v5 | Détection Linux étendue — auditd, PAM, systemd | Planifié |
| v5.5 | Déduplication des Signals + scoring agrégé | Recommandé |
| v6 | Enrichissement **différé** — URL/IP/hash reputation | Planifié |
| v7 | Persistance des données — baseline, historique | Requis avant v6 |
| v8 | SOAR — réponse automatique | Long terme |
