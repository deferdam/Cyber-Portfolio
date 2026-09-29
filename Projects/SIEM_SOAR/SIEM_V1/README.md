# Mini SIEM, Moteur de détection comportementale Sigma

> Moteur de détection comportementale construit en lab, à des fins d'apprentissage.  
> Périmètre défensif uniquement. Aucun binaire malveillant hébergé.

---

## 1. Résumé

Mini SIEM est un moteur de détection léger qui ingère des logs Windows et les score contre des règles comportementales Sigma.

Il ne repose pas sur des signatures par hash. Il détecte des patterns comportementaux, ce qui lui permet de détecter des variantes obfusquées ou renommées que les outils à base de signatures manquent.

Le moteur analyse :
- Les logs Windows (Sysmon, PowerShell Script Block, Security)
- Les patterns d'exécution PowerShell
- La création de processus et les relations parent-enfant
- Des indicateurs comportementaux pondérés en score de risque (0–100)

Couverture actuelle :
- Exécution PowerShell suspecte (EncodedCommand, IEX, DownloadString, WebClient)
- Patterns comportementaux ransomware (mass rename, suppression shadow copies, extension suspecte)

**Statut : v1 terminée. v2 en développement.**

---

## 2. Architecture

```
Sources de logs (Windows Event Logs / Sysmon / PowerShell / JSON-Syslog)
    ↓
Normaliseur, parsing et extraction des champs
    ↓
Moteur de règles Sigma, matching comportemental
    ↓
Scorer, agrégation pondérée des indicateurs
    ↓
Sortie JSON
    {
      "score": 85,
      "classification": "potential_malware_execution",
      "indicators": [...],
      "date": "2025-04-23T09:15:32Z"
    }
```

### Modules

| Module | Rôle |
|--------|------|
| `normalizer.py` | Parse les logs bruts en événements structurés |
| `sigma_engine.py` | Charge et évalue les règles Sigma sur les événements |
| `scorer.py` | Agrège les indicateurs matchés en score de risque pondéré |
| `correlator.py` | Relie les événements liés dans une fenêtre temporelle |
| `reporter.py` | Produit les alertes JSON structurées |

---

## 3. Règles de détection, v1

### Détection PowerShell (Event ID 4104, Script Block Logging)

Déclenche sur l'un des patterns suivants :

| Indicateur | Sévérité |
|-----------|----------|
| `-EncodedCommand` | High |
| `Invoke-Expression` | High |
| `DownloadString` + URL externe | Critical |
| Instanciation `WebClient` | Medium |
| `whoami` / énumération d'identité | Medium |

**Condition :** `1 of selection*`, un seul indicateur suffit à déclencher.  
**Faux positifs connus :** scripts admin légitimes utilisant WebClient ou IEX, tâches planifiées d'inventaire.  
**Correction prévue (v2) :** scoring pondéré par indicateur pour réduire le taux de faux positifs.

### Détection comportementale ransomware

Déclenche sur :

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
| Taux de faux positifs v1 | Condition `1 of selection*` intentionnellement large |
| Pas de capacité de blocage | Détection et alerting uniquement, pas de réponse automatisée |
| Évasion possible | Un attaquant avancé peut contourner les règles comportementales |

---

## 5. Modèle de menace

| Comportement | Détecté |
|----------|----------|
| Exécution PowerShell obfusquée | Oui |
| Téléchargement de payload distant | Oui |
| Exécution en mémoire (fileless) | Partiel |
| Ransomware rapide | Oui |
| Ransomware lent | Oui |
| Suppression des shadow copies | Oui |
| Escalade de privilèges via PS | Partiel |

---

## 6. Roadmap

- [x] Moteur de règles Sigma, détection PowerShell
- [x] Détecteur comportemental ransomware
- [ ] Scoring pondéré par indicateur (v2)
- [ ] Détection de persistance (scheduled tasks, clés de registre)
- [ ] Corrélation multi-sources sur fenêtre temporelle
- [ ] Interface web minimale pour la revue des alertes

---

## 7. Références

- MITRE ATT&CK : T1059.001 (PowerShell), T1486 (Data Encrypted for Impact)
- Spécification des règles Sigma : https://github.com/SigmaHQ/sigma
- Format de log Sysmon : https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Windows Event ID 4104, Script Block Logging

---

> **Contenu défensif et éducatif uniquement.**  
> Construit en environnement lab isolé. Aucun système de production utilisé.
