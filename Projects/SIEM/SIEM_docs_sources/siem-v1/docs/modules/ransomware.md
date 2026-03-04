# Détection Ransomware

Modules : `ransomware_core.py` + `ransomware_v4.py`

## Architecture en deux couches

```
ransomware_v4.py
  ├── Adaptateur : CanonicalEvent → Dict pour ransomware_core
  └── Adaptateur : rapport ransomware_core → Signal

ransomware_core.py
  ├── detect_ransomware()       ← fonction principale
  ├── _sliding_burst_unique_files()
  ├── _check_extension_diversity()
  ├── _check_vss_deletion()
  └── _check_c2_indicators()
```

Cette séparation permet de faire évoluer `ransomware_core.py` indépendamment du schéma `CanonicalEvent`.

## Indicateurs comportementaux détectés

### 1. Écriture massive de fichiers (Mass File Write)

```python
BURST_WINDOW_SECONDS = 60
UNIQUE_FILE_THRESHOLD = 20
```

Un processus qui écrit plus de **20 fichiers uniques en 60 secondes** est considéré suspect. L'algorithme utilise une fenêtre glissante (`_sliding_burst_unique_files`) :

```
t=0s  write /Users/victim/doc1.docx.encrypted
t=2s  write /Users/victim/doc2.docx.encrypted
...
t=58s write /Users/victim/doc21.docx.encrypted
→ Score += mass_write_factor
```

### 2. Diversité d'extensions (Extension Diversity)

Le ransomware génère typiquement une seule extension sur de nombreux fichiers. Un processus qui renomme/écrit des fichiers avec une extension unique jamais vue dans le contexte système est suspect.

```python
SUSPICIOUS_EXTENSIONS = {
    "encrypted", "enc", "locked", "crypt", "crypto",
    "vault", "zepto", "locky", "cerber", "wnry", ...
}
```

Si l'extension correspond à cette liste **ou** si le processus écrit des fichiers avec une seule extension anormalement répétée, le score augmente.

### 3. Suppression de clichés VSS (VSS Deletion)

```python
VSS_PATTERNS = [
    "vssadmin delete shadows",
    "wmic shadowcopy delete",
    "wbadmin delete catalog",
    "bcdedit /set {default} recoveryenabled no",
    "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
]
```

La suppression des shadow copies est un indicateur quasi-pathognomonique du ransomware en phase pré-chiffrement. Ce seul indicateur peut suffire à produire une alerte de niveau `critical`.

### 4. Indicateurs C2 réseau (C2 Network)

- Connexions vers des IP non privées depuis un processus à haute activité fichier
- Ports suspects : 4444, 1337, 8080, 9999
- Protocole TCP outbound depuis un processus à `integrity_level = High`

## Calcul du score

Le score final est une somme pondérée des facteurs de risque :

```python
score = 0.0
if mass_write:     score += 0.40
if suspicious_ext: score += 0.30
if vss_deletion:   score += 0.40
if c2_indicators:  score += 0.25
score = min(score, 1.0)
```

!!! note "Additivité"
    Les facteurs s'additionnent. Un processus qui combine écriture massive + extension suspecte + suppression VSS atteint 1.0 (score tronqué à 1.0).

## Seuils d'alerte

| Score | Sévérité | Action recommandée |
|-------|----------|--------------------|
| ≥ 0.85 | `critical` | Isolation immédiate de la machine |
| 0.60–0.84 | `high` | Investigation prioritaire < 1h |
| 0.40–0.59 | `medium` | Investigation planifiée |
| 0.30–0.39 | `low` | Surveillance renforcée |
| < 0.30 | *ignoré* | Signal non promu en alerte |

## Sortie : Signal ransomware

```python
Signal(
    signal_id    = f"rw_{process_key}",
    signal_type  = "ransomware_behavior",
    score        = 0.87,
    confidence   = 0.87,
    risk_factors = ["mass_file_write", "vss_deletion", "suspicious_extension"],
    evidence_event_ids = ["abc123", "def456", ...],
    explanation  = "Process powershell.exe (PID 4288): 45 unique files written in 60s...",
    recommended_actions = [
        "Isoler la machine WIN-SRV01",
        "Lancer une analyse forensique mémoire sur PID 4288",
        "Vérifier les derniers fichiers modifiés dans C:\\Users\\"
    ]
)
```

## Limitations

!!! warning "Faux positifs connus"
    - **Antivirus / EDR** : un scan complet peut déclencher le seuil d'écriture massive si l'AV écrit des logs de quarantaine
    - **Backup software** : les agents de sauvegarde (Veeam, Acronis) créent de nombreux fichiers rapidement
    - **Compilateurs** : une compilation `make -j8` peut écrire massivement dans un répertoire temporaire

    Sans baseline de légitimité (v2), le taux de faux positifs est structurellement élevé pour ces cas.
