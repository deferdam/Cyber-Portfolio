# Vue d’ensemble du système

## 1. Résumé exécutif

Le **Ransomware Behavior Detector** est un moteur de détection hybride combinant heuristiques comportementales et apprentissage automatique.  
Il surveille les journaux système et détecte aussi bien les ransomwares à chiffrement rapide que les tentatives de chiffrement lentes.

Le système analyse notamment :
- Les opérations sur le système de fichiers
- Les métadonnées des processus (niveau de privilèges, chemin d’exécution)
- Les schémas d’extensions de fichiers
- Les rafales de modifications de fichiers à haute fréquence
- Les comportements réseau suspects

L’apprentissage automatique améliore la précision globale et réduit les faux positifs en apprenant à partir de rapports étiquetés.

---------------------------------------------

## 2. Conception technique et architecture

### Schéma d’architecture

```
Journaux bruts (.jsonl)
    ↓
Détecteur heuristique (ransomware_detector.py)
    ↓
detection_report.json
    ↓
Entraînement Machine Learning (train.py, ml_pipeline.py)
    ↓
ransomware_model.joblib
    ↓
apply_model.py
    ↓
detection_report_with_ml.json
```

### Modules principaux

| Module | Rôle |
|-------|------|
| ransomware_detector.py | Extrait les indicateurs comportementaux et génère un rapport de détection structuré |
| ml_pipeline.py | Transforme le rapport de détection en vecteurs de caractéristiques pour le ML |
| train.py | Entraîne le modèle RandomForest à partir d’exemples étiquetés |
| apply_model.py | Évalue les processus selon une probabilité de comportement ransomware |

---------------------------------------------

## 3. Analyse de sécurité

### Modèle de menace

| Type de comportement | Détection prise en charge |
|---------------------|---------------------------|
| Ransomware à chiffrement rapide | Oui |
| Ransomware à chiffrement lent | Oui |
| Chemins d’exécution anormaux | Oui |
| Détection d’élévation de privilèges | Oui |
| Connexions sortantes suspectes | Oui |

### Hypothèses

- Les journaux sont fiables et contiennent des horodatages et métadonnées de fichiers corrects.
- Les noms de processus et PID restent cohérents durant la journalisation.
- Des exemples étiquetés sont disponibles pour l’entraînement du modèle.

### Limitations

- L’évasion reste théoriquement possible.
- Les performances réelles dépendent fortement de la qualité des données.
- Le système génère des alertes mais ne bloque pas l’exécution.

---------------------------------------------

## 4. Méthodologie de test et résultats

Un jeu de données synthétique a été créé afin de simuler des comportements ransomware et une activité système normale.

Métriques d’évaluation produites par le modèle entraîné :

| Métrique | Valeur |
|---------|--------|
| Précision | 1.00 |
| Rappel | 1.00 |
| Exactitude | 1.00 |

Ces résultats ont été obtenus dans un environnement de test synthétique.  
Des jeux de données réels produiront des scores plus faibles et nécessiteront un réentraînement périodique.

---------------------------------------------

## 5. Rôles et contributions de l’équipe

Format à compléter ultérieurement :

- Membre 1 – Responsabilités à définir
- Membre 2 – Responsabilités à définir
- Membre 3 – Responsabilités à définir

---------------------------------------------

## 6. Références et sources de données

- Framework MITRE ATT&CK : T1486 – Encryption for Impact
- Format de journalisation Sysinternals Sysmon
- Articles de recherche sur la classification comportementale des ransomwares
- Type de jeu de données : journaux synthétiques simulant des intrusions et ransomwares
