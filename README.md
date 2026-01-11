# Blue Team / Malware Analysis — Junior Cybersecurity Profile

## Pitch

Étudiant en 5ᵉ année à Epitech, orienté cybersécurité avec un focus Blue Team (SOC, analyse de malwares, détection).
Je monte un lab personnel (Windows / Linux / Parrot) pour analyser des samples, reproduire des scénarios SOC,
écrire des règles de détection et documenter mes investigations de manière structurée et éthique.


---

## Ce que je fais en ce moment

- Parcours **SOC / Blue Team** sur TryHackMe (SOC Level 1 terminé, suite en cours).
- Mise en place d’un **lab d’analyse malware** isolé (VM Windows, Ubuntu, Parrot).
- Première série de rapports publics :  
  - 1 writeup SOC / réseau (DNS, WHOIS, pings, couches réseau TCP/IP).  
  - 1 analyse guidée de malware basée sur un sample pédagogique public, reproduite dans un lab isolé avec une lecture orientée détection (SOC / Blue Team).

Mon travail consiste à reproduire l’analyse dans un lab isolé, documenter la méthodologie,
extraire les IOCs et produire une lecture orientée détection (SOC / Blue Team), dans `malware-analysis/`.

_(Le dépôt va évoluer au fur et à mesure de ma progression.)_

---

## Compétences techniques

- **Langages :** Python, C (lecture), Bash, Dart (projet mobile), Go (backend).
- **Systèmes & réseau :** Linux (Debian/Ubuntu), Windows, notions de réseaux (TCP/IP, DNS, WHOIS, ICMP).
- **Outils sécurité :** Wireshark, VirtualBox, Parrot/Kali, premiers usages de Ghidra (lecture statique basique) et Procmon (analyse comportementale).
- **Détection (en cours d’apprentissage) :** YARA, Sigma, MITRE ATT&CK.
- **Dev & projet :** Flutter, Firebase, APIs REST, bonnes pratiques de base (CORS, auth, stockage).

Je ne mets ici que ce que j’ai réellement utilisé sur des projets ou des labs.

---

## Projets publics (structure prévue)

### 1. `malware-analysis/`

> Analyses guidées de malwares ou de samples issus de sandboxes publiques, en environnement totalement isolé.

Pour chaque dossier de sample :

- `report.md` — rapport statique/dynamique + IOCs + mapping MITRE.
- `notes.md` — commandes utilisées, sorties d’outils, liens de ressources.
- **Pas de binaire publié**, uniquement du texte, des captures et éventuellement du pseudocode.

### 2. `soc-labs/`

> Exercices orientés SOC / blue team, souvent inspirés de TryHackMe/CTF.

Exemples :

- Analyse de logs réseau ou Windows.
- Mini playbooks : “que faire si je vois X dans les logs ?”.
- Idées de détections : premières règles Sigma / requêtes SIEM inspirées de Splunk (logique de filtrage et corrélation).

### 3. `tryhackme-writeups/`

> Notes synthétiques sur les rooms importantes, sans spoil total.

Pour chaque room :

- Objectif de la room.
- Techniques apprises (réseau, forensic, détection, etc.).
- Ce que j’en retiens pour un boulot de SOC / analyste.

### 4. `eip-project/` (projet Epitech sur 3 ans)

> Projet d’application mobile (Flutter) + backend (Go/Firebase) développé en équipe de 3.

- Co-fondateur du projet (EIP).
- Responsable sécurité applicative et backend (auth, règles de sécurité, CORS, durcissement basique).
- Objectif : déploiement sur App Store / Google Play + création d’une vraie structure.

---

## Règles éthiques & légales

- Aucun binaire malveillant, malware ou exploit exécutable n’est stocké dans ce dépôt.
- Aucune portion de code provenant d’un projet d’école privé, d’un travail d’équipe confidentiel ou d’un environnement professionnel n’est publiée sans autorisation.
- Les analyses de malwares sont réalisées **strictement dans un environnement isolé**, hors réseau public (VMs en Internal Network).
- Les exemples d’IOCs, règles YARA et Sigma sont pédagogiques et ne permettent pas de reproduire des actions malveillantes.
- Aucun nom, identifiant, ou donnée personnelle d'un membre d’équipe n’est publié.
- Le but du dépôt est **l’apprentissage**, la détection et la compréhension des menaces, jamais leur utilisation offensive.

## Autres projets techniques (hors cybersécurité)

Ce dépôt ne contient volontairement que mes travaux liés à la cybersécurité.  
Mes projets d’école et projets systèmes restent privés, mais en voici un aperçu :

- **AsmMiniLib** — réimplémentation de fonctions système bas niveau en assembleur.
- **RPG** — développement d’un jeu complet en C, architecture modulaire, moteur interne.
- **Corewar** — VM + assembleur + “warriors”, projet algorithmique avancé.
- **Neural Network** — implémentation d’un réseau de neurones from scratch.
- **Raytracer** — moteur 3D avec parsing de scène, éclairage, ombres et réflexion.
- **Zappy** — jeu réseau client-serveur multijoueur (C + réseau + IA basique).
- **Area** — automatisation de workflows type “IFTTT”.
- **Gomoku** — IA pour jeu de stratégie, heuristiques, algorithmes de recherche (minimax).

Ces projets sont conservés en **privé** (code complet disponible en entretien).

## Crédits & références

- Certains samples ou analyses guidées s’appuient sur des supports pédagogiques publics.
- Les analyses consistent en une reproduction méthodologique dans un lab isolé,
  avec une lecture orientée détection (SOC / Blue Team).
- Les sources pédagogiques sont publiques ou anonymisées lorsque nécessaire.
