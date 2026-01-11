# Secure File Vault – Présentation

Secure File Vault est une application locale permettant à un utilisateur de chiffrer et déchiffrer des fichiers à l’aide d’un mot de passe. L’objectif principal est de protéger la confidentialité des fichiers sensibles en cas d’accès non autorisé à l’ordinateur ou aux sauvegardes.

L’utilisateur :
- choisit s’il souhaite chiffrer ou déchiffrer,
- sélectionne un fichier (manuellement ou via un explorateur de fichiers),
- saisit un mot de passe fort.

Fonctionnement interne :
- une clé est dérivée du mot de passe à l’aide de PBKDF2-HMAC-SHA256 avec un sel aléatoire,
- le contenu du fichier est chiffré à l’aide d’un algorithme sécurisé (Fernet) utilisant cette clé,
- le sel et le texte chiffré sont stockés ensemble afin de permettre le déchiffrement ultérieur.

L’application ne conserve jamais la clé. Le seul secret que l’utilisateur doit retenir est le mot de passe.

Ce dépôt contient actuellement :
- le module de sécurité principal : `key_management.py`
- l’interface en ligne de commande : `cli.py`
- la documentation et la configuration pour un site de documentation simple (MkDocs).
