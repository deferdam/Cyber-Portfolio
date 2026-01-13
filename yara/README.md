# YARA — Détection et classification (apprentissage)

Ce dossier regroupe les règles YARA que j’ai écrites dans un contexte
d’apprentissage Blue Team et d’analyse défensive.

## Objectifs
- Identifier des échantillons connus ou similaires
- Extraire des patterns fiables à partir d’analyses statiques
- Comprendre les limites et les faux positifs

## Méthodologie
1. Analyse du binaire (strings, fonctions clés, comportements)
2. Sélection d’indicateurs stables
3. Écriture de règles simples et lisibles
4. Test sur échantillons propres / pédagogiques
5. Documentation des limites

## Organisation
Chaque sous-dossier correspond à un projet ou une famille analysée.
Les règles ne sont **jamais utilisées en production**.
