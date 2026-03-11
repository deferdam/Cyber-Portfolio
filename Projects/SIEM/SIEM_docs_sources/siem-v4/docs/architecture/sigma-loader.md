# Chargeur Sigma multi-fichiers

## Ajout d'un nouveau fichier Sigma

1. Créer le fichier YAML dans `src/detect/modules/` en respectant le format Sigma minimal
2. Ajouter son chemin dans `_PS_RULE_FILES` dans `engine.py`
3. C'est tout

```python
# engine.py
_PS_RULE_FILES = [
    str(_MODULES_DIR / "ps_scriptblock.yaml"),
    str(_MODULES_DIR / "ps_persistence.yaml"),
    str(_MODULES_DIR / "ps_privilege_escalation.yaml"),
    str(_MODULES_DIR / "powershell_suspicious.yaml"),
    str(_MODULES_DIR / "ps_mon_nouveau_fichier.yaml"),  # ← ajout ici
]
```

## Format YAML minimal requis

Le parser `_parse_simple_sigma_yaml()` est minimaliste. Contraintes strictes :

```yaml
title: Mon titre                      # obligatoire
level: high                           # low/medium/high/critical
detection:
    selection_monnom:                 # doit commencer par "selection"
        ScriptBlockText|contains:     # un seul champ par bloc
            - 'pattern1'
            - 'pattern2'
    condition: 1 of selection_*       # non interprété — déclaratif seulement
```

**Contraintes du parser (hard limits) :**

| Contrainte | Raison |
|---|---|
| Indentation 4/8/12 espaces | Pas de tabs — le parser est un state machine sur l'indentation |
| Un seul champ par `selection_*` | Si deux champs dans le même bloc, seul le dernier est conservé |
| Modificateur `\|contains` uniquement | `\|startswith`, `\|endswith`, `\|re` ne sont pas supportés |
| Bloc `detection:` obligatoire | Le parser cherche cette clé pour entrer en mode détection |

## Champs reconnus

| Champ YAML | Source dans CanonicalEvent |
|---|---|
| `ScriptBlockText` | `ev.raw.get("ScriptBlockText")` |
| `CommandLine` | `ev.process.command_line` |

Tout autre champ produit un match nul silencieux — il ne crash pas, il ne matche rien.

## Priorité de matching

Pour un événement donné, **toutes les sélections de tous les fichiers** sont évaluées indépendamment. Un Signal est produit par fichier qui génère au moins un match. Si `ps_scriptblock.yaml` et `ps_persistence.yaml` matchent tous deux le même événement, **deux Signals distincts** sont produits avec leurs `rule.title` respectifs.

C'est intentionnel — un script PowerShell peut simultanément être obfusqué (scriptblock) ET créer une registry Run key (persistence). Les deux Signals contribuent au scoring global dans le corrélateur.
