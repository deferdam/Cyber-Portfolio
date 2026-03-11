# Invariants de sécurité v2

Les invariants v1 sont maintenus. Trois nouveaux invariants s'ajoutent.

## Invariants hérités de v1

| # | Invariant | Mécanisme |
|---|-----------|-----------|
| 1 | CanonicalEvent immuable | `frozen=True` |
| 2 | signal_id déterministe | SHA-256 du contenu structurel |
| 3 | Isolation des modules | Architecture en couches |
| 4 | Ordre des événements garanti | `events.sort(key=lambda e: e.event_time_utc)` |
| 5 | Séparation Signals/Alerts | Aucun module ne produit d'Alert |
| 6 | Complexité O(n) | Un seul parcours par couche |

## Invariant 7 — Process Tree read-only après construction

```python
tree = build_tree(events)   # construit une fois
# → passé en lecture seule à lotl_sigma.run(events, tree=tree)
```

Aucun module de détection ne peut appeler `tree.build()`. La méthode `build()` n'est publique que pour le factory `build_tree()` dans `engine.py`.

**Pourquoi c'est critique** : si un module appelait `tree.build()` avec un sous-ensemble d'événements, tous les modules suivants verraient un arbre incomplet. La séquentialité des modules garantit la cohérence des données partagées.

## Invariant 8 — Parseur syslog sans effet de bord

`syslog_parser.py` est une bibliothèque pure :
- Pas de socket réseau
- Pas de subprocess
- Pas d'`eval()` ou `exec()`
- Pas d'écriture fichier
- Pas de variable globale mutable

Toutes les fonctions sont de la forme `str → Optional[Dict[str, Any]]`. Les erreurs de parsing sont **catégoriquement silencieuses** — une ligne malformée produit `None`, jamais une exception propagée.

## Invariant 9 — Isolation des erreurs par couche

```python
# engine.py — chaque couche est protégée
try:
    signals.extend(lotl_sigma.run(events, tree=tree))
except Exception as exc:
    print(f"[engine] ERROR lotl_sigma: {exc}", file=sys.stderr)
    # Le pipeline continue
```

**Conséquence sur la sécurité** : une règle LOTL avec une regex invalide ne fait pas crasher le pipeline — elle produit un log stderr et est ignorée. En revanche, les Signals de cette règle sont perdus pour cette exécution. La supervision des logs stderr est donc critique.

!!! danger "Risque d'angle mort"
    Si `lotl_sigma.run()` lève une exception silencieuse, les règles LOTL ne produisent aucun Signal pour cette exécution sans alerte visible dans `alerts.jsonl`. Implémenter une métrique de santé des couches (v3) est recommandé.

## Invariant 10 — Clés de stockage scoped par host

Dans le `ProcessTree`, tous les nœuds sont indexés par `(hostname, pid)` et non par `pid` seul :

```python
_nodes: Dict[Tuple[str, int], ProcessNode]
# clé = (hostname, pid)
```

Un PID 1234 sur `WIN-SRV01` et un PID 1234 sur `WIN-SRV02` sont deux nœuds distincts. Sans ce scope, des événements de machines différentes se contamineraient mutuellement dans l'arbre.
