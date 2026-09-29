# Invariants de sécurité

Les invariants listés ici sont des **garanties architecturales** — toute modification du code qui les violerait constitue une régression, indépendamment du fait que les tests passent.

## Invariant 1 — Immuabilité du CanonicalEvent

```python
@dataclass(frozen=True)
class CanonicalEvent:
    ...
```

`frozen=True` rend le dataclass non modifiable après construction. Toute tentative d'assignment sur un `CanonicalEvent` existant lève `FrozenInstanceError`.

**Pourquoi c'est critique** : les modules de détection reçoivent la *même* liste d'objets. Si un module pouvait modifier un événement, il altérerait les données vues par les modules suivants. Ce type de bug est notoire pour être silencieux et non déterministe.

## Invariant 2 — Déterminisme du signal_id ransomware

```python
# ransomware_v4.py
signal_id=f"rw_{pk}"
# où pk = process_key(name, pid, path) — fonction pure
```

Pour un même processus, le `signal_id` est identique à chaque replay. Cela permet de dédupliquer des runs successifs sans base de données.

**Limite documentée** : le PID peut être réutilisé par l'OS. En v1, on assume que les PID sont uniques dans la fenêtre d'analyse. V2 devrait utiliser le process GUID Sysmon.

## Invariant 3 — Isolation des modules

```python
# engine.py
signals.extend(ransomware_v4.run(events))
ps_signals = powershell_sigma.run(events, rule_path="powershell_suspicious.yaml")
```

Chaque module reçoit une copie de la liste (référence, mais les éléments sont immuables). Une exception non capturée dans un module est actuellement propagée. 

!!! warning "Point de fragilité v1"
    En v1, `engine.py` ne wrapping pas les appels en `try/except`. Une erreur dans `ransomware_v4` interrompt le pipeline entier. Ce point est corrigé en v2.

## Invariant 4 — Ordre de traitement

```python
events.sort(key=lambda e: e.event_time_utc)
```

Les événements sont triés par `event_time_utc` **avant** d'être passés aux détecteurs. La corrélation temporelle (`correlate_recon_sequence`) dépend de cet ordre.

**Conséquence** : si deux événements ont exactement le même timestamp, leur ordre relatif est non déterministe (stable sort dans CPython depuis 2.2, mais ce n'est pas une garantie de la spec Python).

## Invariant 5 — Les modules retournent des Signals, jamais des Alerts

Aucun module dans `detect/modules/` ne doit importer ni instancier `Alert`. Cette séparation est la garantie que la politique d'alerte (seuils, corrélation, titre) est centralisée dans `correlator.py` uniquement.

## Invariant 6 — Complexité O(n) de la détection

Les modules de détection v1 opèrent en un seul parcours de la liste d'événements (O(n)). La corrélation temporelle utilise un `defaultdict` par processus — également O(n) en espace et en temps.

Aucune opération quadratique O(n²) n'est intentionnellement introduite. Une revue de code doit rejeter tout appel de type `for ev in events: for ev2 in events:`.
