# Engine — Orchestrateur de détection

`src/detect/engine.py` — Point d'entrée unique des trois couches de détection.

## API

```python
def run_all(events: List[CanonicalEvent]) -> List[Signal]
```

## Séquence d'exécution

```python
def run_all(events):

    # Pré-calcul partagé
    tree = build_tree(events)

    # ── Couche 1 : Signature ──────────────────────────────────
    try:
        signals.extend(ransomware_v4.run(events))
    except Exception as exc:
        print(f"[engine] ERROR ransomware_v4: {exc}", stderr)

    # ── Couche 2 : Behavioral ─────────────────────────────────
    try:
        ps_signals = powershell_sigma.run(events, rule_path="powershell_suspicious.yaml")
        signals.extend(ps_signals)
    except Exception as exc:
        print(f"[engine] ERROR powershell_sigma: {exc}", stderr)
        ps_signals = []

    try:
        signals.extend(lotl_sigma.run(events, tree=tree))
    except Exception as exc:
        print(f"[engine] ERROR lotl_sigma: {exc}", stderr)

    # ── Couche 3 : Corrélation ────────────────────────────────
    try:
        correlated = powershell_sigma.correlate_recon_sequence(events, ps_signals)
        signals.extend(correlated)
    except Exception as exc:
        print(f"[engine] ERROR powershell_sigma.correlate: {exc}", stderr)

    return signals
```

## Points critiques

### Fallback ps_signals

Si `powershell_sigma.run()` lève une exception, `ps_signals` est défini à `[]`. La corrélation en couche 3 continue sans données PowerShell — elle ne crashe pas.

```python
except Exception as exc:
    print(...)
    ps_signals = []   # ← fallback explicite
```

### ProcessTree partagé

`build_tree()` est appelé une seule fois. Tous les modules qui ont besoin du tree reçoivent la même instance. Si la construction échoue (ex : tous les événements sont de type `network`, aucun `process`), `tree` est `None` et les modules qui le reçoivent l'ignorent silencieusement.

### Ordre des couches — contrainte forte

La couche 3 (`correlate_recon_sequence`) prend en entrée `ps_signals` produit par la couche 2. L'ordre d'exécution **n'est pas interchangeable**.

```
Couche 2 produit → ps_signals
                          ↓
Couche 3 consomme ← ps_signals
```

Toute refactorisation qui paralléliserait les couches 2 et 3 casserait cette dépendance.
