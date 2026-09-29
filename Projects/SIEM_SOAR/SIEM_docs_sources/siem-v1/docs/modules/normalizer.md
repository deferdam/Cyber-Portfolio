# Normalisation

`src/normalize/normalizer.py` — Conversion d'un événement brut en `CanonicalEvent`.

## Responsabilités

Le normalizer a une unique responsabilité : transformer un `Dict[str, Any]` de forme quelconque en un `CanonicalEvent` typé et immuable. Il ne doit pas :

- Valider les valeurs (c'est le rôle des détecteurs)
- Enrichir les données (pas d'appels réseau, pas de lookups)
- Loguer des avertissements (tolérance silencieuse des champs manquants)

## API

```python
def normalize(raw: Dict[str, Any], default_host: str = "unknown-host") -> CanonicalEvent
```

**Paramètres :**

| Paramètre | Type | Description |
|-----------|------|-------------|
| `raw` | `Dict[str, Any]` | Événement brut tel que parsé depuis le JSONL |
| `default_host` | `str` | Hostname de fallback si `raw["host"]` est absent |

**Retour :** `CanonicalEvent` (frozen)

## Logique de normalisation

### event_type

```python
etype = raw.get("event_type") or "file"
if etype not in ("file", "network", "process", "auth", "other"):
    etype = "other"
```

Si `event_type` est absent ou invalide, il est défini à `"other"` — jamais à une valeur hors énumération.

### Extraction de l'extension de fichier

```python
def _extract_extension(path: Optional[str]) -> str:
    if not path:
        return ""
    p = path.replace("\\", "/")
    last = p.split("/")[-1]
    if "." not in last:
        return ""
    return last.split(".")[-1].lower()
```

Exemples :
```
C:\Users\victim\doc.docx.encrypted  →  "encrypted"
/etc/passwd                          →  ""
report.PDF                           →  "pdf"
```

### Extraction du répertoire

```python
def _extract_directory(path: Optional[str]) -> str:
    p = path.replace("\\", "/")
    if "/" not in p:
        return ""
    return "/".join(p.split("/")[:-1])
```

Les backslashes Windows sont normalisés en forward slashes avant extraction. Cela garantit que `ransomware_core.py` peut comparer des paths de manière uniforme.

## Champs non normalisés

Les champs présents dans `raw` mais absents du schéma canonique sont **conservés** dans `CanonicalEvent.raw`. Les modules de détection peuvent y accéder via `ev.raw.get("champ_custom")`.

```python
# Exemple dans un détecteur
task_name = ev.raw.get("TaskName") or ev.raw.get("EventData", {}).get("TaskName")
```

## Exemple complet

```python
raw = {
    "timestamp": "2024-01-15T12:00:00Z",
    "host": "WIN-SRV01",
    "event_type": "process",
    "process_name": "powershell.exe",
    "pid": 4288,
    "command_line": "powershell -enc SGVsbG8=",
    "username": "jdoe",
    "domain": "CORP"
}

ev = normalize(raw)
# ev.event_id       → SHA-256 du raw
# ev.event_time_utc → datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)
# ev.process.name   → "powershell.exe"
# ev.process.pid    → 4288
# ev.user.username  → "jdoe"
# ev.user.domain    → "CORP"
# ev.raw            → dict original intact
```
