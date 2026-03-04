# Core — IDs & Temps

## ids.py

### `stable_event_id(raw_event, salt="v1")`

Génère un identifiant stable et déterministe pour un événement brut.

```python
def stable_event_id(raw_event: Dict[str, Any], salt: str = "v1") -> str:
    blob = json.dumps(raw_event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    h = hashlib.sha256(salt.encode("utf-8") + b"|" + blob).hexdigest()
    return h
```

**Propriétés :**

- **Déterministe** : même `raw_event` → même hash, indépendamment de l'ordre des clés (grâce à `sort_keys=True`)
- **Sans collision pratique** : espace de 2²⁵⁶ valeurs
- **Versionnable** : le `salt` permet de distinguer des schémas de hashing différents entre versions

**Utilisation :**
```python
ev_id = stable_event_id(raw)  # appelé dans normalizer.py
```

---

### `process_key(process_name, pid, process_path)`

Clé composite identifiant un processus dans la fenêtre d'analyse.

```python
def process_key(
    process_name: Optional[str],
    pid: Optional[int],
    process_path: Optional[str]
) -> str:
    name = (process_name or "unknown").lower()
    path = (process_path or "").lower()
    pid_s = str(pid) if pid is not None else "na"
    return f"{name}|{pid_s}|{path}"
```

**Exemple :**
```
powershell.exe|4288|c:/windows/system32/windowspowershell/v1.0/powershell.exe
```

!!! warning "Limitation PID recycling"
    Les PID Windows sont réutilisés. Sur une longue fenêtre temporelle, deux processus distincts peuvent avoir la même `process_key`. **V2 devrait utiliser le GUID de processus Sysmon** (`ProcessGuid` dans EventID 1).

## time.py

### `parse_to_utc(ts_string)`

Convertit une chaîne de caractères représentant un timestamp en `datetime` UTC.

Stratégies tentées dans l'ordre :
1. Format ISO 8601 avec fuseau horaire explicite
2. Format ISO 8601 sans fuseau (assume UTC)
3. Epoch Unix (integer en string)
4. Fallback sur `utcnow()` si aucun format reconnu

**Exemples acceptés :**
```python
parse_to_utc("2024-01-15T12:00:00Z")        # ISO avec Z
parse_to_utc("2024-01-15T12:00:00+01:00")   # ISO avec offset
parse_to_utc("2024-01-15T12:00:00")         # ISO sans TZ → UTC assumé
parse_to_utc("1705320000")                   # Epoch
```

### `utcnow()`

Retourne `datetime.now(timezone.utc)` — encapsulé pour faciliter le mocking dans les tests.

```python
from core.time import utcnow
ingest_time = utcnow()
```
