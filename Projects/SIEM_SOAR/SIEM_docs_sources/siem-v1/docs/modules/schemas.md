# Core — Schémas de données

`src/core/schemas.py` définit les quatre types de données centraux du pipeline. Tous sont des `dataclass(frozen=True)` — immuables par construction.

## HostRef

Référence à une machine dans un événement.

```python
@dataclass(frozen=True)
class HostRef:
    hostname: str
    agent_id: Optional[str] = None
    ip: Optional[str] = None
```

| Champ | Type | Description |
|-------|------|-------------|
| `hostname` | `str` | Nom de la machine (obligatoire) |
| `agent_id` | `Optional[str]` | ID de l'agent de collecte (Sysmon GUID, Beats ID…) |
| `ip` | `Optional[str]` | IP principale — utile si le hostname est un alias |

## UserRef

```python
@dataclass(frozen=True)
class UserRef:
    username: Optional[str] = None
    domain: Optional[str] = None
    sid: Optional[str] = None
```

Le `sid` Windows est préférable au `username` pour l'identification stable d'un compte (un compte peut être renommé, son SID non).

## ProcessRef

```python
@dataclass(frozen=True)
class ProcessRef:
    name: Optional[str] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    image_path: Optional[str] = None
    command_line: Optional[str] = None
    integrity_level: Optional[str] = None
```

!!! important "command_line en v1"
    `command_line` est présent dans le schéma mais dépend de la présence du champ dans les événements sources. Sur Windows, le logging de la CommandLine dans EventID 4688 est désactivé par défaut (cf. [Audit Process Creation](../usage/quickstart.md#audit-policies)).

## FileRef

```python
@dataclass(frozen=True)
class FileRef:
    path: Optional[str] = None
    operation: Optional[str] = None  # write/modify/rename/delete/create/open
    extension: Optional[str] = None
    directory: Optional[str] = None
```

`extension` et `directory` sont calculés automatiquement par le normalizer depuis `path`. Les backslashes Windows sont normalisés en forward slashes.

## NetworkRef

```python
@dataclass(frozen=True)
class NetworkRef:
    direction: Optional[str] = None  # inbound/outbound/unknown
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
```

## CanonicalEvent

Type central du pipeline — conteneur immuable d'un événement normalisé.

```python
@dataclass(frozen=True)
class CanonicalEvent:
    event_id: str               # SHA-256 déterministe
    event_time_utc: datetime    # Heure de l'événement, UTC
    ingest_time_utc: datetime   # Heure d'ingestion, UTC

    source: str                 # Origine : sysmon_like, winlog, etc.
    event_type: str             # process|file|network|auth|other

    host: HostRef
    user: UserRef
    process: ProcessRef
    file: FileRef
    network: NetworkRef

    raw: Dict[str, Any]         # Événement brut original — pour audit
```

Le champ `raw` est conservé pour deux raisons :
- **Auditabilité** : on peut toujours retrouver la source exacte d'un signal
- **Extensibilité** : les modules peuvent accéder à des champs non encore normalisés via `ev.raw.get("champ_custom")`

## Signal

Résultat d'un module de détection.

```python
@dataclass(frozen=True)
class Signal:
    signal_id: str
    signal_type: str            # ex: "ransomware_behavior"

    host: HostRef
    process_key: Optional[str]
    user_key: Optional[str]

    score: float                # 0.0 à 1.0
    confidence: float           # 0.0 à 1.0

    risk_factors: List[str]
    evidence_event_ids: List[str]   # Pointeurs vers CanonicalEvent.event_id

    explanation: str
    recommended_actions: List[str]
```

**score vs confidence** : en v1, ces deux valeurs sont identiques (confidence = score). La distinction est prévue pour v2 : `score` mesure la sévérité comportementale, `confidence` mesure la certitude du match.

## Alert

Produit final du corrélateur.

```python
@dataclass(frozen=True)
class Alert:
    alert_id: str
    title: str
    severity: str               # low|medium|high|critical
    confidence: float

    host: HostRef
    process_key: Optional[str]

    summary: str
    reasoning: List[str]
    timeline_event_ids: List[str]
    suggested_actions: List[str]
    related_signals: List[str]
```

La `severity` est calculée par `_severity_from_score()` dans `correlator.py` :

| Score | Sévérité |
|-------|----------|
| ≥ 0.85 | `critical` |
| ≥ 0.60 | `high` |
| ≥ 0.40 | `medium` |
| ≥ 0.30 | `low` |
| < 0.30 | *Signal ignoré* |
