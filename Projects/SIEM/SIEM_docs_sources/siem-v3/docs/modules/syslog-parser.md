# Parseur Syslog — syslog_parser.py

## Objectif

Convertir des lignes de log textuelles (syslog RFC 3164, RFC 5424, CEF, JSON direct) en `Dict[str, Any]` compatibles avec `normalizer.normalize()`.

## Formats supportés

### RFC 5424

Format moderne, utilisé par rsyslog, syslog-ng, journald.

```
<134>1 2024-01-15T12:00:00Z WIN-SRV01 Security 4688 - - {"EventID":4688,...}
↑pri  ↑version ↑timestamp     ↑host     ↑app  ↑pid      ↑message (JSON body)
```

**Regex d'identification** : `^<\d+>1\s`

### RFC 3164

Format legacy, encore très répandu (équipements réseau, vieux systèmes).

```
<190>Jan 15 12:00:01 WIN-SRV02 sysmon[4321]: process created: vssadmin.exe
↑pri  ↑timestamp (sans année) ↑host  ↑tag ↑pid  ↑message
```

!!! warning "Année manquante"
    RFC 3164 n'inclut pas l'année dans le timestamp. Le parseur injecte l'année courante, ce qui peut causer des erreurs de tri pour des logs archivés en fin d'année (31 déc. vs 1er jan.).

**Regex d'identification** : `^<\d+>` (sans `>1`)

### CEF (Common Event Format)

Format d'ArcSight, utilisé par de nombreux équipements de sécurité (Palo Alto, Check Point, Fortinet).

```
CEF:0|Microsoft|Windows|10|4688|Process Created|5|shost=WIN-SRV03 suser=ADMIN dproc=wmic.exe cs1=wmic /node:...
↑version ↑vendor ↑product ↑ver ↑classId ↑name ↑sev ↑extensions (key=value)
```

**Mapping des champs CEF → canoniques :**

| Champ CEF | Champ canonique |
|-----------|----------------|
| `shost` / `dhost` | `host` |
| `suser` / `duser` | `user` |
| `sproc` / `dproc` | `process_name` |
| `cs1` | `command_line` (convention ArcSight) |
| `cs2` | `parent_image` |
| `fname` | `file_path` |
| `dst` / `destinationAddress` | `dest_ip` |
| `dpt` / `destinationPort` | `dest_port` |
| `act` | `operation` |

### JSON direct (NXLog / Winlogbeat)

Lignes commençant par `{` — JSON Windows event log exporté par NXLog ou Winlogbeat.

**NXLog** (structure plate) :
```json
{"EventID":4688,"Hostname":"WIN-SRV01","EventData":{"CommandLine":"vssadmin..."}}
```

**Winlogbeat** (structure imbriquée) :
```json
{"@timestamp":"...","event":{"code":"4688"},"winlog":{"event_data":{"CommandLine":"..."}}}
```

`_flatten_windows_json()` supporte les deux structures et produit les mêmes champs canoniques.

## Décodage de la priorité syslog

La priorité `PRI` encode facilité et sévérité :

```python
facility = pri >> 3     # bits 7-3
severity = pri & 0x07   # bits 2-0
```

| Sévérité | Valeur | Signification |
|----------|--------|---------------|
| emergency | 0 | Système inutilisable |
| alert | 1 | Action immédiate requise |
| critical | 2 | Condition critique |
| error | 3 | Condition d'erreur |
| warning | 4 | Condition d'avertissement |
| notice | 5 | Condition normale mais significative |
| info | 6 | Message informatif |
| debug | 7 | Message de débogage |

Ces valeurs sont stockées dans `_syslog_severity` et `_syslog_facility` dans le dict de sortie — disponibles via `ev.raw`.

## API

### `parse_line(line: str) -> Optional[Dict[str, Any]]`

Parse une seule ligne. Retourne `None` si la ligne est vide. Ne lève jamais d'exception (les erreurs sont catchées en interne).

```python
from ingest.syslog_parser import parse_line

result = parse_line('<134>1 2024-01-15T12:00:00Z WIN01 Security 4688 - - {...}')
# result["host"] == "WIN01"
# result["event_code"] == 4688
# result["command_line"] == "vssadmin delete shadows /all"
```

### `read_syslog_file(path_or_stdin) -> Iterator[Dict[str, Any]]`

Générateur — yield un dict par ligne parsée. Accepte un chemin de fichier ou `sys.stdin`.

```python
from ingest.syslog_parser import read_syslog_file

for event in read_syslog_file("/var/log/security.log"):
    canonical = normalize(event)
    ...
```

## Gestion des erreurs

```python
for lineno, line in enumerate(lines, start=1):
    try:
        result = parse_line(line)
        if result is not None:
            yield result
    except Exception as exc:
        print(f"[syslog_parser] WARN line {lineno}: {exc}", file=sys.stderr)
        continue  # ligne suivante
```

Les lignes imparsables sont loguées sur stderr et ignorées. Le pipeline ne s'arrête jamais sur une ligne malformée.
