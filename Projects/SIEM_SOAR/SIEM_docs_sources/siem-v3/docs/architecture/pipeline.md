# Pipeline de données v2

## Flux de données multi-source

```mermaid
flowchart LR
    subgraph Entrée
        J[".jsonl\nevents JSON"]
        S3["RFC 3164\n<PRI>Timestamp host tag: msg"]
        S4["RFC 5424\n<PRI>1 ts host app pid msgid [sd] msg"]
        CEF["CEF\nCEF:0|Vendor|..."]
        STDIN["stdin\ntail -f pipe"]
    end

    subgraph Parser ["syslog_parser.py"]
        AD{Auto-detect\nformat}
        FJ[JSON parser]
        F3[RFC 3164 parser]
        F4[RFC 5424 parser]
        FC[CEF parser]
        FW[flatten_windows_json\nNXLog / Winlogbeat]
    end

    subgraph Normalize
        N[normalizer.py\nCanonicalEvent]
        PT[process_tree.py\nParentImage → Image]
    end

    J & S3 & S4 & CEF & STDIN --> AD
    AD -->|startswith {| FJ --> FW
    AD -->|CEF:0| FC --> FW
    AD -->|<PRI>1| F4 --> FW
    AD -->|<PRI>| F3 --> FW
    FW --> N --> PT
```

## Détection de format en syslog_parser

L'auto-détection suit cette priorité :

```python
if line.startswith("{"):          # 1. JSON pur (Winlogbeat, NXLog)
    ...
elif "CEF:0|" in line:           # 2. CEF (peut être dans un wrapper syslog)
    ...
elif re.match(r"^<\d+>1\s", line):  # 3. RFC 5424 (<PRI>1 ...)
    ...
elif re.match(r"^<\d+>", line):   # 4. RFC 3164
    ...
else:                             # 5. Message brut sans header
    ...
```

## Extraction des champs Windows depuis JSON

`_flatten_windows_json()` supporte deux formats de structuration :

=== "NXLog (flat)"
    ```json
    {
      "EventID": 4688,
      "Hostname": "WIN-SRV01",
      "EventData": {
        "NewProcessName": "C:\\Windows\\System32\\vssadmin.exe",
        "CommandLine": "vssadmin delete shadows /all /quiet",
        "SubjectUserName": "SYSTEM",
        "ParentProcessName": "C:\\Windows\\System32\\cmd.exe"
      }
    }
    ```

=== "Winlogbeat (nested)"
    ```json
    {
      "@timestamp": "2024-01-15T12:00:00Z",
      "host": {"hostname": "WIN-SRV01"},
      "event": {"code": "4688"},
      "winlog": {
        "event_id": 4688,
        "event_data": {
          "CommandLine": "vssadmin delete shadows /all /quiet",
          "NewProcessName": "vssadmin.exe"
        },
        "user": {"name": "SYSTEM", "domain": "NT AUTHORITY"}
      }
    }
    ```

Les deux formats produisent le même `CanonicalEvent`.

## Construction du Process Tree

Le `ProcessTree` est construit en deux passes après la normalisation :

**Passe 1 — Enregistrement des nœuds**

```python
for ev in events:
    if ev.event_type != "process":
        continue
    node = ProcessNode(image, pid, ppid, host, event_id, command_line, parent_image)
    _nodes[(host, pid)] = node
    _by_image[image].append(node)
```

**Passe 2 — Construction de l'index parent→enfant**

```python
for node in _nodes.values():
    parent = node.parent_image
    if not parent and node.ppid:
        parent_node = _nodes.get((node.host, node.ppid))
        if parent_node:
            parent = parent_node.image
    if parent:
        _children[parent].append(node.image)
```

!!! question "Pourquoi deux passes ?"
    La passe 1 construit l'index `(host, pid) → node`. Sans cet index, la passe 2 ne peut pas résoudre les PPID en images. Si on fusionnait les deux passes, les processus enregistrés après leur parent dans la liste seraient ignorés — on perdrait des relations parent→enfant valides.
