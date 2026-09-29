# Format des événements d'entrée

Le format d'entrée v1 est un JSONL maison (une ligne = un objet JSON). Voici les formats d'événements supportés.

## Événement Process (event_type: process)

```json
{
  "timestamp":       "2024-01-15T12:00:00Z",
  "host":            "WIN-SRV01",
  "event_type":      "process",
  "source":          "sysmon_like",
  "process_name":    "powershell.exe",
  "pid":             4288,
  "ppid":            1234,
  "process_path":    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "command_line":    "powershell -enc SGVsbG8=",
  "integrity_level": "High",
  "username":        "CORP\\jdoe",
  "domain":          "CORP",
  "sid":             "S-1-5-21-123456789-0-0-1001"
}
```

## Événement Fichier (event_type: file)

```json
{
  "timestamp":    "2024-01-15T12:00:05Z",
  "host":         "WIN-SRV01",
  "event_type":   "file",
  "process_name": "powershell.exe",
  "pid":          4288,
  "operation":    "write",
  "file_path":    "C:\\Users\\victim\\important.docx.encrypted"
}
```

**Valeurs de `operation`** : `write`, `modify`, `rename`, `delete`, `create`, `open`

## Événement Réseau (event_type: network)

```json
{
  "timestamp":    "2024-01-15T12:00:10Z",
  "host":         "WIN-SRV01",
  "event_type":   "network",
  "process_name": "powershell.exe",
  "pid":          4288,
  "direction":    "outbound",
  "dest_ip":      "185.220.101.50",
  "dest_port":    4444,
  "protocol":     "tcp"
}
```

## Événement Auth (event_type: auth)

```json
{
  "timestamp":    "2024-01-15T12:00:15Z",
  "host":         "DC-01",
  "event_type":   "auth",
  "username":     "jdoe",
  "domain":       "CORP",
  "sid":          "S-1-5-21-...",
  "source":       "winlog"
}
```
