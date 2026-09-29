# Modes d'ingestion

## Comparatif des modes

| Mode | Flag | Détecte | Cas d'usage |
|------|------|---------|-------------|
| `json` | `--format json` | JSONL maison uniquement | Compatibilité v1, développement |
| `syslog` | `--format syslog` | RFC 3164, RFC 5424, CEF, JSON-in-syslog | Production, rsyslog, NXLog |
| `auto` | `--format auto` (défaut) | Tout — JSON prioritaire, syslog fallback | Fichiers mixtes, migration |

## Mode json

Comportement identique à v1. Lit un fichier JSONL ligne par ligne.

```bash
python -m ingest.replay --format json --input events.jsonl --out-dir out/
```

## Mode syslog

Passe chaque ligne par `syslog_parser.parse_line()` avec auto-détection RFC 3164 / RFC 5424 / CEF / JSON.

```bash
# Fichier syslog local
python -m ingest.replay --format syslog --input /var/log/security.log --out-dir out/

# Stdin — rsyslog template
# /etc/rsyslog.d/siem.conf:
# *.* |/usr/bin/python3 -m ingest.replay --format syslog --input - --out-dir /var/siem/out
```

## Mode auto (défaut)

Tentative JSON d'abord (startswith `{`), puis syslog si échec. Garantit la rétrocompatibilité totale avec les fichiers v1.

```bash
# Pas besoin de spécifier --format pour des fichiers JSON v1
python -m ingest.replay --input events.jsonl --out-dir out/
```

## Support stdin

`--input -` active la lecture depuis stdin. Utile pour le streaming temps réel :

```bash
# Tail en temps quasi-réel (NXLog, Filebeat)
tail -f /var/log/auth.log | python -m ingest.replay --format syslog --input - --out-dir /out/stream

# Pipeline rsyslog → SIEM
logger "test message" | python -m ingest.replay --format auto --input - --out-dir /tmp/test
```

!!! warning "Mode streaming — limitations v2"
    En mode stdin, la détection s'exécute sur l'intégralité du buffer lu jusqu'à EOF (ou Ctrl+C). Le pipeline n'est pas encore temps-réel event-by-event. Pour une détection continue, relancer périodiquement le pipeline sur des fenêtres glissantes.
