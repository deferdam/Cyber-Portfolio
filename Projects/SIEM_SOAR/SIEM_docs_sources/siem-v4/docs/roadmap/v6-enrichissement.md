# v6 — Enrichissement (différé)

## Architecture choisie : enrichissement différé

L'enrichissement des Signals (URLVoid, WHOIS, géoloc IP, hash check) sera implémenté en mode **différé** — asynchrone, hors du pipeline de détection principal.

### Pourquoi pas synchrone ?

Un appel synchrone URLVoid dans le pipeline de détection :

```
Signal #1 → URLVoid(url) → [timeout 5s] → Signal #2 → ...
200 signaux × 5s = 16 minutes d'analyse
```

Ce n'est pas acceptable. En mode différé :

```
Pipeline détection → signals.jsonl     (< 1 seconde)
                          ↓
          Enrichment worker (async)    (background, N secondes)
                          ↓
          enriched_signals.jsonl       (consulté par le SOC)
```

## Architecture prévue

```
src/
├── enrich/
│   ├── enricher.py          # Orchestrateur enrichissement différé
│   ├── url_checker.py       # URLVoid / VirusTotal URL
│   ├── ip_checker.py        # AbuseIPDB / géoloc / WHOIS
│   ├── hash_checker.py      # VirusTotal hash lookup
│   └── base64_decoder.py    # Décodage base64 inline dans ScriptBlockText
```

## Enrichissements planifiés

| Module | Source | Ce qu'il extrait |
|--------|--------|-----------------|
| `url_checker` | URLVoid, VirusTotal | Réputation URL, catégorie, date enregistrement |
| `ip_checker` | AbuseIPDB, ip-api.com | Score d'abus, pays, ASN, réputation |
| `hash_checker` | VirusTotal | Réputation hash, famille de malware |
| `base64_decoder` | Local (stdlib) | Décode les `-EncodedCommand` et URLs encodées |
| `whois_lookup` | python-whois | Registrant, date création, TTL suspect |

## Prérequis architecturaux

Avant v6, les éléments suivants doivent exister :

1. **Persistance des Signals** — les Signals doivent être stockés quelque part pour être enrichis plus tard (fichier, SQLite, Redis)
2. **Déduplication** — ne pas enrichir deux fois le même IOC
3. **Gestion des clés API** — URLVoid, AbuseIPDB, VirusTotal nécessitent des comptes et des rate limits

## Note sur les appels réseau sortants

!!! warning "Considération OPSEC"
    Envoyer des URLs ou des hashes vers des services tiers peut alerter l'attaquant que sa campagne est détectée (si l'URL est unique ou le hash non-public). En environnement SOC réel, utiliser des **services privés** ou des **feeds locaux** plutôt que des APIs publiques.
