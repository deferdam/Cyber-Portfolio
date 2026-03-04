# Démarrage rapide

## Prérequis

- Python 3.10 ou supérieur
- Windows 10/11 ou Windows Server 2016+ (pour les événements Windows)
- Aucune dépendance externe Python en v1 (stdlib uniquement)

## Installation

```bash
# Cloner ou décompresser le projet
cd SIEM/

# Vérifier Python
python --version  # doit être >= 3.10
```

## Premier lancement

=== "Windows (BAT)"
    ```bat
    # Petit jeu de données (243 événements)
    run_siem.bat small

    # Grand jeu de données
    run_siem.bat large
    ```

=== "Python direct"
    ```bash
    cd SIEM
    set PYTHONPATH=src                          # Windows CMD
    # export PYTHONPATH=src                    # Linux/macOS

    python -m ingest.replay \
        --input events.jsonl \
        --out-dir out/small \
        --default-host lab-host
    ```

## Sortie attendue

```
Normalized events: 243
Signals: 1
Alerts: 0
```

## Audit Policies

Pour que le SIEM reçoive des données réelles depuis Windows Event Log, deux politiques d'audit doivent être actives.

### Activer via auditpol (Administrator)

```bat
REM Activer EventID 4688 (Process Creation)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

REM Activer la CommandLine dans 4688
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" ^
    /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

REM Vérifier
auditpol /get /subcategory:"Process Creation"
```

### Pourquoi ces politiques sont désactivées par défaut

Microsoft livre Windows avec la majorité des politiques d'audit avancées **désactivées** pour deux raisons :

1. **Performance** : sur un serveur applicatif actif, EventID 4688 peut générer plusieurs milliers d'entrées par minute. L'I/O du Security Event Log a un coût non négligeable sur du matériel modeste.

2. **Confidentialité / compliance** : la CommandLine peut contenir des mots de passe passés en argument (`net user jdoe P@ssw0rd /add`). Sa journalisation peut violer des politiques internes ou réglementaires (RGPD, PCI-DSS) si les logs ne sont pas correctement protégés.

!!! tip "Recommandation SOC"
    Activer `ProcessCreationIncludeCmdLine` uniquement dans un environnement où les logs sont :
    - Transmis vers un SIEM centralisé via canal chiffré (TLS)
    - Accessibles uniquement aux comptes SOC/SIEM
    - Soumis à une politique de rétention avec purge automatique

## Tester avec vos propres événements

Créez un fichier `my_events.jsonl` avec un événement par ligne :

```json
{"timestamp":"2024-01-15T12:00:00Z","host":"TEST-PC","event_type":"process","process_name":"powershell.exe","pid":4288,"command_line":"powershell -enc SGVsbG8gV29ybGQ="}
{"timestamp":"2024-01-15T12:00:05Z","host":"TEST-PC","event_type":"file","process_name":"powershell.exe","pid":4288,"operation":"write","file_path":"C:\\Users\\victim\\doc1.docx.encrypted"}
```

```bat
python -m ingest.replay --input my_events.jsonl --out-dir out/test
```
