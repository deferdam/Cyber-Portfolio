# ps_scriptblock.yaml

**Fichier :** `src/detect/modules/ps_scriptblock.yaml`  
**EventID :** 4104 (PowerShell Script Block Logging)  
**Auteur :** Dams — 2026-02-22

## Sélections

| Sélection | Patterns clés | MITRE |
|---|---|---|
| `selection_encoded` | `-EncodedCommand`, `-enc`, `-ec` | T1059.001 |
| `selection_obfuscation` | backtick escape, `[char]`, `-join` | T1027 |
| `selection_iex` | `Invoke-Expression`, `IEX(` | T1059.001 |
| `selection_download` | `DownloadString`, `Invoke-WebRequest`, `Start-BitsTransfer` | T1105 |
| `selection_webclient` | `Net.WebClient`, `HttpClient` | T1071.001 |
| `selection_amsi_bypass` | `amsiInitFailed`, `AmsiScanBuffer`, `AmsiUtils` | T1562.001 |
| `selection_exec_bypass` | `-ExecutionPolicy Bypass`, `Set-ExecutionPolicy Unrestricted` | T1562.001 |
| `selection_recon_identity` | `whoami`, `WindowsIdentity::GetCurrent()` | T1033 |
| `selection_recon_enum` | `net user`, `Get-ADUser`, `nltest` | T1087 |

## Scoring

Score = `min(1.0, 0.6 + 0.1 × nb_sélections_matchées)`

Un script qui encode **et** bypass AMSI **et** télécharge → 3 sélections → score 0.9.

## Faux positifs documentés

- Scripts admin légitimes utilisant `WebClient` pour du monitoring
- Outils de déploiement SCCM/Intune avec `-ExecutionPolicy Bypass`
- Scripts d'inventaire utilisant `Get-ADUser`
