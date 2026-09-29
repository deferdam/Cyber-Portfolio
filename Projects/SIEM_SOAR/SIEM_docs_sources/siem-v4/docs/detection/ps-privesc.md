# ps_privilege_escalation.yaml

**Fichier :** `src/detect/modules/ps_privilege_escalation.yaml`  
**EventID :** 4104  
**Focus :** Élévation de privilèges, manipulation de comptes, credential access

## Sélections

| Sélection | Patterns clés | MITRE |
|---|---|---|
| `selection_local_admin_add` | `net localgroup administrators`, `Add-LocalGroupMember -Group Administrators` | T1098 |
| `selection_domain_admin_add` | `Add-ADGroupMember`, `net group "Domain Admins"` | T1098 |
| `selection_create_account` | `net user /add`, `New-LocalUser`, `New-ADUser` | T1136.001 |
| `selection_uac_bypass` | `fodhelper`, `eventvwr`, `sdclt`, `bypassuac` | T1548.002 |
| `selection_token_manipulation` | `ImpersonateLoggedOnUser`, `SeDebugPrivilege` | T1134 |
| `selection_credential_dump` | `Invoke-Mimikatz`, `sekurlsa`, `MiniDumpWriteDump` | T1003 |

## Criticité des patterns

`Invoke-Mimikatz` et `sekurlsa` sont des indicateurs quasi-pathognomoniques — leur présence dans un script block est pratiquement toujours malveillante. Ces patterns mériteraient un score fixe élevé (0.95+) indépendamment du nombre de sélections matchées.

!!! tip "Amélioration v5"
    Implémenter des scores fixes par sélection (override du calcul additif) pour les patterns à haute certitude comme Mimikatz.

## Faux positifs

- Scripts de gestion des comptes par les administrateurs système (onboarding automatisé)
- `Get-Credential` / `ConvertTo-SecureString` utilisés légitimement dans des scripts de connexion à des APIs
