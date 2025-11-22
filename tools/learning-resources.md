# Ressources — YARA / Sigma / Malware Analysis

## YARA
Documentation : https://yara.readthedocs.io  
Repo rules : https://github.com/Yara-Rules/rules

But : détecter des patterns dans fichiers malveillants.

Exemple :
```
rule SampleRule {
    strings:
        $a = "malware"
    condition:
        $a
}
```

## Sigma
Documentation : https://sigmahq-pysigma.readthedocs.io  
Repo rules : https://github.com/SigmaHQ/sigma

But : règles de détection génériques pour SIEM.

Exemple :
```
title: Suspicious Powershell
logsource:
  product: windows
  service: powershell
detection:
  selection:
    CommandLine|contains: "Invoke-WebRequest"
  condition: selection
```
