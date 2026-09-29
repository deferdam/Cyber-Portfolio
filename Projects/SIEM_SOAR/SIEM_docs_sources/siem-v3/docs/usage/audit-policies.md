# Audit Policies Windows

## Pourquoi sont-elles désactivées par défaut ?

Microsoft livre Windows avec la majorité des politiques d'audit avancées **désactivées** pour deux raisons structurelles :

### 1. Performance

Sur un serveur applicatif actif, EventID 4688 (Process Creation) peut générer plusieurs milliers d'entrées par minute. L'écriture dans le Security Event Log consomme des IOPS et de la CPU non négligeables sur du matériel modeste. Microsoft a historiquement priorisé les performances sur la visibilité sécurité dans ses paramètres par défaut.

### 2. Confidentialité / compliance

Le logging de la `CommandLine` dans EventID 4688 est séparément désactivé par une politique GPO car les arguments de processus peuvent contenir des **mots de passe en clair** :

```
net user jdoe P@ssw0rd /add
psexec \\server -u admin -p S3cr3t cmd.exe
runas /user:domain\admin /password:MyPass cmd.exe
```

Si les logs Security sont accessibles sans contrôle d'accès strict, cette donnée constitue une exposition de credentials. RGPD et PCI-DSS imposent des contraintes sur le stockage de mots de passe, même journalisés accidentellement.

## Politiques activées par run_siem.bat

`run_siem.bat` active les politiques suivantes si lancé en Administrateur :

### 1. Process Creation (EventID 4688)

```bat
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

Génère EventID 4688 à chaque création de processus. **Requis** pour toutes les détections basées sur `CommandLine`.

### 2. CommandLine dans 4688

```bat
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" ^
    /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

Sans ce paramètre, EventID 4688 est généré mais `CommandLine` est vide. Toutes les règles LOTL, PowerShell et spawn suspects seraient aveugles.

### 3. Process Termination

```bat
auditpol /set /subcategory:"Process Termination" /success:enable /failure:disable
```

Génère EventID 4689 à chaque fin de processus. Utile pour calculer la durée de vie des processus — un `vssadmin.exe` qui s'exécute 2 secondes puis disparaît est plus suspect qu'un processus de longue durée.

### 4. Scheduled Task (EventID 4698/4699/4702)

```bat
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

Génère les EventID de création/suppression/modification de tâches planifiées, consommés par `lotl_sigma._run_eventid_rules()`.

### 5. Logon Events (4624/4625)

```bat
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

Génère les EventID d'authentification. Utile pour la corrélation (authentification suspecte → exécution LOTL).

## Vérification des politiques appliquées

```bat
auditpol /get /subcategory:"Process Creation"
auditpol /get /subcategory:"Logon"

# Vérifier le registre CommandLine
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" ^
    /v ProcessCreationIncludeCmdLine_Enabled
```

## Recommandations de sécurité pour les logs

!!! danger "Ne jamais exposer les logs Security sans contrôle d'accès"
    Les logs contenant des CommandLine peuvent exposer des mots de passe. Appliquer :
    - Accès restreint au répertoire `C:\Windows\System32\winevt\Logs\Security.evtx`
    - Transmission vers le SIEM via canal TLS
    - Accès aux logs SIEM limité aux comptes SOC uniquement
    - Politique de rétention avec chiffrement au repos

## Configuration Sysmon recommandée (complément)

Sysmon enrichit EventID 4688 avec le champ `ParentImage` et le `CommandLine` de manière plus fiable que l'audit natif. Installer Sysmon avec une configuration de base :

```xml
<!-- sysmon_config.xml minimal -->
<Sysmon schemaversion="4.70">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="end with">powershell.exe</Image>
        <Image condition="end with">cmd.exe</Image>
        <Image condition="end with">vssadmin.exe</Image>
        <Image condition="end with">wmic.exe</Image>
        <Image condition="end with">mshta.exe</Image>
        <Image condition="end with">certutil.exe</Image>
        <Image condition="end with">rundll32.exe</Image>
        <Image condition="end with">schtasks.exe</Image>
        <Image condition="end with">regsvr32.exe</Image>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

```bat
sysmon64.exe -accepteula -i sysmon_config.xml
```
