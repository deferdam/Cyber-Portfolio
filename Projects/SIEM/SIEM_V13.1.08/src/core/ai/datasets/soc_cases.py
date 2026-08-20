"""Curated SOC training corpus for ticket triage (100+ labeled cases).

HONEST FRAMING: these are realistic cases grounded in documented, real-world tradecraft
(MITRE ATT&CK techniques, known tool and malware behaviors, and common benign administrative
patterns). They are NOT records pulled from a production SOC database; using a real company's
data here would be a privacy and legal problem, and is unnecessary because the discriminating
signal lives in the technique/behavior features, which are public knowledge.

Each row: (signal_type, mitre_technique, severity, [risk_factors], title, label, source).
Labels are the four dispositions the analyst uses: true_positive, false_positive, benign,
duplicate. Rows are grouped by domain source (windows/linux/email/network/identity) so each
source stays under the per-source influence cap and no single batch can dominate the model,
exactly like an imported dataset.

The corpus is deliberately shaped so the classes are separable by real features: genuine
attacks carry malicious risk factors at high severity; false positives are legitimate admin
or security tooling that resembles an attack; benign is routine activity; duplicates are
re-alerts of an already-known event.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

TP = "true_positive"
FP = "false_positive"
BENIGN = "benign"
DUP = "duplicate"

# (signal_type, mitre, severity, risk_factors, title, label)
_WINDOWS = [
    ("powershell", "T1059.001", "high", ["encoded_command", "download_cradle"], "Encoded PowerShell download cradle", TP),
    ("powershell", "T1059.001", "high", ["download_cradle", "webclient"], "PowerShell IEX WebClient remote payload", TP),
    ("powershell", "T1059.001", "high", ["amsi_bypass"], "PowerShell AMSI bypass attempt", TP),
    ("credential_access", "T1003.001", "critical", ["lsass_access", "mimikatz"], "LSASS memory access consistent with Mimikatz", TP),
    ("credential_access", "T1003.002", "high", ["sam_dump", "reg_save"], "SAM hive dumped via reg save", TP),
    ("ransomware", "T1486", "critical", ["mass_rename", "shadow_copy_deletion"], "Mass file rename with shadow copy deletion", TP),
    ("ransomware", "T1490", "critical", ["vssadmin_delete", "mass_encrypt"], "vssadmin delete shadows before encryption", TP),
    ("lotl", "T1105", "high", ["lolbin", "certutil"], "certutil used to download remote file", TP),
    ("lotl", "T1218.010", "high", ["lolbin", "regsvr32"], "regsvr32 scriptlet execution (Squiblydoo)", TP),
    ("lotl", "T1218.005", "high", ["lolbin", "mshta"], "mshta executing remote HTA", TP),
    ("lotl", "T1218.011", "high", ["lolbin", "rundll32"], "rundll32 launching suspicious export", TP),
    ("persistence", "T1547.001", "medium", ["run_key"], "Registry Run key persistence added", TP),
    ("persistence", "T1053.005", "medium", ["scheduled_task"], "Suspicious scheduled task created", TP),
    ("persistence", "T1546.003", "high", ["wmi_subscription"], "WMI event subscription persistence", TP),
    ("privilege_escalation", "T1548.002", "high", ["uac_bypass", "fodhelper"], "UAC bypass via fodhelper", TP),
    ("privilege_escalation", "T1134", "high", ["token_manipulation"], "Access token impersonation", TP),
    ("lateral_movement", "T1021.002", "high", ["psexec", "lateral"], "PsExec service creation on remote host", TP),
    ("lateral_movement", "T1021.006", "high", ["wmi_exec", "lateral"], "Remote WMI process creation", TP),
    ("defense_evasion", "T1562.001", "high", ["defender_tamper"], "Windows Defender real-time protection disabled", TP),
    ("account_manipulation", "T1136.001", "high", ["admin_add", "local_account"], "New local administrator account created", TP),
    ("powershell", "T1059.001", "low", ["admin_script"], "Scheduled inventory PowerShell script", FP),
    ("deployment", "T1072", "low", ["sccm", "admin_tool"], "SCCM software deployment run", FP),
    ("deployment", "T1072", "low", ["intune", "admin_tool"], "Intune management script execution", FP),
    ("persistence", "T1053.005", "low", ["scheduled_task", "backup_software"], "Backup software scheduled task", FP),
    ("scan", "T1046", "low", ["vuln_scanner", "authorized"], "Authorized Nessus internal scan", FP),
    ("lateral_movement", "T1021.002", "low", ["psexec", "admin_tool"], "Admin remote maintenance via PsExec", FP),
    ("update", "T1072", "low", ["patch", "wsus"], "WSUS patch installation", FP),
    ("lotl", "T1105", "low", ["certutil", "admin_tool"], "certutil used for certificate management", FP),
    ("powershell", "T1059.001", "high", ["obfuscated", "invoke_obfuscation"], "Heavily obfuscated PowerShell", TP),
    ("credential_access", "T1558.003", "high", ["kerberoasting"], "Kerberoasting service ticket requests", TP),
    ("persistence", "T1543.003", "high", ["malicious_service"], "Malicious Windows service installed", TP),
    ("defense_evasion", "T1070.001", "medium", ["clear_eventlog"], "Security event log cleared", TP),
    ("scan", "T1046", "low", ["port_scan", "monitoring", "authorized"], "Authorized monitoring health check", FP),
    ("update", "T1072", "low", ["patch", "sccm"], "Routine SCCM patch cycle", FP),
]

_LINUX = [
    ("reverse_shell", "T1059.004", "high", ["reverse_shell", "dev_tcp"], "Bash /dev/tcp reverse shell", TP),
    ("bash", "T1059.004", "high", ["download_cradle", "curl_pipe"], "curl piped to bash payload", TP),
    ("privilege_escalation", "T1548.001", "high", ["setuid", "chmod_s"], "setuid bit set on shell binary", TP),
    ("cron", "T1053.003", "medium", ["cron_persistence"], "Malicious cron job persistence", TP),
    ("account_manipulation", "T1098", "high", ["passwd_write"], "Direct write to /etc/passwd", TP),
    ("persistence", "T1098.004", "high", ["ssh_key_backdoor"], "Unauthorized SSH authorized_keys entry", TP),
    ("bash", "T1105", "high", ["download_exec", "wget_tmp"], "wget payload to /tmp then execute", TP),
    ("privilege_escalation", "T1548.003", "high", ["sudo_abuse"], "Sudo misconfiguration exploited", TP),
    ("defense_evasion", "T1140", "high", ["encoded_command", "base64_decode"], "Base64-decoded shell command", TP),
    ("persistence", "T1574.006", "high", ["ld_preload"], "LD_PRELOAD rootkit loading", TP),
    ("defense_evasion", "T1070.003", "medium", ["history_clear"], "Bash history cleared after activity", TP),
    ("reverse_shell", "T1059", "high", ["netcat_listener"], "netcat bind shell listener started", TP),
    ("bash", "T1059.004", "low", ["admin_script", "chmod"], "Developer chmod +x on own script", FP),
    ("bash", "T1105", "low", ["download_cradle", "ci_pipeline"], "Ansible curl pipe in CI pipeline", FP),
    ("cron", "T1053.003", "low", ["cron", "backup_software"], "Nightly backup cron job", FP),
    ("privilege_escalation", "T1548.003", "info", ["sudo", "admin_tool"], "Admin routine sudo usage", BENIGN),
    ("update", "T1072", "low", ["patch", "apt"], "apt package upgrade", FP),
    ("cron", "T1053.003", "low", ["cron", "monitoring"], "Monitoring agent cron registration", FP),
    ("bash", "T1059.004", "info", ["admin_script", "known_admin"], "Admin routine maintenance script", BENIGN),
    ("reverse_shell", "T1059.004", "medium", ["reverse_shell", "repeat"], "Duplicate reverse shell alert", DUP),
    ("cron", "T1053.003", "low", ["cron_persistence", "repeat"], "Duplicate cron persistence alert", DUP),
]

_EMAIL = [
    ("phishing", "T1566.002", "high", ["credential_link", "lookalike_domain"], "Credential-harvesting phishing link", TP),
    ("email_attachment", "T1566.001", "high", ["macro", "attachment"], "Macro-enabled document attachment", TP),
    ("email_attachment", "T1566.001", "high", ["iso_lnk", "attachment"], "ISO with embedded LNK payload", TP),
    ("phishing", "T1566", "high", ["bec", "social_engineering"], "Business email compromise wire request", TP),
    ("email_attachment", "T1027.006", "high", ["html_smuggling"], "HTML smuggling attachment", TP),
    ("phishing", "T1534", "medium", ["spoofed_sender", "display_name"], "Spoofed display-name sender", TP),
    ("email_attachment", "T1027", "high", ["protected_archive", "malware"], "Password-protected zip malware", TP),
    ("phishing", "T1566.002", "medium", ["qr_phishing"], "QR code phishing (quishing)", TP),
    ("phishing", "T1528", "high", ["oauth_consent"], "OAuth consent phishing grant", TP),
    ("phishing", "T1566", "high", ["thread_hijack"], "Reply-chain thread hijack", TP),
    ("email", "T1566", "low", ["newsletter", "bulk"], "Marketing newsletter flagged by filter", FP),
    ("email", "T1566", "low", ["marketing", "bulk"], "Bulk marketing campaign", FP),
    ("email", "T1114", "info", ["internal", "known_sender"], "Internal company announcement", BENIGN),
    ("email", "T1114", "info", ["known_vendor", "invoice"], "Invoice from known vendor", BENIGN),
    ("email", "T1114", "info", ["calendar"], "Calendar meeting invite", BENIGN),
    ("email", "T1114", "info", ["automated_report"], "Automated system report email", BENIGN),
    ("phishing", "T1566.001", "high", ["macro", "emotet"], "Emotet-style macro loader mail", TP),
    ("email", "T1114", "low", ["marketing", "repeat"], "Duplicate bulk marketing alert", DUP),
    ("email", "T1114", "info", ["known_vendor", "receipt"], "Purchase receipt from known vendor", BENIGN),
]

_NETWORK = [
    ("beacon", "T1071.001", "high", ["beaconing", "regular_interval"], "C2 beaconing at regular interval", TP),
    ("beacon", "T1071.004", "high", ["dns_tunneling"], "DNS tunneling to external resolver", TP),
    ("beacon", "T1071", "critical", ["cobalt_strike", "named_pipe"], "Cobalt Strike named pipe pattern", TP),
    ("exfiltration", "T1567.002", "high", ["exfil_cloud", "large_transfer"], "Data exfiltration to cloud storage", TP),
    ("lateral_movement", "T1021.002", "high", ["smb_spread", "lateral"], "SMB lateral spread across hosts", TP),
    ("network", "T1090.003", "medium", ["tor"], "Tor network connection", TP),
    ("exfiltration", "T1041", "high", ["large_transfer", "off_hours"], "Large off-hours outbound transfer", TP),
    ("network", "T1071", "high", ["malicious_ip", "threat_intel"], "Connection to known malicious IP", TP),
    ("brute_force", "T1110", "high", ["rdp_bruteforce"], "RDP brute-force login attempts", TP),
    ("port_scan", "T1046", "medium", ["port_scan", "internal"], "Internal port scan detected", TP),
    ("port_scan", "T1046", "low", ["port_scan", "vuln_scanner", "authorized"], "Authorized vulnerability scan", FP),
    ("exfiltration", "T1041", "low", ["large_transfer", "backup_software"], "Backup replication traffic", FP),
    ("beacon", "T1071.001", "low", ["beaconing", "cdn"], "CDN keep-alive traffic", FP),
    ("beacon", "T1071.001", "low", ["beaconing", "repeat"], "Repeated beacon alert same destination", DUP),
    ("port_scan", "T1046", "low", ["port_scan", "repeat"], "Duplicate port scan alert", DUP),
    ("beacon", "T1071.001", "low", ["beaconing", "update_check"], "Periodic software update check", FP),
    ("network", "T1071", "info", ["known_service", "internal"], "Routine internal service traffic", BENIGN),
    ("exfiltration", "T1567.002", "low", ["exfil_cloud", "repeat"], "Duplicate cloud upload alert", DUP),
    ("brute_force", "T1110", "medium", ["rdp_bruteforce", "repeat"], "Duplicate RDP brute-force alert", DUP),
]

_IDENTITY = [
    ("auth", "T1078", "info", ["successful_login", "business_hours"], "Successful login during business hours", BENIGN),
    ("auth", "T1078", "info", ["password_change"], "User password change", BENIGN),
    ("auth", "T1078", "info", ["mfa_enroll"], "MFA enrollment completed", BENIGN),
    ("auth", "T1078.004", "info", ["service_account", "scheduled"], "Service account scheduled login", BENIGN),
    ("auth", "T1078", "info", ["vpn_connect", "known_user"], "VPN connection from known user", BENIGN),
    ("auth", "T1078", "info", ["account_unlock", "helpdesk"], "Account unlock by helpdesk", BENIGN),
    ("auth", "T1078", "info", ["kerberos_normal"], "Normal Kerberos TGT request", BENIGN),
    ("auth", "T1078", "info", ["known_device"], "Login from a known device", BENIGN),
    ("auth", "T1110", "medium", ["failed_login", "repeat"], "Repeated failed login same source", DUP),
    ("phishing", "T1566.002", "low", ["credential_link", "repeat"], "Re-reported phishing email", DUP),
    ("ransomware", "T1486", "high", ["mass_rename", "repeat"], "Duplicate ransomware alert same host", DUP),
    ("powershell", "T1059.001", "medium", ["encoded_command", "repeat"], "Duplicate PowerShell alert", DUP),
    ("email_attachment", "T1566.001", "low", ["macro", "repeat"], "Re-alert on same file hash", DUP),
    ("auth", "T1621", "high", ["mfa_fatigue", "push_bombing"], "MFA push-bombing (fatigue) attack", TP),
    ("auth", "T1110.003", "high", ["password_spray"], "Password spray across many accounts", TP),
    ("auth", "T1078", "high", ["impossible_travel"], "Impossible-travel sign-in", TP),
    ("auth", "T1078", "info", ["successful_login", "known_device"], "Routine login known device", BENIGN),
    ("auth", "T1078.004", "info", ["service_account", "scheduled"], "Service account nightly job login", BENIGN),
    ("auth", "T1110.003", "medium", ["password_spray", "repeat"], "Duplicate password spray alert", DUP),
]

_GROUPS = {
    "dataset:windows_v1": _WINDOWS,
    "dataset:linux_v1": _LINUX,
    "dataset:email_v1": _EMAIL,
    "dataset:network_v1": _NETWORK,
    "dataset:identity_v1": _IDENTITY,
}

_HOSTS = ["WIN-DC01", "WIN-WS14", "WEB-APP02", "FILE-SRV1", "LNX-BUILD3",
          "MAIL-GW", "FW-EDGE", "HR-PC22", "DEV-LT7", "SVC-HOST9"]


def load_cases() -> List[Dict]:
    """Return every case as a full ticket-like dict with a rotating host and its source."""
    out: List[Dict] = []
    i = 0
    for source, rows in _GROUPS.items():
        for stype, mitre, sev, risks, title, label in rows:
            out.append({
                "ticket_id": "SEED-%03d" % i,
                "signal_type": stype,
                "mitre_technique": mitre,
                "severity": sev,
                "host": _HOSTS[i % len(_HOSTS)],
                "risk_factors": list(risks),
                "title": title,
                "label": label,
                "source": source,
            })
            i += 1
    return out


def by_source() -> Dict[str, List[Dict]]:
    """Cases grouped by their provenance source tag."""
    groups: Dict[str, List[Dict]] = {}
    for case in load_cases():
        groups.setdefault(case["source"], []).append(case)
    return groups


def label_counts() -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for case in load_cases():
        counts[case["label"]] = counts.get(case["label"], 0) + 1
    return counts
