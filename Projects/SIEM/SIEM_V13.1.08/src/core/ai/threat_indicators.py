"""Threat-indicator safety net.

A learned classifier can be confidently wrong. The dangerous failure for a SOC is not missing
a threat, it is missing a threat WITH HIGH CONFIDENCE, because a high-confidence disposition is
not re-checked by an analyst. This module is a deterministic, defense-in-depth backstop: if a
ticket carries a recognized malicious indicator but the model dismisses it as a non-threat, the
reported confidence is capped low so the item lands in the human review queue.

The indicators are behavioral evidence of real tradecraft (grounded in the public MITRE ATT&CK
framework across Windows, Linux, macOS, network, email, identity and cloud): things that are
strong signals of an attack regardless of severity. The set is intentionally about behaviors
(risk factors) plus a short list of unambiguously offensive techniques, not dual-use techniques
like generic script execution, so genuine benign activity is not force-flagged.

This is a SAFETY NET, not the classifier: it never changes the predicted label and never marks
anything a threat on its own. It only lowers confidence on a dismissed-but-suspicious ticket so
a human looks. Truly novel tradecraft with no recognized indicator still relies on the model
(you cannot flag what nothing recognizes); the net removes the known high-confidence blind spot.
"""
from __future__ import annotations

from typing import Dict

# Behavioral malicious indicators (risk-factor tokens). These are evidence of an attack step,
# not administrative activity.
MALICIOUS_RISK_FACTORS = {
    # execution / obfuscation
    "encoded_command", "download_cradle", "obfuscated", "invoke_obfuscation", "base64_decode",
    "amsi_bypass", "html_smuggling", "process_hollowing", "dll_sideload",
    # credential access
    "mimikatz", "lsass_access", "sam_dump", "kerberoasting", "golden_ticket", "dcsync",
    "password_spray", "credential_link", "oauth_consent",
    # impact / ransomware
    "mass_rename", "mass_encrypt", "shadow_copy_deletion", "vssadmin_delete",
    # persistence / privesc (offensive)
    "run_key", "wmi_subscription", "uac_bypass", "token_manipulation", "ld_preload",
    "ssh_key_backdoor", "passwd_write", "malicious_service", "setuid", "sudo_abuse",
    # lateral movement / remote
    "psexec", "wmi_exec", "smb_spread", "rdp_bruteforce", "reverse_shell", "netcat_listener",
    "lolbin",
    # C2 / exfil / evasion
    "beaconing", "dns_tunneling", "cobalt_strike", "tor", "exfil_cloud", "malicious_ip",
    "defender_tamper", "clear_eventlog", "history_clear",
    # phishing payloads
    "macro", "iso_lnk", "protected_archive", "thread_hijack", "emotet",
    # known exploit shorthands (real ATT&CK-adjacent CVEs/behaviors)
    "printnightmare", "zerologon", "clfs_exploit", "asr_bypass", "impossible_travel",
    "mfa_fatigue", "push_bombing",
}

# Unambiguously offensive techniques (credential dumping, ransomware, injection, C2, exfil,
# defense evasion via tampering). Dual-use techniques (generic execution, valid accounts,
# scheduled task) are deliberately EXCLUDED to avoid force-flagging benign admin activity.
MALICIOUS_TECHNIQUES = {
    "T1003", "T1003.001", "T1003.002", "T1558.003",   # credential access
    "T1486", "T1490",                                  # impact / ransomware
    "T1055", "T1620",                                  # process injection
    "T1071.004", "T1090.003",                          # C2 tunneling / multi-hop
    "T1041", "T1567.002",                              # exfiltration
    "T1562.001", "T1070.001",                          # impair defenses / clear logs
    "T1218.005", "T1218.010", "T1218.011",             # signed binary proxy (LOLBins)
    "T1548.002",                                       # UAC bypass
    "T1621",                                           # MFA request generation
}


def has_threat_indicator(ticket: Dict) -> bool:
    """True if the ticket carries a recognized malicious behavioral indicator or an
    unambiguously offensive technique."""
    for rf in (ticket.get("risk_factors") or []):
        if str(rf).lower().strip() in MALICIOUS_RISK_FACTORS:
            return True
    if str(ticket.get("mitre_technique", "")).strip() in MALICIOUS_TECHNIQUES:
        return True
    return False
