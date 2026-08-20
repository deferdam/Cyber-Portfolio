"""Synthetic SOC case generator for GENERALIZATION testing.

This exists to answer one honest question: does the model's held-out recall hold on fresh data
it has never seen, and at larger volumes, or was a small-sample result luck? It generates
realistic tickets with a KNOWN ground-truth label and deliberately includes hard cases:
  * real attacks at only medium severity (so the model cannot lean on severity alone),
  * benign or admin activity that superficially looks malicious (look-alike false positives),
  * occasional novel risk factors the training corpus never contained (unseen tokens),
so the evaluation is a fair test of generalization, not a rerun of the training patterns.

IMPORTANT, kept honest: these are SYNTHETIC cases from templates that overlap the training
vocabulary. Results here estimate robustness across this synthetic distribution; they are
optimistic relative to real production traffic, which only real deployments can measure.
"""
from __future__ import annotations

import random
from typing import Dict, List

# Malicious techniques/risk factors: their presence defines a real threat regardless of
# severity, which is the point (a low-severity real attack must still be caught).
_MAL_SIGNALS = ["powershell", "ransomware", "lotl", "credential_access", "lateral_movement",
                "reverse_shell", "beacon", "exfiltration", "phishing", "privilege_escalation",
                "persistence", "defense_evasion", "brute_force"]
_MAL_TECHNIQUES = ["T1059.001", "T1003.001", "T1486", "T1547.001", "T1021.002", "T1059.004",
                   "T1071.001", "T1041", "T1566.002", "T1548.002", "T1053.005", "T1562.001",
                   "T1110.003", "T1218.010", "T1490", "T1558.003"]
_MAL_RISKS = ["encoded_command", "download_cradle", "mimikatz", "lsass_access", "mass_rename",
              "shadow_copy_deletion", "lolbin", "credential_link", "macro", "beaconing",
              "dns_tunneling", "uac_bypass", "token_manipulation", "reverse_shell",
              "exfil_cloud", "kerberoasting", "password_spray", "cobalt_strike", "sam_dump",
              "psexec", "smb_spread", "rdp_bruteforce"]
# Novel malicious risk factors NOT present in the training corpus, to test unseen tokens.
_MAL_RISKS_NOVEL = ["process_hollowing", "dll_sideload", "asr_bypass", "clfs_exploit",
                    "printnightmare", "zerologon", "golden_ticket"]

_BENIGN_SIGNALS = ["auth", "login", "update", "email", "scan", "deployment", "cron", "backup"]
_BENIGN_RISKS = ["successful_login", "admin_script", "backup_software", "vuln_scanner",
                 "authorized", "patch", "sccm", "intune", "newsletter", "known_vendor",
                 "monitoring", "ci_pipeline", "known_device", "mfa_enroll", "password_change"]
# Look-alike: a suspicious-looking signal type but with a clearly benign/admin risk factor.
_LOOKALIKE_SIGNALS = ["powershell", "lotl", "scan", "lateral_movement", "deployment"]

_HOSTS = ["WIN-DC01", "WIN-WS%02d", "WEB-APP%02d", "FILE-SRV%d", "LNX-%02d", "MAIL-GW",
          "FW-EDGE", "HR-PC%02d", "DEV-LT%d", "SVC-%02d"]
_SEV_HI = ["high", "critical"]
_SEV_LO = ["low", "info"]


def _host(rng: random.Random) -> str:
    h = rng.choice(_HOSTS)
    return h % rng.randint(1, 40) if "%" in h else h


def generate(n: int, seed: int = 1337, novel_rate: float = 0.15,
             hard_rate: float = 0.25) -> List[Dict]:
    """Generate n labeled cases. novel_rate injects unseen risk factors into some threats;
    hard_rate makes some threats low-severity and some benign high-severity."""
    rng = random.Random(seed)
    out: List[Dict] = []
    # Class mix roughly like a real queue: many benign/FP, fewer real threats, some duplicates.
    weights = [("true_positive", 0.40), ("false_positive", 0.30),
               ("benign", 0.20), ("duplicate", 0.10)]
    labels = [l for l, _ in weights]
    probs = [w for _, w in weights]
    for i in range(n):
        label = rng.choices(labels, probs)[0]
        hard = rng.random() < hard_rate
        if label == "true_positive":
            stype = rng.choice(_MAL_SIGNALS)
            mitre = rng.choice(_MAL_TECHNIQUES)
            risks = [rng.choice(_MAL_RISKS)]
            if rng.random() < novel_rate:
                risks.append(rng.choice(_MAL_RISKS_NOVEL))
            # hard case: a genuine attack that only shows at medium/low severity
            sev = rng.choice(_SEV_LO) if hard else rng.choice(_SEV_HI)
            title = "%s activity with %s" % (stype, risks[0])
        elif label == "false_positive":
            # admin/security tooling that resembles an attack
            stype = rng.choice(_LOOKALIKE_SIGNALS)
            mitre = rng.choice(["T1059.001", "T1046", "T1072", "T1021.002"])
            risks = [rng.choice(["admin_script", "vuln_scanner", "sccm", "backup_software",
                                 "authorized", "admin_tool"])]
            # hard case: a benign action logged at high severity
            sev = rng.choice(_SEV_HI) if hard else rng.choice(_SEV_LO)
            title = "%s by admin tooling (%s)" % (stype, risks[0])
        elif label == "benign":
            stype = rng.choice(_BENIGN_SIGNALS)
            mitre = rng.choice(["T1078", "T1114", "T1072"])
            risks = [rng.choice(_BENIGN_RISKS)]
            sev = rng.choice(_SEV_LO)
            title = "routine %s (%s)" % (stype, risks[0])
        else:  # duplicate
            stype = rng.choice(_MAL_SIGNALS + _BENIGN_SIGNALS)
            mitre = rng.choice(_MAL_TECHNIQUES + ["T1078", "T1114"])
            risks = [rng.choice(_MAL_RISKS + _BENIGN_RISKS), "repeat"]
            sev = rng.choice(_SEV_LO + _SEV_HI)
            title = "re-alert on %s (%s)" % (stype, risks[0])
        out.append({
            "ticket_id": "SYN-%05d" % i,
            "signal_type": stype,
            "mitre_technique": mitre,
            "severity": sev,
            "host": _host(rng),
            "risk_factors": risks,
            "title": title,
            "label": label,
        })
    return out
