"""Deterministic feature extraction for mail triage.

Everything here reads ingested content as a STRING and turns it into a stable bag of feature
tokens. It never executes, evaluates or interprets the content. Same input always yields the
same feature list (sorted, lowercased), which is what keeps the classifier deterministic and
the tests reproducible.

Feature tokens are uniform strings so the Naive Bayes classifier can treat categorical
signals and subject words the same way, e.g.:
    spf=fail  dkim=missing  dmarc=fail  mismatch=1  attach=1  dom=microsoft.com  subj=invoice
"""
from __future__ import annotations

import re
from typing import Dict, List

_WORD = re.compile(r"[a-z0-9]+")


def _domain(addr: str) -> str:
    addr = (addr or "").strip().lower()
    if "@" in addr:
        addr = addr.rsplit("@", 1)[1]
    # strip a trailing '>' or whitespace sometimes present in raw From headers
    addr = addr.strip(" >\t\r\n")
    return addr


def _subject_tokens(subject: str, cap: int = 40) -> List[str]:
    toks = _WORD.findall((subject or "").lower())
    # de-duplicate while keeping determinism, cap to bound very long subjects
    seen = []
    for t in toks:
        if len(t) < 2:
            continue
        if t not in seen:
            seen.append(t)
        if len(seen) >= cap:
            break
    return ["subj=%s" % t for t in seen]


def extract_ticket_features(ticket: Dict) -> List[str]:
    """Turn a SOC ticket dict into a sorted, deterministic list of feature tokens.

    Tickets do not carry mail headers; they carry detection metadata. This extractor uses
    the fields a ticket actually has (signal type, MITRE technique, host, severity, risk
    factors, title words), so the AI can triage any ticket, not only mail. Like the mail
    extractor, everything is read as a STRING and never executed."""
    t = ticket or {}
    feats: List[str] = []

    stype = str(t.get("signal_type", "")).lower().strip()
    if stype:
        feats.append("stype=%s" % stype.replace(" ", "_"))
    mitre = str(t.get("mitre_technique", "")).strip()
    if mitre:
        feats.append("mitre=%s" % mitre)
    sev = str(t.get("severity", "")).lower().strip()
    if sev:
        feats.append("sev=%s" % sev)
    host = str(t.get("host", "")).lower().strip()
    if host:
        feats.append("host=%s" % host.replace(" ", "_"))

    for rf in (t.get("risk_factors") or []):
        tok = str(rf).lower().strip().replace(" ", "_")
        if tok:
            feats.append("risk=%s" % tok)

    for w in _WORD.findall(str(t.get("title", "")).lower()):
        if len(w) >= 3:
            feats.append("title=%s" % w)

    return sorted(set(feats))


def extract_mail_features(raw: Dict) -> List[str]:
    """Turn a mail event's raw dict into a sorted, deterministic list of feature tokens."""
    raw = raw or {}
    feats: List[str] = []

    spf = (raw.get("received_spf") or "").lower()
    if "fail" in spf:
        feats.append("spf=fail")
    elif "pass" in spf:
        feats.append("spf=pass")
    else:
        feats.append("spf=none")

    dkim = (raw.get("dkim_signature") or "").strip()
    feats.append("dkim=present" if dkim else "dkim=missing")

    auth = (raw.get("authentication_results") or raw.get("auth") or "").lower()
    if "dmarc=fail" in auth:
        feats.append("dmarc=fail")
    elif "dmarc=pass" in auth:
        feats.append("dmarc=pass")
    else:
        feats.append("dmarc=none")

    from_dom = _domain(raw.get("from", ""))
    return_dom = _domain(raw.get("return_path", ""))
    if from_dom:
        feats.append("dom=%s" % from_dom)
    if from_dom and return_dom and from_dom != return_dom:
        feats.append("mismatch=1")
    else:
        feats.append("mismatch=0")

    has_attach = bool(raw.get("attachments") or raw.get("attachment_names"))
    feats.append("attach=1" if has_attach else "attach=0")

    feats.extend(_subject_tokens(raw.get("subject", "")))

    # Stable order: identical input -> identical feature vector.
    return sorted(set(feats))
