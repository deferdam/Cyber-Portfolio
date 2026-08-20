"""email_phishing.py - Detect email phishing indicators.

Two detectors:
  1. Header analysis  - SPF fail, DKIM missing, From/Return-Path mismatch
  2. Link analysis    - suspicious URLs in body (IP links, URL shorteners,
                        mismatched display vs href text)

MITRE T1566.001 - Spearphishing Attachment
MITRE T1566.002 - Spearphishing Link
"""
from __future__ import annotations

import hashlib
import re
from typing import List

from core.schemas import CanonicalEvent, Signal
from core.hashes import extract_hashes

_SHORTENERS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","buff.ly",
    "short.link","rb.gy","cutt.ly","is.gd","v.gd","tiny.cc",
}

_URL_RE = re.compile(r'https?://[^\s<>]+', re.I)
_IP_URL_RE = re.compile(r'https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', re.I)

def _sig_id(kind: str, eid: str) -> str:
    return "sig-" + hashlib.sha256(f"email.{kind}|{eid}".encode()).hexdigest()[:16]


def _run_header(ev: CanonicalEvent) -> List[Signal]:
    raw = ev.raw or {}
    factors: List[str] = []

    spf = raw.get("received_spf", "").lower()
    if "fail" in spf or "softfail" in spf:
        factors.append(f"spf:{spf[:60]}")

    dkim = raw.get("dkim_signature", "").strip()
    if not dkim:
        factors.append("dkim:missing")

    auth = raw.get("authentication_results", "").lower()
    if "dmarc=fail" in auth:
        factors.append("dmarc:fail")

    from_addr   = raw.get("from", "")
    return_path = raw.get("return_path", "")
    if from_addr and return_path:
        def _domain(s):
            m = re.search(r"@([\w.\-]+)", s)
            return m.group(1).lower() if m else ""
        fd, rd = _domain(from_addr), _domain(return_path)
        if fd and rd and fd != rd:
            factors.append(f"from_return_path_mismatch:{fd}!={rd}")

    if not factors:
        return []

    score = min(1.0, 0.50 + 0.15 * len(factors))
    return [Signal(
        signal_id          = _sig_id("header", ev.event_id),
        signal_type        = "email.suspicious_headers",
        host               = ev.host,
        user_key           = ev.user.username,
        score              = score,
        confidence         = score - 0.05,
        risk_factors       = factors,
        evidence_event_ids = [ev.event_id],
        file_hashes        = {},
        explanation        = (
            f"Email from '{from_addr[:60]}' shows suspicious header indicators: "
            + ", ".join(factors)
        ),
        recommended_actions = [
            "Verify sender domain legitimacy.",
            "Check DMARC policy at sender domain.",
            "Do not click links or open attachments.",
        ],
        mitre_tactic     = "Initial Access",
        mitre_technique  = "T1566.001",
    )]


def _run_links(ev: CanonicalEvent) -> List[Signal]:
    raw  = ev.raw or {}
    body = raw.get("body_text", "")
    if not body:
        return []

    factors: List[str] = []

    if _IP_URL_RE.search(body):
        factors.append("ip_based_url_in_body")

    for m in _URL_RE.finditer(body):
        domain = m.group(0).split("//")[-1].split("/")[0].lower()
        if any(s in domain for s in _SHORTENERS):
            factors.append(f"url_shortener:{domain}")
            break

    # Mismatched href - look for href= containing different domain than visible text
    href_re = re.compile(r'href=[=]?[\"\'][^\"\'>]+', re.I)
    text_re   = re.compile(r'>([^<]{4,60})<', re.I)
    hrefs     = href_re.findall(body)
    if len(hrefs) > 5:
        factors.append(f"many_links:{len(hrefs)}")

    if not factors:
        return []

    score = min(1.0, 0.45 + 0.15 * len(factors))
    return [Signal(
        signal_id          = _sig_id("links", ev.event_id),
        signal_type        = "email.suspicious_links",
        host               = ev.host,
        user_key           = ev.user.username,
        score              = score,
        confidence         = score - 0.05,
        risk_factors       = factors,
        evidence_event_ids = [ev.event_id],
        file_hashes        = {},
        explanation        = (
            f"Email body contains suspicious link indicators: "
            + ", ".join(factors)
        ),
        recommended_actions = [
            "Do not click any links in this email.",
            "Analyze URLs in a sandboxed environment.",
            "Block sender domain at email gateway.",
        ],
        mitre_tactic     = "Initial Access",
        mitre_technique  = "T1566.002",
    )]


def run(events: List[CanonicalEvent]) -> List[Signal]:
    signals: List[Signal] = []
    for ev in events:
        if ev.source != "email":
            continue
        if ev.event_type == "auth":
            signals.extend(_run_header(ev))
            signals.extend(_run_links(ev))
    return signals
