"""hashes.py - Extract file hashes from any CanonicalEvent.

Sources handled:
  Sysmon  : raw["Hashes"] = "SHA256=abc,MD5=def,IMPHASH=ghi"
  Generic : raw["sha256"] / raw["SHA256"] / raw["file_hash"]
            raw["md5"]    / raw["MD5"]
  Email   : computed by email_parser.py, stored in raw["sha256"]/raw["md5"]
"""
from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from core.schemas import CanonicalEvent


def extract_hashes(ev) -> dict:
    raw = ev.raw or {}
    hashes: dict = {}

    sysmon = raw.get("Hashes") or raw.get("hashes")
    if sysmon:
        for part in str(sysmon).split(","):
            if "=" in part:
                k, v = part.split("=", 1)
                hashes[k.strip().lower()] = v.strip()

    for field in ("sha256", "SHA256", "file_hash"):
        if raw.get(field) and "sha256" not in hashes:
            hashes["sha256"] = str(raw[field])
    for field in ("md5", "MD5"):
        if raw.get(field) and "md5" not in hashes:
            hashes["md5"] = str(raw[field])

    return hashes
