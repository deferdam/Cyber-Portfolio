"""Versioned model registry with rollback.

Each trained model is stored as a JSON document (data-only, no code, no pickle) with a
version number, the metrics it scored on a held-out validated set, and a timestamp. An
"active" pointer selects the model currently in use. A bad label batch that degrades
precision is undone with rollback(), which re-activates the previous version. v12.1 exposes
this in the admin panel; the primitive lives here.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Optional

from core.time import utcnow


class ModelRegistry:
    def __init__(self, base_dir) -> None:
        self.base = Path(base_dir)
        self.base.mkdir(parents=True, exist_ok=True)

    def _path(self, category: str) -> Path:
        safe = "".join(c for c in category if c.isalnum() or c in ("_", "-"))
        if safe != category or not safe:
            raise ValueError("unsafe category name: %r" % category)
        return self.base / ("%s.json" % safe)

    def _load(self, category: str) -> Dict:
        p = self._path(category)
        if not p.exists():
            return {"active": None, "versions": []}
        return json.loads(p.read_text(encoding="utf-8"))

    def _save(self, category: str, data: Dict) -> None:
        p = self._path(category)
        p.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass

    def save(self, category: str, model: Dict, metrics: Optional[Dict] = None,
             activate: bool = True) -> int:
        """Save a new model version. By default it becomes active. An IMPORTED model is saved
        with activate=False (quarantine): it exists as an inactive version and an admin must
        explicitly activate it after review, so an imported model has no authority on import."""
        data = self._load(category)
        version = (data["versions"][-1]["version"] + 1) if data["versions"] else 1
        data["versions"].append({
            "version": version,
            "model": model,
            "metrics": metrics or {},
            "created_at": utcnow().isoformat(),
        })
        if activate:
            data["active"] = version
        self._save(category, data)
        return version

    def active(self, category: str) -> Optional[Dict]:
        data = self._load(category)
        if data["active"] is None:
            return None
        for v in data["versions"]:
            if v["version"] == data["active"]:
                return v
        return None

    def versions(self, category: str) -> List[int]:
        return [v["version"] for v in self._load(category)["versions"]]

    def activate(self, category: str, version: int) -> None:
        data = self._load(category)
        if version not in [v["version"] for v in data["versions"]]:
            raise ValueError("no such version %r for %s" % (version, category))
        data["active"] = version
        self._save(category, data)

    def rollback(self, category: str) -> Optional[int]:
        """Re-activate the version just before the currently active one. Returns the new
        active version, or None if there is nothing to roll back to."""
        data = self._load(category)
        vers = [v["version"] for v in data["versions"]]
        if data["active"] is None or data["active"] not in vers:
            return None
        idx = vers.index(data["active"])
        if idx == 0:
            return None
        data["active"] = vers[idx - 1]
        self._save(category, data)
        return data["active"]
