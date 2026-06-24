"""process_tree.py — Build and query process ancestry from normalized events.

Security invariants:
  - The tree is constructed once, then treated as read-only (frozen dict of tuples).
  - No process can be its own ancestor (cycle guard with depth limit).
  - Parent resolution uses PID + host scoping to avoid cross-host collisions.
  - All public methods are pure functions (no side effects, no I/O).

Data model:
  ProcessNode: lightweight record per observed process
  ProcessTree: dict-based index supporting two queries:
    1. get_children(image) -> list of child image names
    2. get_ancestors(event) -> ordered list of ancestor image names (root first)
    3. is_spawn_suspect(parent_image, child_image) -> bool based on known-suspicious pairs
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Tuple

from core.schemas import CanonicalEvent


# ── Known suspicious parent→child spawn pairs (LOTL / APT patterns) ──────────
# Source: Sigma community rules + MITRE ATT&CK T1059, T1218, T1053
# Format: frozenset({parent_basename, child_basename}) — order-independent for
# symmetric lookup, but we also check directional (parent → child) below.

_SUSPICIOUS_SPAWNS: List[Tuple[str, str]] = [
    # Office spawning shells
    ("winword.exe",      "powershell.exe"),
    ("winword.exe",      "cmd.exe"),
    ("winword.exe",      "wscript.exe"),
    ("winword.exe",      "mshta.exe"),
    ("excel.exe",        "powershell.exe"),
    ("excel.exe",        "cmd.exe"),
    ("excel.exe",        "wscript.exe"),
    ("excel.exe",        "mshta.exe"),
    ("outlook.exe",      "powershell.exe"),
    ("outlook.exe",      "cmd.exe"),
    # Browsers spawning scripting engines
    ("chrome.exe",       "powershell.exe"),
    ("firefox.exe",      "powershell.exe"),
    ("iexplore.exe",     "powershell.exe"),
    ("iexplore.exe",     "cmd.exe"),
    # Living-off-the-land loaders
    ("mshta.exe",        "powershell.exe"),
    ("mshta.exe",        "cmd.exe"),
    ("wscript.exe",      "powershell.exe"),
    ("cscript.exe",      "powershell.exe"),
    ("rundll32.exe",     "powershell.exe"),
    ("regsvr32.exe",     "powershell.exe"),
    ("regsvr32.exe",     "cmd.exe"),
    # Unexpected shells from system processes
    ("services.exe",     "cmd.exe"),
    ("lsass.exe",        "cmd.exe"),
    ("svchost.exe",      "cmd.exe"),
    ("svchost.exe",      "powershell.exe"),
    ("taskeng.exe",      "powershell.exe"),
    ("msiexec.exe",      "powershell.exe"),
    ("msiexec.exe",      "cmd.exe"),
    # WMI lateral movement
    ("wmiprvse.exe",     "powershell.exe"),
    ("wmiprvse.exe",     "cmd.exe"),
    ("wmiprvse.exe",     "wscript.exe"),
    # SQL server as execution vector
    ("sqlservr.exe",     "cmd.exe"),
    ("sqlservr.exe",     "powershell.exe"),
]

# Build a set of (parent, child) tuples for O(1) lookup
_SUSPICIOUS_SET: FrozenSet[Tuple[str, str]] = frozenset(
    (p.lower(), c.lower()) for p, c in _SUSPICIOUS_SPAWNS
)


@dataclass(frozen=True)
class ProcessNode:
    """One observed process instance, scoped to a host."""
    image: str          # basename, lower-cased
    pid: Optional[int]
    ppid: Optional[int]
    host: str
    event_id: str       # which CanonicalEvent created this node
    command_line: Optional[str] = None
    parent_image: Optional[str] = None   # may be absent in some sources


@dataclass
class ProcessTree:
    """
    Index of process relationships observed in a batch of events.

    Internal structures:
      _nodes: (host, pid) -> ProcessNode   — for PID-based parent resolution
      _children: parent_image -> [child_image]  — for image-based queries
      _by_image: image -> [ProcessNode]    — for ancestry reconstruction

    All images are normalised to lowercase basename for stable matching.
    """
    _nodes: Dict[Tuple[str, int], ProcessNode] = field(default_factory=dict)
    _children: Dict[str, List[str]] = field(default_factory=dict)
    _by_image: Dict[str, List[ProcessNode]] = field(default_factory=dict)

    def _basename(self, path: Optional[str]) -> str:
        if not path:
            return ""
        p = path.replace("\\", "/")
        return p.split("/")[-1].lower()

    def build(self, events: List[CanonicalEvent]) -> None:
        """Populate the tree from a sorted list of CanonicalEvents.

        Must be called once before any query method.
        Idempotent: calling again rebuilds from scratch.
        """
        self._nodes.clear()
        self._children.clear()
        self._by_image.clear()

        # Pass 1: register all process events
        for ev in events:
            if ev.event_type != "process":
                continue
            proc = ev.process
            if not proc.pid:
                continue

            image = self._basename(proc.image_path) or self._basename(proc.name)
            if not image:
                continue

            parent_img = self._basename(
                proc.image_path  # will be replaced by parent below if ppid found
            )
            # parent_image may be stored in raw under ParentImage key
            raw_parent = ev.raw.get("parent_image") or ev.raw.get("ParentImage")
            if raw_parent:
                parent_img = self._basename(raw_parent)

            node = ProcessNode(
                image=image,
                pid=proc.pid,
                ppid=proc.ppid,
                host=ev.host.hostname,
                event_id=ev.event_id,
                command_line=proc.command_line,
                parent_image=parent_img or None,
            )
            self._nodes[(ev.host.hostname, proc.pid)] = node

            if image not in self._by_image:
                self._by_image[image] = []
            self._by_image[image].append(node)

        # Pass 2: build parent→child image index
        for node in self._nodes.values():
            parent = node.parent_image
            if not parent:
                # Try to resolve via ppid
                if node.ppid:
                    parent_node = self._nodes.get((node.host, node.ppid))
                    if parent_node:
                        parent = parent_node.image

            if parent:
                if parent not in self._children:
                    self._children[parent] = []
                if node.image not in self._children[parent]:
                    self._children[parent].append(node.image)

    # ── Query API (read-only after build()) ───────────────────────────────────

    def get_children(self, parent_image: str) -> List[str]:
        """Return direct child image basenames for a given parent."""
        return list(self._children.get(parent_image.lower(), []))

    def get_ancestors(self, event: CanonicalEvent, max_depth: int = 10) -> List[str]:
        """Return ancestor chain for the process in this event (root first).

        Cycle guard: stops after max_depth steps.
        """
        if not event.process.pid:
            return []
        node = self._nodes.get((event.host.hostname, event.process.pid))
        if not node:
            return []

        chain: List[str] = []
        visited: set = set()
        current = node
        depth = 0

        while current and depth < max_depth:
            if current.pid in visited:
                break  # cycle detected
            visited.add(current.pid)
            depth += 1

            if current.ppid:
                parent = self._nodes.get((current.host, current.ppid))
                if parent:
                    chain.insert(0, parent.image)
                    current = parent
                    continue
            break

        return chain

    def is_spawn_suspect(
        self,
        parent_image: Optional[str],
        child_image: Optional[str],
    ) -> bool:
        """Return True if (parent, child) is a known suspicious spawn pair."""
        if not parent_image or not child_image:
            return False
        p = self._basename(parent_image)
        c = self._basename(child_image)
        return (p, c) in _SUSPICIOUS_SET

    def all_suspicious_spawns(self, events: List[CanonicalEvent]) -> List[dict]:
        """Return list of suspicious spawn records found in the event batch."""
        results = []
        for ev in events:
            if ev.event_type != "process":
                continue
            child_img = self._basename(ev.process.image_path or ev.process.name or "")
            if not child_img:
                continue

            # Resolve parent
            parent_img: Optional[str] = None
            raw_parent = ev.raw.get("parent_image") or ev.raw.get("ParentImage")
            if raw_parent:
                parent_img = self._basename(raw_parent)
            elif ev.process.ppid:
                parent_node = self._nodes.get((ev.host.hostname, ev.process.ppid))
                if parent_node:
                    parent_img = parent_node.image

            if parent_img and self.is_spawn_suspect(parent_img, child_img):
                results.append({
                    "event_id": ev.event_id,
                    "host": ev.host.hostname,
                    "parent_image": parent_img,
                    "child_image": child_img,
                    "command_line": ev.process.command_line,
                    "user": ev.user.username,
                })
        return results


def build_tree(events: List[CanonicalEvent]) -> ProcessTree:
    """Convenience factory — builds and returns a ready ProcessTree."""
    tree = ProcessTree()
    tree.build(events)
    return tree
