# Process Tree — process_tree.py

## Objectif

Construire et interroger les relations parent→enfant entre processus, à partir d'une liste de `CanonicalEvent`, pour alimenter les règles de détection de type "spawn suspect".

## Modèle de données

### ProcessNode

```python
@dataclass(frozen=True)
class ProcessNode:
    image: str               # basename, lowercase ex: "powershell.exe"
    pid: Optional[int]
    ppid: Optional[int]
    host: str
    event_id: str            # CanonicalEvent source
    command_line: Optional[str]
    parent_image: Optional[str]  # si disponible dans le champ ParentImage
```

### ProcessTree

```python
@dataclass
class ProcessTree:
    _nodes:    Dict[Tuple[str, int], ProcessNode]   # (host, pid) → node
    _children: Dict[str, List[str]]                  # parent_image → [child_image]
    _by_image: Dict[str, List[ProcessNode]]          # image → [nodes]
```

## Construction — deux passes

```python
tree = build_tree(events)
```

**Passe 1 — Enregistrement :** parcourt tous les événements `process` et crée un `ProcessNode` pour chacun. Remplit `_nodes` et `_by_image`.

**Passe 2 — Résolution des liens :** pour chaque nœud, tente de trouver son parent :
1. Via `parent_image` explicite (champ `ParentImage` dans Sysmon EventID 1)
2. Via PPID → lookup dans `_nodes[(host, ppid)]`
3. Si aucun parent trouvé, le nœud est racine

!!! question "Pourquoi deux passes ?"
    Sans la passe 1, on ne peut pas résoudre les PPID en images lors de la passe 2 : un processus peut apparaître dans la liste *après* son enfant si les timestamps sont proches ou identiques. Les deux passes garantissent que tous les nœuds existent avant qu'on essaie de construire les liens.

## API de requête

### `get_children(parent_image: str) -> List[str]`

Retourne les images enfants directes d'un parent.

```python
tree.get_children("winword.exe")
# → ["powershell.exe", "cmd.exe"]
```

### `get_ancestors(event: CanonicalEvent, max_depth=10) -> List[str]`

Retourne la chaîne d'ancêtres d'un processus (du plus ancien au plus proche).

```python
ancestors = tree.get_ancestors(powershell_event)
# → ["explorer.exe", "winword.exe"]
```

**Cycle guard** : le parcours s'arrête après `max_depth` niveaux ou dès qu'un PID déjà visité est rencontré.

### `is_spawn_suspect(parent_image, child_image) -> bool`

Vérifie si la paire parent→enfant est dans la table des spawns suspects.

```python
tree.is_spawn_suspect("winword.exe", "powershell.exe")  # → True
tree.is_spawn_suspect("explorer.exe", "notepad.exe")    # → False
```

### `all_suspicious_spawns(events) -> List[dict]`

Parcourt tous les événements et retourne les paires suspectes trouvées.

```python
spawns = tree.all_suspicious_spawns(events)
# → [{"event_id": "...", "host": "WIN01",
#     "parent_image": "winword.exe",
#     "child_image": "powershell.exe",
#     "command_line": "powershell -enc ...",
#     "user": "jdoe"}]
```

## Table des spawns suspects

32 paires définies dans `_SUSPICIOUS_SPAWNS`. Organisées par catégorie :

| Catégorie | Parents | Enfants suspects |
|-----------|---------|-----------------|
| Office macros | winword, excel, outlook | powershell, cmd, wscript, mshta |
| Browsers | chrome, firefox, iexplore | powershell, cmd |
| LOTL loaders | mshta, wscript, cscript, rundll32, regsvr32 | powershell, cmd |
| System processes | services, lsass, svchost, taskeng, msiexec | cmd, powershell |
| WMI | wmiprvse | powershell, cmd, wscript |
| SQL Server | sqlservr | cmd, powershell |

La comparaison utilise les **basenames en minuscules** — le chemin complet n'est pas considéré. `C:\Windows\System32\powershell.exe` et `C:\Windows\SysWOW64\powershell.exe` sont tous deux `powershell.exe`.

## Normalisation des images

```python
def _basename(path: Optional[str]) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").split("/")[-1].lower()
```

Exemples :
```
C:\Windows\System32\vssadmin.exe  →  vssadmin.exe
/usr/bin/python3                  →  python3
powershell.exe                    →  powershell.exe
```
