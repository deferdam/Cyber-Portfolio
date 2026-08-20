from __future__ import annotations
import re
from typing import Any, Dict, Optional
from core.ids import stable_event_id
from core.schemas import CanonicalEvent, FileRef, HostRef, NetworkRef, ProcessRef, UserRef
from core.time import parse_to_utc, utcnow

def _ext(path):
    if not path: return ""
    p = path.replace("\\","/"); last = p.split("/")[-1]
    return last.split(".")[-1].lower() if "." in last else ""

def _dir(path):
    if not path: return ""
    p = path.replace("\\","/")
    return "/".join(p.split("/")[:-1]) if "/" in p else ""

def _execve_cmdline(raw):
    if raw.get("args"): return str(raw["args"])
    if raw.get("cmdline"): return str(raw["cmdline"])
    parts = []
    for i in range(32):
        v = raw.get(f"a{i}")
        if v is None: break
        arg = str(v)
        if re.match(r"^[0-9A-F]{2,}$", arg) and len(arg)%2==0:
            try: arg = bytes.fromhex(arg).decode("utf-8",errors="replace")
            except: pass
        parts.append(arg)
    return " ".join(parts) if parts else None

_AUTH_USER = re.compile(r"for (?:invalid user )?(\S+) from ([\d.a-fA-F:]+)", re.I)
_AUTH_SUDO = re.compile(r"sudo:\s+(\S+)\s+:", re.I)
_AUTH_PAM  = re.compile(r"pam_unix.*?user[= ](\S+)", re.I)

def _parse_auth(msg):
    for pat,keys in [(_AUTH_USER,("username","src_ip")),(_AUTH_SUDO,("username",)),(_AUTH_PAM,("username",))]:
        m = pat.search(msg)
        if m: return dict(zip(keys,m.groups()))
    return {}

def _detect_source(raw):
    src = str(raw.get("source") or raw.get("log_source") or "").lower()
    if src: return src
    t = str(raw.get("type") or "").upper()
    if t in ("EXECVE","SYSCALL","PATH","PROCTITLE","CWD"): return "auditd"
    msg = str(raw.get("message") or raw.get("msg") or "").lower()
    if any(k in msg for k in ("failed password","accepted password","sudo:","pam_unix","session opened")): return "auth"
    if raw.get("EventID") or raw.get("event_id"): return "sysmon_like"
    if raw.get("facility") or raw.get("severity") or raw.get("hostname"): return "syslog"
    return "unknown"

def _norm_auditd(raw, host):
    t = str(raw.get("type") or "").upper()
    if t == "EXECVE": cmdline = _execve_cmdline(raw)
    elif t == "PROCTITLE":
        pt = str(raw.get("proctitle") or "")
        if re.match(r"^[0-9A-F]+$", pt):
            try: pt = bytes.fromhex(pt).decode("utf-8",errors="replace").replace("\x00"," ")
            except: pass
        cmdline = pt or None
    else: cmdline = raw.get("command_line") or raw.get("CommandLine") or raw.get("cmdline")
    img = raw.get("exe") or raw.get("image_path") or raw.get("Image")
    _a0 = raw.get("a0")
    _name = (str(img).split("/")[-1] if img
             else raw.get("process_name")
             or (str(_a0).split("/")[-1] if _a0 else None))
    proc = ProcessRef(name=_name,
        pid=raw.get("pid"), ppid=raw.get("ppid"), image_path=img, command_line=cmdline, integrity_level=None)
    fp = raw.get("name") or raw.get("path") or raw.get("file_path")
    file_ref = FileRef(path=fp, operation=raw.get("operation"), extension=_ext(fp), directory=_dir(fp))
    net = NetworkRef(direction=raw.get("direction"), dest_ip=raw.get("addr") or raw.get("dest_ip"),
                     dest_port=raw.get("port") or raw.get("dest_port"), protocol=raw.get("protocol"))
    uid = raw.get("uid") or raw.get("auid")
    user = UserRef(username=raw.get("username") or raw.get("user"), sid=str(uid) if uid is not None else None)
    etype = "process" if t in ("EXECVE","PROCTITLE") else "other"
    return proc, file_ref, net, user, etype

def _norm_auth(raw, host):
    msg = str(raw.get("message") or raw.get("msg") or "")
    parsed = _parse_auth(msg)
    pname, pid = raw.get("process_name") or raw.get("program"), raw.get("pid") or raw.get("process_pid")
    if not pname:
        m = re.match(r"(\w+)\[(\d+)\]:", str(raw.get("ident") or ""))
        if m: pname, pid = m.group(1), int(m.group(2))
    proc = ProcessRef(name=pname, pid=pid, command_line=msg[:512])
    net = NetworkRef(dest_ip=parsed.get("src_ip"), direction="inbound")
    return proc, FileRef(), net, UserRef(username=parsed.get("username")), "auth"

def normalize(raw: Dict[str, Any], default_host: str = "unknown-host") -> CanonicalEvent:
    event_time, ingest_time = parse_to_utc(str(raw.get("timestamp"))), utcnow()
    host = HostRef(hostname=str(raw.get("host") or raw.get("hostname") or default_host),
                   ip=raw.get("host_ip") or raw.get("ip"))
    source = _detect_source(raw)
    if source == "auditd":
        proc, file_ref, net, user, etype = _norm_auditd(raw, host)
    elif source == "auth":
        proc, file_ref, net, user, etype = _norm_auth(raw, host)
    else:
        etype = raw.get("event_type") or "file"
        if etype not in ("file","network","process","auth","other"): etype = "other"
        fp = raw.get("file_path")
        proc = ProcessRef(name=raw.get("process_name"), pid=raw.get("pid"), ppid=raw.get("ppid"),
                          image_path=raw.get("process_path"), command_line=raw.get("command_line"),
                          integrity_level=raw.get("integrity_level"))
        file_ref = FileRef(path=fp, operation=raw.get("operation"), extension=_ext(fp), directory=_dir(fp))
        net = NetworkRef(direction=raw.get("direction"), dest_ip=raw.get("dest_ip"),
                         dest_port=raw.get("dest_port"), protocol=raw.get("protocol"))
        user = UserRef(username=raw.get("username"), domain=raw.get("domain"), sid=raw.get("sid"))
    return CanonicalEvent(event_id=stable_event_id(raw), event_time_utc=event_time,
        ingest_time_utc=ingest_time, source=source, event_type=etype, host=host,
        user=user, process=proc, file=file_ref, network=net, raw=raw)
