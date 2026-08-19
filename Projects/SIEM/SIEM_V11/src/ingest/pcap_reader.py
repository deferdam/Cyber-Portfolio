"""PCAP / Wireshark ingestion reader (LOCAL ONLY).

Parses a saved .pcap capture into canonical network raw dicts using dpkt. Each TCP or
UDP packet becomes a network event with src/dst ip and port and protocol. Binary parsing
of a third-party format is a security-sensitive surface, hence local only and never
exposed in server mode.

Defensive: a packet that fails to decode is skipped, never fatal. If dpkt is not
installed the reader raises a clear message and the format stays disabled in the UI.
"""
from __future__ import annotations

import datetime as _dt
import socket
import sys
from typing import Any, Dict, Iterator

try:
    import dpkt
    _HAVE_DPKT = True
except Exception:
    _HAVE_DPKT = False


def _ip_str(family, raw_addr):
    try:
        return socket.inet_ntop(family, raw_addr)
    except Exception:
        return None


def _iso(ts_epoch):
    try:
        return _dt.datetime.fromtimestamp(float(ts_epoch), _dt.timezone.utc).isoformat()
    except Exception:
        return None


def read(path_or_stdin: Any) -> Iterator[Dict[str, Any]]:
    if not _HAVE_DPKT:
        raise RuntimeError("PCAP support requires dpkt. Install it: pip install dpkt")
    if path_or_stdin == "-":
        raise RuntimeError("PCAP is a binary format and cannot be read from stdin; pass a file path.")

    f = open(str(path_or_stdin), "rb")
    try:
        try:
            pcap = dpkt.pcap.Reader(f)
        except ValueError as exc:
            raise RuntimeError(f"not a valid pcap file: {exc}")
        for n, (ts, buf) in enumerate(pcap, start=1):
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if isinstance(ip, dpkt.ip.IP):
                    fam, src, dst = socket.AF_INET, ip.src, ip.dst
                elif isinstance(ip, dpkt.ip6.IP6):
                    fam, src, dst = socket.AF_INET6, ip.src, ip.dst
                else:
                    continue
                l4 = ip.data
                if isinstance(l4, dpkt.tcp.TCP):
                    proto = "TCP"
                elif isinstance(l4, dpkt.udp.UDP):
                    proto = "UDP"
                else:
                    continue
                raw = {
                    "source":     "pcap",
                    "event_type": "network",
                    "timestamp":  _iso(ts),
                    "host":       _ip_str(fam, dst) or "pcap-host",
                    "src_ip":     _ip_str(fam, src),
                    "src_port":   int(l4.sport),
                    "dest_ip":    _ip_str(fam, dst),
                    "dest_port":  int(l4.dport),
                    "protocol":   proto,
                }
                yield {k: v for k, v in raw.items() if v is not None}
            except Exception as exc:
                print(f"[pcap] WARN packet {n}: {exc}", file=sys.stderr)
    finally:
        f.close()
