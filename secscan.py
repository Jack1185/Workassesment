#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
secscan.py — simple security log analysis CLI

Parses log lines of the form:
[Timestamp] [Severity] [Source IP] [Event Type] [Message/Details]

Usage:
  python secscan.py sample_security.log
  python secscan.py sample_security.log --json findings.json --csv findings.csv --threshold-bruteforce 3 --window-bruteforce 15
"""

from __future__ import annotations
import argparse
import csv
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Iterable, List, Dict, Optional

@dataclass
class LogEntry:
    ts: datetime
    severity: str
    src_ip: str
    event: str
    details_raw: str
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    kv: Optional[Dict[str, str]] = None

@dataclass
class Incident:
    rule: str
    timestamp: datetime
    src_ip: str
    summary: str
    context: Dict[str, str]

LINE_RE = re.compile(
    r"^\[(?P<ts>[^]]+)\]\s+(?P<sev>\S+)\s+(?P<ip>\S+)\s+(?P<event>\S+)\s*(?P<rest>.*)$"
)

HTTP_RE = re.compile(
    r"^(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?P<path>\S+)\s+(?P<status>\d{3})(?:\s+(?P<kv>.*))?$",
    re.IGNORECASE,
)

KV_RE = re.compile(r"(?P<k>[A-Za-z0-9_\-\.]+)=(?P<v>\S+)")

def parse_line(line: str) -> Optional[LogEntry]:
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    ts_str = m.group("ts")
    sev = m.group("sev")
    ip = m.group("ip")
    event = m.group("event")
    rest = (m.group("rest") or "").strip()
    try:
        ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        ts = datetime.fromisoformat(ts_str)
    entry = LogEntry(ts=ts, severity=sev, src_ip=ip, event=event, details_raw=rest)
    hm = HTTP_RE.match(rest)
    if hm:
        entry.http_method = hm.group("method").upper()
        entry.http_path = hm.group("path")
        entry.http_status = int(hm.group("status"))
        kv_text = hm.group("kv")
        if kv_text:
            entry.kv = dict(KV_RE.findall(kv_text)) or None
        return entry
    kv_matches = list(KV_RE.finditer(rest))
    if kv_matches:
        entry.kv = {m.group("k"): m.group("v") for m in kv_matches}
    return entry

def parse_file(path: str) -> Iterable[LogEntry]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                entry = parse_line(line)
                if entry:
                    yield entry

SQLI_PATTERNS = [
    r"(?i)\bOR\s+1=1\b",
    r"(?i)\bUNION\s+SELECT\b",
    r"(?i)\bSELECT\s+\*\s+FROM\b",
    r"--\s*$",
    r";--\s*$",
]

SENSITIVE_PATHS = {
    "/etc/passwd",
    "/root/.bashrc",
    "/var/log/auth.log",
    "/admin/panel",
}

def detect_sql_injection(entries: Iterable[LogEntry]) -> List[Incident]:
    incidents: List[Incident] = []
    for e in entries:
        if e.event.upper() == "SQL_INJECTION_ATTEMPT":
            incidents.append(
                Incident(
                    rule="SQL Injection (explicit)",
                    timestamp=e.ts,
                    src_ip=e.src_ip,
                    summary=f"SQL injection attempt flagged by source at {e.src_ip}",
                    context={"details": e.details_raw},
                )
            )
            continue
        if any(re.search(pat, e.details_raw) for pat in SQLI_PATTERNS):
            incidents.append(
                Incident(
                    rule="SQL Injection (pattern)",
                    timestamp=e.ts,
                    src_ip=e.src_ip,
                    summary=f"Possible SQLi pattern from {e.src_ip}",
                    context={"details": e.details_raw},
                )
            )
    return incidents

def detect_unusual_access(entries: Iterable[LogEntry]) -> List[Incident]:
    inc: List[Incident] = []
    for e in entries:
        if e.event.upper() == "UNUSUAL_ACCESS":
            inc.append(
                Incident(
                    rule="Unusual Access (explicit)",
                    timestamp=e.ts,
                    src_ip=e.src_ip,
                    summary=f"Unusual access reported by {e.src_ip}",
                    context={"resource": e.details_raw},
                )
            )
        if e.http_path and e.http_status in (401, 403) and e.http_path in SENSITIVE_PATHS:
            inc.append(
                Incident(
                    rule="Forbidden admin access",
                    timestamp=e.ts,
                    src_ip=e.src_ip,
                    summary=f"{e.http_status} on {e.http_path} from {e.src_ip}",
                    context={"path": e.http_path, "status": str(e.http_status)},
                )
            )
    return inc

def detect_bruteforce(entries: Iterable[LogEntry], threshold: int = 3, window_seconds: int = 15) -> List[Incident]:
    per_ip = defaultdict(deque)
    window = timedelta(seconds=window_seconds)
    incidents: List[Incident] = []
    for e in entries:
        if e.event.upper() != "FAILED_LOGIN":
            continue
        ip = e.src_ip
        dq = per_ip[ip]
        dq.append(e.ts)
        while dq and (e.ts - dq[0]) > window:
            dq.popleft()
        if len(dq) >= threshold:
            incidents.append(
                Incident(
                    rule="Brute Force (failed logins)",
                    timestamp=e.ts,
                    src_ip=ip,
                    summary=f"{len(dq)} failed logins within {window_seconds}s from {ip}",
                    context={"count_in_window": str(len(dq)), "user": (e.kv or {}).get("user", "?")},
                )
            )
    return incidents

def detect_port_scans(entries: Iterable[LogEntry], threshold_unique_ports: int = 3, window_seconds: int = 60) -> List[Incident]:
    window = timedelta(seconds=window_seconds)
    per_ip_deque = defaultdict(deque)
    incidents: List[Incident] = []
    def cleanup(ip: str, now: datetime) -> None:
        dq = per_ip_deque[ip]
        while dq and (now - dq[0][0]) > window:
            dq.popleft()
    for e in entries:
        if e.event.upper() != "PORT_SCAN_ATTEMPT":
            continue
        ip = e.src_ip
        target = None
        if e.kv and "target" in e.kv:
            target = e.kv["target"]
        else:
            m = re.search(r"target=(\d+)", e.details_raw)
            if m:
                target = m.group(1)
        if target is None:
            continue
        dq = per_ip_deque[ip]
        dq.append((e.ts, target))
        cleanup(ip, e.ts)
        unique_ports = {t for _, t in dq}
        if len(unique_ports) >= threshold_unique_ports:
            incidents.append(
                Incident(
                    rule="Port Scan",
                    timestamp=e.ts,
                    src_ip=ip,
                    summary=f"{len(unique_ports)} unique ports probed within {window_seconds}s by {ip}",
                    context={"unique_ports": ",".join(sorted(unique_ports))},
                )
            )
    return incidents

def format_incident(i: Incident) -> str:
    ts = i.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    ctx = ", ".join(f"{k}={v}" for k, v in i.context.items())
    return f"[{ts}] {i.rule:<28} src={i.src_ip:<15} | {i.summary} | {ctx}"

def write_json(incidents: List[Incident], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(i) for i in incidents], f, indent=2, default=str)

def write_csv(incidents: List[Incident], path: str) -> None:
    fieldnames = ["rule", "timestamp", "src_ip", "summary", "context"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for i in incidents:
            row = asdict(i)
            row["timestamp"] = i.timestamp.isoformat(sep=" ")
            row["context"] = ";".join(f"{k}={v}" for k, v in i.context.items())
            w.writerow(row)

def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze security logs and detect suspicious activity.")
    ap.add_argument("logfile", help="Path to the log file (e.g., sample_security.log)")
    ap.add_argument("--threshold-bruteforce", type=int, default=3, help="Failed login threshold (default: 3)")
    ap.add_argument("--window-bruteforce", type=int, default=15, help="Window (seconds) for brute force (default: 15)")
    ap.add_argument("--threshold-ports", type=int, default=3, help="Distinct ports threshold (default: 3)")
    ap.add_argument("--window-ports", type=int, default=60, help="Window (seconds) for port scan (default: 60)")
    ap.add_argument("--json", dest="json_out", help="Write findings as JSON to this file")
    ap.add_argument("--csv", dest="csv_out", help="Write findings as CSV to this file")
    ap.add_argument("--quiet", action="store_true", help="Suppress console output")
    args = ap.parse_args()

    entries = list(parse_file(args.logfile))
    entries.sort(key=lambda e: e.ts)

    incidents: List[Incident] = []
    incidents += detect_bruteforce(entries, threshold=args.threshold_bruteforce, window_seconds=args.window_bruteforce)
    incidents += detect_sql_injection(entries)
    incidents += detect_unusual_access(entries)
    incidents += detect_port_scans(entries, threshold_unique_ports=args.threshold_ports, window_seconds=args.window_ports)
    incidents.sort(key=lambda i: i.timestamp)

    if not args.quiet:
        print("\n=== Suspicious Activity Report ===")
        if not incidents:
            print("No incidents detected.")
        else:
            for i in incidents:
                print(format_incident(i))
        print(f"\nTotal incidents: {len(incidents)}\n")

    if args.json_out:
        write_json(incidents, args.json_out)
    if args.csv_out:
        write_csv(incidents, args.csv_out)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
