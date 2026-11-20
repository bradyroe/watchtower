"""Offline IP -> country (2026-11-19, round 2).

Uses the free DB-IP "IP to Country Lite" file (CC BY 4.0: "IP Geolocation by DB-IP", https://db-ip.com),
stored in data/geo/. Lookups never leave this machine. The file is refreshed monthly by refresh(), which
is a plain download of a public file; no address being looked up is ever sent anywhere.
"""
from __future__ import annotations

import bisect
import csv
import gzip
import ipaddress
import logging
import threading
import time
import urllib.request

import config

log = logging.getLogger("watchtower.geo")
DIR = config.DATA_DIR / "geo"
FILE = DIR / "dbip-country-lite.csv.gz"
ATTRIBUTION = "IP Geolocation by DB-IP"
_lock = threading.Lock()
_tables: dict[int, tuple[list[int], list[int], list[str]]] | None = None


def _load() -> dict:
    global _tables
    with _lock:
        if _tables is not None:
            return _tables
        t = {4: ([], [], []), 6: ([], [], [])}
        try:
            with gzip.open(FILE, "rt", encoding="utf-8", newline="") as f:
                for lo, hi, cc in csv.reader(f):
                    a, b = ipaddress.ip_address(lo), ipaddress.ip_address(hi)
                    starts, ends, ccs = t[a.version]
                    starts.append(int(a)); ends.append(int(b)); ccs.append(cc)
        except OSError:
            log.warning("geo file missing: %s", FILE)
        _tables = t
        return t


def country(ip: str) -> str:
    """Two-letter country code, '' when unknown, private, or not an IP (e.g. an AWS service name)."""
    try:
        a = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return ""
    if a.is_private or a.is_loopback or a.is_link_local or a.is_reserved:
        return ""
    if a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10"):     # Tailscale / CGNAT
        return ""
    starts, ends, ccs = _load()[a.version]
    i = bisect.bisect_right(starts, int(a)) - 1
    if i >= 0 and int(a) <= ends[i] and ccs[i] != "ZZ":
        return ccs[i]
    return ""


def network(ip: str) -> str:
    """The /16 (IPv4) or /48 (IPv6) an address sits in: a home or office line, not one exact address."""
    try:
        a = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return ""
    return str(ipaddress.ip_network(f"{a}/{16 if a.version == 4 else 48}", strict=False))


def refresh(force: bool = False) -> bool:
    """Download this month's file when ours is older than 35 days. Never raises."""
    global _tables
    try:
        if not force and FILE.exists() and time.time() - FILE.stat().st_mtime < 35 * 86400:
            return False
        DIR.mkdir(parents=True, exist_ok=True)
        url = f"https://download.db-ip.com/free/dbip-country-lite-{time.strftime('%Y-%m')}.csv.gz"
        req = urllib.request.Request(url, headers={"User-Agent": "Watchtower"})
        tmp = FILE.with_suffix(".tmp")
        with urllib.request.urlopen(req, timeout=60) as r, open(tmp, "wb") as f:
            f.write(r.read())
        with gzip.open(tmp, "rt") as f:                  # must be a real gzip csv before it replaces ours
            f.readline()
        tmp.replace(FILE)
        with _lock:
            _tables = None
        return True
    except Exception as exc:                             # noqa: BLE001
        log.warning("geo refresh failed: %s", type(exc).__name__)
        return False
