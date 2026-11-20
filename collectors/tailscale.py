"""Tailscale peers: new devices, and devices going online or offline.

The first run records the devices already on the tailnet as a baseline, so only a device that
joins after that raises "new device".
"""
from __future__ import annotations

import json
import subprocess
import sys
import time

import config
import normalize

NAME = "tailscale"
NO_WINDOW = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


def status() -> dict:
    p = subprocess.run([config.TAILSCALE_BIN, "status", "--json"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=30, creationflags=NO_WINDOW)
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout or f"exit {p.returncode}").strip()[:200])
    return json.loads(p.stdout)


def run(store, get_status=status) -> int:
    try:
        st = get_status()
    except Exception as exc:                       # noqa: BLE001
        store.health(NAME, False, f"{type(exc).__name__}: {exc}")
        return 0
    peers = list((st.get("Peer") or {}).values())
    if st.get("Self"):
        peers.append(st["Self"])
    known = store.get("ts_known")                  # {id: online}
    now = time.time()
    evs = []
    if known is None:
        known = {}
        for p in peers:
            known[p.get("ID", "")] = bool(p.get("Online"))
            evs.append(normalize.tailscale("DeviceBaseline", p, now))
    else:
        for p in peers:
            pid, online = p.get("ID", ""), bool(p.get("Online"))
            if pid not in known:
                evs.append(normalize.tailscale("NewDevice", p, now))
            elif known[pid] != online:
                evs.append(normalize.tailscale("DeviceOnline" if online else "DeviceOffline", p, now))
            known[pid] = online
    store.put("ts_known", known)
    n = store.add_events(evs)
    store.health(NAME, True, f"{len(peers)} devices, {sum(1 for p in peers if p.get('Online'))} online", n)
    return n
