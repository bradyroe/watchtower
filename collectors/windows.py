"""This PC's Windows event logs, read with wevtutil (no admin needed for most logs).

The Security log needs admin or the "Event Log Readers" group (the owner added 2026-11-19); when access is denied that is recorded, not fatal, and the
other logs still run.
"""
from __future__ import annotations

import datetime as dt
import re
import subprocess
import sys
import time

import config
import normalize

NAME = "windows"
NO_WINDOW = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


def _query(log: str, since: float, limit: int) -> tuple[list[str], str]:
    iso = dt.datetime.fromtimestamp(since, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    q = f"*[System[TimeCreated[@SystemTime>='{iso}']]]"
    p = subprocess.run(["wevtutil", "qe", log, f"/q:{q}", "/f:xml", f"/c:{limit}"], capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=120, creationflags=NO_WINDOW)
    if p.returncode != 0:
        return [], (p.stderr or p.stdout or "").strip().splitlines()[0] if (p.stderr or p.stdout) else f"exit {p.returncode}"
    return re.findall(r"<Event .*?</Event>", p.stdout, re.S), ""


def run(store) -> int:
    if sys.platform != "win32":
        store.health(NAME, False, "not Windows")
        return 0
    added, status = 0, []
    for log in config.WINDOWS_LOGS:
        key = f"win_since:{log}"
        since = store.get(key) or time.time() - config.WINDOWS_BACKFILL_HOURS * 3600
        try:
            xs, err = _query(log, since, config.WINDOWS_MAX_PER_RUN)
        except Exception as exc:                   # noqa: BLE001
            xs, err = [], f"{type(exc).__name__}: {exc}"
        if err:
            status.append(f"{log}: {'needs admin' if 'denied' in err.lower() else err[:80]}")
            continue
        evs = [e for e in (normalize.windows(x, log) for x in xs) if e]
        added += store.add_events(evs)
        if evs:
            store.put(key, max(e["ts"] for e in evs) + 0.001)
        status.append(f"{log}: ok")
    readable = [s for s in status if s.endswith(": ok")]
    store.health(NAME, bool(readable), "; ".join(status), added)
    store.put("windows_logs_status", status)
    return added
