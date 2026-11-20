"""Watchtower watching itself (2026-11-19, the owner: "make it better").

A SIEM that goes quiet looks exactly like a SIEM with nothing to report. After every collector run this
checks each feed: if it has not succeeded for SILENT_AFTER(feed), it writes one 'watchtower' event so the
normal rules open an offense (wt-feed-silent, or wt-aws-login-expired when the cause is the SSO login).
When the feed works again those offenses close themselves with a note, like posture offenses do.
"""
from __future__ import annotations

import time

import config

AWS_FEEDS = {"cloudtrail", "posture", "s3logs"}
RULE_IDS = ("wt-feed-silent", "wt-aws-login-expired")


def silent_after(name: str) -> int:
    """Seconds without a success before a feed counts as silent: three missed runs, at least 30 minutes."""
    return max(3 * config.INTERVALS.get(name, 300), 1800)


def check(store, now: float | None = None) -> tuple[int, list[int]]:
    """Returns (events written, offense ids closed)."""
    now = now or time.time()
    started = store.get("wt_started") or now
    if not store.get("wt_started"):
        store.put("wt_started", now)
    with store.db() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM collector_health")]
    events, back = [], []
    for h in rows:
        name = h["name"]
        if name not in config.COLLECTORS:
            continue
        last_ok = h["last_ok"] or started
        if h["status"] == "ok":
            back.append(name)
            continue
        if now - last_ok < silent_after(name):
            continue
        expired = name in AWS_FEEDS and "login expired" in (h["detail"] or "").lower()
        action = "AwsLoginExpired" if expired else "FeedSilent"
        events.append({"uid": f"wt:{action}:{name}:{int(last_ok)}", "ts": now, "source": "watchtower",
                       "category": "health", "action": action, "outcome": "failure", "actor": name,
                       "target": (h["detail"] or "")[:200], "region": "",
                       "extra": {"last_ok": last_ok, "silent_min": int((now - last_ok) // 60)},
                       "raw_json": "{}"})
    added = store.add_events(events) if events else 0
    return added, _resolve(store, back)


def _resolve(store, back: list[str]) -> list[int]:
    if not back:
        return []
    stamp = time.strftime("%Y-%m-%d %H:%M")
    note = f"Resolved: the feed is delivering again ({stamp})"
    closed = []
    with store.db() as c:
        q = (f"SELECT id FROM offenses WHERE status='open' AND rule_id IN ({','.join('?' * len(RULE_IDS))}) "
             f"AND entity IN ({','.join('?' * len(back))})")
        for o in c.execute(q, (*RULE_IDS, *back)).fetchall():
            c.execute("UPDATE offenses SET status='closed', closed_at=?, note=CASE WHEN COALESCE(note,'')='' THEN ? "
                      "ELSE note || char(10) || ? END WHERE id=?", (time.time(), note, note, o["id"]))
            closed.append(o["id"])
    for oid in closed:
        store.audit("system", "", "auto-closed offense", f"#{oid}: feed is back")
    return closed
