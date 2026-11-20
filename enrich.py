"""Enrichment and baselines (2026-11-19, round 2).

Before the rules see a CloudTrail event, this adds:
  country      offline lookup of src_ip (geo.py)
  new_country  this actor has signed in before, but never from this country
  new_network  this actor has been seen before, but never from this /16 network
  new_region   the account has history, but has never had a write in this AWS region
"New" needs history first: the first value ever seen for an actor is learning, not an alert.
Baselines live in the `baseline` table so they survive restarts and can be shown on the Learn page.
"""
from __future__ import annotations

import json

import geo


def _x(e: dict) -> dict:
    x = e.get("extra")
    if isinstance(x, dict):
        return x
    try:
        return json.loads(e.get("extra_json") or "{}")
    except ValueError:
        return {}


def _seen(c, kind: str, key: str, value: str, ts: float) -> tuple[bool, bool]:
    """Record (kind, key, value). Returns (key had history before, this value is new for the key)."""
    had = c.execute("SELECT 1 FROM baseline WHERE kind=? AND key=? LIMIT 1", (kind, key)).fetchone() is not None
    cur = c.execute("INSERT OR IGNORE INTO baseline(kind,key,value,first_seen) VALUES(?,?,?,?)", (kind, key, value, ts))
    return had, cur.rowcount == 1


def event(c, e: dict, learn_only: bool = False) -> dict:
    """Enrich one event in place (and in the DB row when it has an id). Returns the extra dict."""
    if e.get("source") != "aws-cloudtrail":
        return _x(e)
    x = dict(_x(e))
    if x.get("drill"):                                   # drills carry their own flags
        e["extra"] = x
        return x
    ip, actor, ts = e.get("src_ip") or "", e.get("actor") or "", e.get("ts") or 0
    cc = geo.country(ip)
    if cc:
        x["country"] = cc
    ok = e.get("outcome") == "success"
    if ok and actor and cc and e.get("action") == "ConsoleLogin":
        had, new = _seen(c, "signin-country", actor, cc, ts)
        x["new_country"] = had and new and not learn_only
    net = geo.network(ip) if cc else ""                  # only real public addresses, not AWS service names
    if ok and actor and net and x.get("identity_type") in ("IAMUser", "Root"):
        had, new = _seen(c, "network", actor, net, ts)
        x["new_network"] = had and new and not learn_only
    region = e.get("region") or ""
    if ok and region and x.get("read_only") is False and x.get("event_type") in ("AwsApiCall", "AwsConsoleAction"):
        had, new = _seen(c, "write-region", "account", region, ts)
        x["new_region"] = had and new and not learn_only
    e["extra"] = x
    if e.get("id"):
        c.execute("UPDATE events SET extra_json=? WHERE id=?", (json.dumps(x, default=str), e["id"]))
    return x


def seed(store) -> int:
    """First run on an existing database: learn from every CloudTrail event already stored, flag nothing."""
    if store.get("baseline_seeded"):
        return 0
    n = 0
    with store.db() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM events WHERE source='aws-cloudtrail' ORDER BY ts")]
        for e in rows:
            event(c, e, learn_only=True)
            n += 1
    store.put("baseline_seeded", True)
    return n
