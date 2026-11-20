"""Read-side queries for the console. Everything takes a time range (start, end) in epoch seconds."""
from __future__ import annotations

import json
import time

import rules as R

RANGES = {"1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
SOURCES = ["aws-cloudtrail", "aws-posture", "windows", "tailscale", "aws-flowlogs", "watchtower"]


def bucket_for(span: float) -> int:
    for b in (60, 300, 900, 3600, 3 * 3600, 6 * 3600, 86400):
        if span / b <= 120:
            return b
    return 86400


def series_by_source(store, start: float, end: float) -> dict:
    b = bucket_for(end - start)
    first = int(start // b) * b
    xs = list(range(first, int(end) + 1, b))
    idx = {x: i for i, x in enumerate(xs)}
    out = {}
    with store.db() as c:
        for r in c.execute("SELECT source, CAST(ts/? AS INTEGER)*? AS t, COUNT(*) n FROM events WHERE ts BETWEEN ? AND ? "
                           "GROUP BY source, t", (b, b, start, end)):
            out.setdefault(r["source"], [0] * len(xs))
            i = idx.get(r["t"])
            if i is not None:
                out[r["source"]][i] = r["n"]
    return {"x": xs, "bucket": b, "series": out}


def counts(store, start, end) -> dict:
    with store.db() as c:
        total = c.execute("SELECT COUNT(*) FROM events WHERE ts BETWEEN ? AND ?", (start, end)).fetchone()[0]
        by = {r["source"]: r["n"] for r in c.execute(
            "SELECT source, COUNT(*) n FROM events WHERE ts BETWEEN ? AND ? GROUP BY source", (start, end))}
        open_off = c.execute("SELECT COUNT(*) FROM offenses WHERE status='open'").fetchone()[0]
        new_off = c.execute("SELECT COUNT(*) FROM offenses WHERE first_seen BETWEEN ? AND ?", (start, end)).fetchone()[0]
    return {"total": total, "by_source": by, "open_offenses": open_off, "new_offenses": new_off}


def top(store, field: str, start, end, n=8, where="") -> list[dict]:
    assert field in ("actor", "src_ip", "action", "target")
    with store.db() as c:
        return [dict(r) for r in c.execute(
            f"SELECT {field} AS k, COUNT(*) n, SUM(outcome='failure') fails FROM events WHERE ts BETWEEN ? AND ? "
            f"AND {field}<>'' {where} GROUP BY {field} ORDER BY n DESC LIMIT ?", (start, end, n))]


def offenses(store, status="open", q="", min_mag=0, start=None, end=None, limit=500) -> list[dict]:
    sql, args = "SELECT * FROM offenses WHERE magnitude>=?", [min_mag]
    if status in ("open", "closed"):
        sql += " AND status=?"
        args.append(status)
    if q:
        sql += " AND (title LIKE ? OR entity LIKE ? OR note LIKE ? OR CAST(id AS TEXT)=?)"
        args += [f"%{q}%", f"%{q}%", f"%{q}%", q]
    if start is not None:
        sql += " AND last_seen>=?"
        args.append(start)
    sql += " ORDER BY status='open' DESC, magnitude DESC, last_seen DESC LIMIT ?"
    args.append(limit)
    with store.db() as c:
        rows = [dict(r) for r in c.execute(sql, args)]
    for r in rows:
        r["rule"] = R.BY_ID.get(r["rule_id"], {"name": r["rule_id"], "why": ""})
    return rows


def offense(store, oid: int) -> dict | None:
    with store.db() as c:
        r = c.execute("SELECT * FROM offenses WHERE id=?", (oid,)).fetchone()
        if not r:
            return None
        o = dict(r)
        o["events"] = [dict(x) for x in c.execute(
            "SELECT e.* FROM events e JOIN offense_events oe ON oe.event_id=e.id WHERE oe.offense_id=? ORDER BY e.ts DESC LIMIT 500",
            (oid,))]
    o["rule"] = R.BY_ID.get(o["rule_id"], {"name": o["rule_id"], "why": "", "window_min": 0})
    return o


def search_events(store, f: dict, start, end, before_id=None, after_id=None, limit=200) -> list[dict]:
    sql, args = "SELECT id,uid,ts,source,category,action,outcome,actor,src_ip,target,region FROM events WHERE ts BETWEEN ? AND ?", [start, end]
    for k in ("source", "outcome", "category"):
        if f.get(k):
            sql += f" AND {k}=?"
            args.append(f[k])
    for k in ("actor", "src_ip", "action", "target"):
        if f.get(k):
            sql += f" AND {k} LIKE ?"
            args.append(f"%{f[k]}%")
    if f.get("q"):
        sql += " AND (action LIKE ? OR actor LIKE ? OR src_ip LIKE ? OR target LIKE ? OR raw_json LIKE ?)"
        args += [f"%{f['q']}%"] * 5
    if before_id:
        sql += " AND id<?"
        args.append(before_id)
    if after_id:
        sql += " AND id>?"
        args.append(after_id)
    sql += " ORDER BY ts DESC, id DESC LIMIT ?"
    args.append(limit)
    with store.db() as c:
        return [dict(r) for r in c.execute(sql, args)]


def event(store, eid: int) -> dict | None:
    with store.db() as c:
        r = c.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if not r:
        return None
    d = dict(r)
    for k in ("raw_json", "extra_json"):
        try:
            d[k[:-5]] = json.loads(d.pop(k))
        except ValueError:
            d[k[:-5]] = d.pop(k, "")
    return d


def findings(store) -> list[dict]:
    with store.db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM findings WHERE active=1 ORDER BY severity DESC, entity")]


def health(store) -> list[dict]:
    with store.db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM collector_health ORDER BY name")]


def rule_stats(store, start, end) -> dict:
    with store.db() as c:
        hits = {r["rule_id"]: r["n"] for r in c.execute(
            "SELECT rule_id, COUNT(*) n FROM rule_hits WHERE ts BETWEEN ? AND ? GROUP BY rule_id", (start, end))}
        offs = {r["rule_id"]: r["n"] for r in c.execute(
            "SELECT rule_id, COUNT(*) n FROM offenses WHERE status='open' GROUP BY rule_id")}
        off = {r["rule_id"] for r in c.execute("SELECT rule_id FROM rule_state WHERE enabled=0")}
    return {"hits": hits, "offenses": offs, "disabled": off}


def audit(store, limit=200) -> list[dict]:
    with store.db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]


def now() -> float:
    return time.time()
