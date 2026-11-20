"""Runs the rules over new events and rolls hits into offenses.

Offense = one rule + one entity. A hit joins that entity's open offense when it falls inside the
rule's window from the offense's last event; otherwise it opens a new one (once the threshold is
met). Magnitude follows the familiar SIEM split: severity (how bad), credibility (how sure),
relevance (how important the entity is, plus how much activity there was).
"""
from __future__ import annotations

import json
import math
import threading
import time

import config
import enrich
import rules as R
from rules.builtin import matches

# An open offense keeps collecting its rule's hits for the same entity until it has been quiet this
# long ("dormant"); the rule window only decides how many hits it takes to open one.
DORMANT = 5 * 86400


def enabled(store) -> set[str]:
    with store.db() as c:
        off = {r["rule_id"] for r in c.execute("SELECT rule_id FROM rule_state WHERE enabled=0")}
    return {r["id"] for r in R.ALL} - off


def relevance(entity: str, count: int) -> int:
    base = 7 if entity.lower() in config.IMPORTANT_ENTITIES else 4
    return max(1, min(10, base + int(math.log2(max(1, count)))))


def magnitude(sev: int, cred: int, rel: int) -> int:
    # Weighted toward severity; rounded to 1-10.
    return max(1, min(10, round(0.5 * sev + 0.2 * cred + 0.3 * rel)))


LOCK = threading.RLock()


def process(store, batch: int = 5000, created: list | None = None) -> int:
    """Match all events not yet processed. Returns the number of rule hits.
    `created`: if given, the id of every offense this run opened is appended (for Discord pings)."""
    with LOCK:
        return _process(store, batch, created)


def _process(store, batch: int, created: list | None) -> int:
    last = store.get("engine_last_id", 0)
    if not store.get("baseline_seeded"):
        enrich.seed(store)                               # learn from history once; flags nothing
    on = enabled(store)
    hits = 0
    for _pass in range(2):                               # pass 2 matches the correlation events pass 1 wrote
        h, last = _match(store, last, batch, on, created)
        hits += h
        if not correlate(store):
            break
    return hits


def _match(store, last: int, batch: int, on: set, created: list | None) -> tuple[int, int]:
    hits = 0
    while True:
        evs = store.events_after(last, batch)
        if not evs:
            break
        with store.db() as c:
            for e in evs:
                enrich.event(c, e)
        for e in sorted(evs, key=lambda x: x["ts"]):    # backfills arrive newest-first; match oldest-first
            for rule in R.ALL:
                if rule["id"] in on and matches(rule, e):
                    new = _hit(store, rule, e)
                    if new:
                        if created is not None:
                            created.append(new)
                        q = store.get("notify_queue", []) or []
                        store.put("notify_queue", (q + [new])[-200:])    # notify.py drains this
                    hits += 1
        last = evs[-1]["id"]
        store.put("engine_last_id", last)
    return hits, last


# Correlation: one entity tripping two or more different rules close together is a story, not two alerts.
CORR_WINDOW = 24 * 3600
CORR_SKIP = ("posture-", "wt-", "corr-")                 # standing findings and our own health are not actions


def correlate(store) -> int:
    """Write one 'Correlated' event per new combination. Returns events written."""
    with store.db() as c:
        rows = [dict(r) for r in c.execute("SELECT id, rule_id, entity, first_seen, last_seen, drill FROM offenses "
                                           "WHERE status='open' ORDER BY entity, first_seen")]
    by = {}
    for o in rows:                                       # a drill only ever correlates with its own offenses
        if not o["rule_id"].startswith(CORR_SKIP) and o["entity"] not in ("", "unknown"):
            by.setdefault((o["drill"], o["entity"]), []).append(o)
    evs = []
    for (drill, ent), offs in by.items():
        for i, a in enumerate(offs):
            near = [b for b in offs if b["rule_id"] != a["rule_id"]
                    and b["first_seen"] <= a["last_seen"] + CORR_WINDOW and a["first_seen"] <= b["last_seen"] + CORR_WINDOW]
            if not near:
                continue
            group = sorted({a["id"], *(b["id"] for b in near)})
            rules = sorted({a["rule_id"], *(b["rule_id"] for b in near)})
            extra = {"offenses": group, "rules": rules, **({"drill": drill} if drill else {})}
            evs.append({"uid": f"wt:corr:{ent}:{'-'.join(map(str, group))}", "ts": max(o["last_seen"] for o in offs if o["id"] in group),
                        "source": "watchtower", "category": "correlation", "action": "Correlated", "outcome": "info",
                        "actor": ent, "target": " + ".join(rules)[:300], "region": "",
                        "extra": extra, "raw_json": json.dumps({"offenses": group, "rules": rules})})
            break                                        # one combination per entity per pass
    return store.add_events(evs) if evs else 0


def _hit(store, rule: dict, e: dict) -> int | None:
    """Returns the new offense id when this hit opened one."""
    entity = str(e.get(rule["group_by"]) or "unknown")
    window = rule.get("window_min", 60) * 60
    threshold = rule.get("threshold", 1)
    with store.db() as c:
        c.execute("INSERT OR IGNORE INTO rule_hits(rule_id,entity,event_id,ts) VALUES(?,?,?,?)",
                  (rule["id"], entity, e["id"], e["ts"]))
        join = max(window, DORMANT)
        near = c.execute("SELECT * FROM offenses WHERE rule_id=? AND entity=? AND status='open' AND ? BETWEEN first_seen-? AND last_seen+? "
                         "ORDER BY id", (rule["id"], entity, e["ts"], join, join)).fetchall()
        if near:
            off = near[0]
            c.execute("INSERT OR IGNORE INTO offense_events(offense_id,event_id) VALUES(?,?)", (off["id"], e["id"]))
            for other in near[1:]:                       # this event bridges two offenses: fold the newer into the older
                c.execute("INSERT OR IGNORE INTO offense_events(offense_id,event_id) SELECT ?, event_id FROM offense_events "
                          "WHERE offense_id=?", (off["id"], other["id"]))
                c.execute("DELETE FROM offense_events WHERE offense_id=?", (other["id"],))
                c.execute("DELETE FROM offenses WHERE id=?", (other["id"],))
            span = c.execute("SELECT MIN(e.ts), MAX(e.ts) FROM events e JOIN offense_events oe ON oe.event_id=e.id "
                             "WHERE oe.offense_id=?", (off["id"],)).fetchone()
            n = c.execute("SELECT COUNT(*) FROM offense_events WHERE offense_id=?", (off["id"],)).fetchone()[0]
            rel = relevance(entity, n)
            c.execute("UPDATE offenses SET event_count=?, first_seen=?, last_seen=?, relevance=?, magnitude=? WHERE id=?",
                      (n, span[0], span[1], rel, magnitude(off["severity"], off["credibility"], rel), off["id"]))
            return
        recent = [r["event_id"] for r in c.execute(
            "SELECT event_id FROM rule_hits WHERE rule_id=? AND entity=? AND ts BETWEEN ? AND ?",
            (rule["id"], entity, e["ts"] - window, e["ts"] + window))]
        if len(recent) < threshold:
            return
        ts = [r["ts"] for r in c.execute(f"SELECT ts FROM events WHERE id IN ({','.join('?' * len(recent))})", recent)]
        rel = relevance(entity, len(recent))
        sev, cred = rule["severity"], rule.get("credibility", 7)
        drill = str(enrich._x(e).get("drill") or "")
        cur = c.execute("INSERT INTO offenses(rule_id,entity,title,severity,credibility,relevance,magnitude,event_count,"
                        "first_seen,last_seen,drill) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (rule["id"], entity, f"{rule['name']}: {entity}", sev, cred, rel, magnitude(sev, cred, rel),
                         len(recent), min(ts), max(ts), drill))
        c.executemany("INSERT OR IGNORE INTO offense_events(offense_id,event_id) VALUES(?,?)",
                      [(cur.lastrowid, i) for i in recent])
        return cur.lastrowid


def posture_keys(found: list[dict], day: str) -> set[tuple[str, str]]:
    """(rule id, entity) for every posture rule the current findings still trip."""
    import normalize
    out = set()
    for f in found:
        e = normalize.finding({**f, "ts": time.time()}, day)
        for rule in R.ALL:
            if rule["id"].startswith("posture-") and matches(rule, e):
                out.add((rule["id"], str(e.get(rule["group_by"]) or "unknown")))
    return out


def resolve_posture(store, found: list[dict], day: str) -> list[int]:
    """2026-11-18 the owner: a posture offense closes on its own once AWS no longer shows the finding (dana added
    MFA, a key was turned off). Only posture-* offenses: event offenses are history and stay until a person
    closes them. Call only after a SUCCESSFUL snapshot, never on an error. Returns the closed ids."""
    still = posture_keys(found, day)
    stamp = time.strftime("%Y-%m-%d %H:%M")
    closed = []
    with store.db() as c:
        for o in c.execute("SELECT id, rule_id, entity, title FROM offenses WHERE status='open' AND rule_id LIKE 'posture-%'").fetchall():
            if (o["rule_id"], o["entity"]) in still:
                continue
            note = f"Resolved: no longer found in AWS ({stamp})"
            c.execute("UPDATE offenses SET status='closed', closed_at=?, note=CASE WHEN COALESCE(note,'')='' THEN ? "
                      "ELSE note || char(10) || ? END WHERE id=?", (time.time(), note, note, o["id"]))
            closed.append(o["id"])
    for oid in closed:
        store.audit("system", "", "auto-closed offense", f"#{oid}: no longer found in AWS")
    return closed
