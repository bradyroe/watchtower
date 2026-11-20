"""Rules the owner writes himself in the rule builder (2026-11-19). Stored in the custom_rules table as JSON
specs, never as code: a spec can only pick from the fields and operators below, so a saved rule cannot run
anything. load() adds them to rules.ALL / rules.BY_ID in place.
"""
from __future__ import annotations

import json
import re
import time

import rules as R
from rules.builtin import _x, matches

SOURCES = ["aws-cloudtrail", "aws-posture", "aws-flowlogs", "windows", "tailscale"]
FIELDS = {"action": "Event name", "actor": "Actor", "src_ip": "Source IP", "target": "Target", "region": "Region / host",
          "category": "Category", "raw": "Anywhere in the raw log", "extra.country": "Country (2 letters)",
          "extra.event_id": "Windows event ID", "extra.mfa_used": "MFA used (Yes/No)"}
GROUP_BY = {"actor": "Actor", "src_ip": "Source IP", "target": "Target", "region": "Region / host"}
OUTCOMES = {"": "Any", "success": "Success", "failure": "Failure"}


def _field(e: dict, f: str) -> str:
    if f == "raw":
        return e.get("raw_json") or ""
    if f.startswith("extra."):
        return str(_x(e).get(f[6:], ""))
    return str(e.get(f) or "")


def validate(form: dict) -> tuple[dict | None, str]:
    """Form fields -> a clean spec, or (None, the problem in plain words)."""
    name = (form.get("name") or "").strip()[:80]
    if len(name) < 3:
        return None, "Give the rule a name (3 characters or more)."
    src = form.get("source") or ""
    if src not in SOURCES:
        return None, "Pick a log source."
    actions = [a.strip() for a in (form.get("actions") or "").split(",") if a.strip()][:30]
    if any(len(a) > 80 for a in actions):
        return None, "Event names are short, like ConsoleLogin."
    field, contains = form.get("field") or "", (form.get("contains") or "").strip()[:200]
    if contains and field not in FIELDS:
        return None, "Pick which field to look in."
    if not actions and not contains:
        return None, "Add at least one event name or a 'contains' condition, or the rule matches everything."

    def num(k, lo, hi, d):
        try:
            return max(lo, min(hi, int(form.get(k) or d)))
        except ValueError:
            return d
    tid = (form.get("mitre") or "").strip().upper()[:12]
    if tid and not re.fullmatch(r"T\d{4}(\.\d{3})?", tid):
        return None, "A MITRE technique id looks like T1110 or T1078.004."
    spec = {"name": name, "why": (form.get("why") or "").strip()[:300] or "Written by you in the rule builder.",
            "source": src, "actions": actions, "outcome": form.get("outcome") if form.get("outcome") in OUTCOMES else "",
            "field": field if contains else "", "contains": contains,
            "group_by": form.get("group_by") if form.get("group_by") in GROUP_BY else "actor",
            "window_min": num("window_min", 1, 7 * 1440, 60), "threshold": num("threshold", 1, 1000, 1),
            "severity": num("severity", 1, 10, 5), "credibility": num("credibility", 1, 10, 5),
            "mitre": tid, "mitre_name": (form.get("mitre_name") or "").strip()[:80]}
    return spec, ""


def build(rid: str, spec: dict) -> dict:
    needle = spec["contains"].lower()
    field = spec["field"]
    return {"id": rid, "name": spec["name"], "severity": spec["severity"], "credibility": spec["credibility"],
            "source": spec["source"], "actions": set(spec["actions"]) or None, "outcome": spec["outcome"] or None,
            "where": (lambda e: needle in _field(e, field).lower()) if needle else None,
            "group_by": spec["group_by"], "window_min": spec["window_min"], "threshold": spec["threshold"],
            "why": spec["why"], "custom": True,
            "mitre": (spec["mitre"], spec["mitre_name"] or ("Your tag" if spec["mitre"] else "Not tagged yet"), "")}


def slug(name: str) -> str:
    return "custom-" + (re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "rule")


def load(store) -> int:
    """Put every saved custom rule into rules.ALL / BY_ID (in place, so every importer sees them)."""
    with store.db() as c:
        rows = [dict(r) for r in c.execute("SELECT id, spec_json FROM custom_rules ORDER BY created")]
    R.ALL[:] = [r for r in R.ALL if not r.get("custom")]
    for row in rows:
        try:
            R.ALL.append(build(row["id"], json.loads(row["spec_json"])))
        except (ValueError, KeyError):
            continue
    R.BY_ID.clear()
    R.BY_ID.update({r["id"]: r for r in R.ALL})
    return len(rows)


def save(store, spec: dict, author: str, rid: str | None = None) -> str:
    rid = rid or slug(spec["name"])
    base, n = rid, 2
    with store.db() as c:
        while rid in R.BY_ID and not R.BY_ID[rid].get("custom"):     # never shadow a built-in rule
            rid, n = f"{base}-{n}", n + 1
        now = time.time()
        c.execute("INSERT INTO custom_rules(id,spec_json,author,created,updated) VALUES(?,?,?,?,?) "
                  "ON CONFLICT(id) DO UPDATE SET spec_json=excluded.spec_json, updated=excluded.updated",
                  (rid, json.dumps(spec), author, now, now))
    load(store)
    return rid


def delete(store, rid: str) -> None:
    with store.db() as c:
        c.execute("DELETE FROM custom_rules WHERE id=?", (rid,))
    load(store)


def test(store, spec: dict, days: int = 7, limit: int = 50000) -> dict:
    """Run a spec over the last `days` of stored events: hits, entities, and how many offenses it would open."""
    rule = build("custom-test", spec)
    since = time.time() - days * 86400
    with store.db() as c:
        evs = [dict(r) for r in c.execute("SELECT * FROM events WHERE source=? AND ts>=? AND uid NOT LIKE 'drill:%' "
                                          "ORDER BY ts LIMIT ?", (spec["source"], since, limit))]
    hits = [e for e in evs if matches(rule, e)]
    by: dict[str, list[float]] = {}
    for e in hits:
        by.setdefault(str(e.get(spec["group_by"]) or "unknown"), []).append(e["ts"])
    win = spec["window_min"] * 60
    would = 0
    for ts in by.values():                               # sliding window: does any window reach the threshold?
        j = 0
        for i in range(len(ts)):
            while ts[i] - ts[j] > win:
                j += 1
            if i - j + 1 >= spec["threshold"]:
                would += 1
                break
    return {"scanned": len(evs), "hits": len(hits), "entities": len(by), "would_open": would,
            "top": sorted(((k, len(v)) for k, v in by.items()), key=lambda x: -x[1])[:8], "sample": hits[-10:][::-1]}
