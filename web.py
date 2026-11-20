"""The console: a stdlib HTTP server, server-rendered pages, a little JS for live mode and charts.

Security: every page but /login, /api/health and /static needs a session. Session cookie is
HttpOnly + SameSite=Strict (+ Secure behind HTTPS). Every POST carries the session's CSRF token.
CSP allows only this origin; no inline script runs. Every UI action is written to the audit log.
"""
from __future__ import annotations

import datetime as dt
import html
import json
import mimetypes
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import auth
import config
import queries as Q
import drills as D
import rules as R
import web_train as T
from rules import custom as RC
from rules.builtin import mitre_url

STATIC = Path(__file__).resolve().parent / "static"
COOKIE = "wt_session"
SRC_LABEL = {"aws-cloudtrail": "AWS CloudTrail", "aws-posture": "AWS posture", "windows": "Windows (this PC)",
             "tailscale": "Tailscale", "aws-flowlogs": "VPC flow logs", "watchtower": "Watchtower health"}
COLLECTOR_LABEL = {"cloudtrail": "AWS CloudTrail", "posture": "AWS posture", "windows": "Windows event logs",
                   "tailscale": "Tailscale", "s3logs": "Log bucket (flow logs)"}
NAV = [("/", "Overview", "overview"), ("/offenses", "Offenses", "offenses"), ("/events", "Log activity", "events"),
       ("/posture", "Posture", "posture"), ("/rules", "Rules", "rules"), ("/audit", "Audit log", "audit"),
       ("/learn", "Learn", "learn"), ("/drills", "Drills", "drills"), ("/analyst", "Analyst log", "analyst")]
EVENT_COLS = [("ts", "Time"), ("source", "Source"), ("category", "Category"), ("action", "Event"),
              ("outcome", "Outcome"), ("actor", "Actor"), ("src_ip", "Source IP"), ("target", "Target"),
              ("region", "Region / host")]

e = html.escape


def fmt_ts(ts, secs=False) -> str:
    if not ts:
        return ""
    return dt.datetime.fromtimestamp(ts).strftime("%b %d %H:%M:%S" if secs else "%b %d %H:%M")


def ago(ts) -> str:
    if not ts:
        return "never"
    s = int(time.time() - ts)
    if s < 90:
        return f"{s}s ago"
    if s < 5400:
        return f"{s // 60}m ago"
    if s < 172800:
        return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


def sev_band(n: int) -> str:
    return "critical" if n >= 9 else "serious" if n >= 7 else "warning" if n >= 4 else "low"


def mag_bar(n: int) -> str:
    band = sev_band(n)
    cells = "".join(f'<i class="{"on" if i < n else ""}"></i>' for i in range(10))
    return f'<span class="mag {band}" title="Magnitude {n} of 10"><span class="cells">{cells}</span><b class="num">{n}</b></span>'


def badge(n: int) -> str:
    band = sev_band(n)
    word = {"critical": "Critical", "serious": "High", "warning": "Medium", "low": "Low"}[band]
    return f'<span class="sev {band}"><i></i>{word} <span class="num">{n}</span></span>'


def status_word(s: str) -> str:
    return f'<span class="state {e(s)}"><i></i>{e(s.capitalize())}</span>'


def num(n) -> str:
    return f"{n:,}"


class App:
    def __init__(self, store):
        self.store = store

    # ------------------------------------------------------------------ range
    @staticmethod
    def time_range(qs: dict, cookies: dict) -> tuple[float, float, str]:
        r = (qs.get("range") or [cookies.get("wt_range") or "24h"])[0]
        now = time.time()
        if r == "custom":
            try:
                start = dt.datetime.fromisoformat(qs["from"][0]).timestamp()
                end = dt.datetime.fromisoformat(qs["to"][0]).timestamp()
                if end > start:
                    return start, end, "custom"
            except (KeyError, ValueError, IndexError):
                pass
            r = "24h"
        if r not in Q.RANGES:
            r = "24h"
        return now - Q.RANGES[r], now, r

    # ------------------------------------------------------------------ shell
    def page(self, h: "Handler", active: str, title: str, body: str, sess: dict, rng: tuple, scripts=("app.js",)) -> str:
        start, end, r = rng
        q = e(h.qs.get("q", [""])[0]) if active == "events" else ""
        nav = "".join(f'<a href="{href}" class="{"on" if key == active else ""}">{_icon(key)}<span>{label}</span>'
                      f'{self._nav_count(key)}</a>' for href, label, key in NAV)
        keep = {k: v[0] for k, v in h.qs.items() if k not in ("range", "from", "to")}
        def rlink(x):
            return "?" + urllib.parse.urlencode({**keep, "range": x})
        ranges = "".join(f'<a href="{rlink(x)}" class="{"on" if x == r else ""}">{x}</a>' for x in Q.RANGES)
        fv = dt.datetime.fromtimestamp(start).strftime("%Y-%m-%dT%H:%M")
        tv = dt.datetime.fromtimestamp(end).strftime("%Y-%m-%dT%H:%M")
        hidden = "".join(f'<input type="hidden" name="{e(k)}" value="{e(v)}">' for k, v in keep.items())
        custom = (f'<details class="custom {"on" if r == "custom" else ""}"><summary>Custom</summary>'
                  f'<form method="get" class="pop">{hidden}<input type="hidden" name="range" value="custom">'
                  f'<label>From<input type="datetime-local" name="from" value="{fv}"></label>'
                  f'<label>To<input type="datetime-local" name="to" value="{tv}"></label>'
                  f'<button class="btn primary">Apply</button></form></details>')
        span = f'{fmt_ts(start)} to {fmt_ts(end)}' if r == "custom" else f"Last {r}"
        js = "".join(f'<script src="/static/{s}" defer></script>' for s in scripts)
        return f"""<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)} | Watchtower</title><link rel="icon" href="/static/icon.svg"><link rel="manifest" href="/static/manifest.webmanifest"><link rel="apple-touch-icon" href="/static/apple-touch-icon.png"><meta name="theme-color" content="#111110"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-title" content="Watchtower"><meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<link rel="stylesheet" href="/static/app.css"><link rel="stylesheet" href="/static/vendor/uPlot.min.css">
<script src="/static/theme.js"></script>
</head><body data-csrf="{e(sess['csrf'])}" data-range="{r}" data-start="{int(start)}" data-end="{int(end)}">
<header class="top">
  <a class="brand" href="/">{_logo()}<span>Watchtower</span></a>
  <form class="search" action="/events" method="get" role="search"><input type="hidden" name="range" value="{r}">
    {_icon('search')}<input name="q" value="{q}" placeholder="Search events: actor, IP, event name, anything in the raw log" aria-label="Search events"></form>
  <div class="range" role="group" aria-label="Time range"><span class="span">{e(span)}</span>{ranges}{custom}</div>
  <button class="icon-btn" id="theme" type="button" aria-label="Switch light or dark theme">{_icon('theme')}</button>
  <form method="post" action="/logout" class="who"><input type="hidden" name="csrf" value="{e(sess['csrf'])}">
    <span>{e(sess['user'])}</span><button class="btn quiet" type="submit">Sign out</button></form>
</header>
<nav class="rail" aria-label="Main">{nav}</nav>
<main id="main">{body}</main>
<div id="drawer" class="drawer" hidden aria-hidden="true"><div class="drawer-head"><b>Raw event</b>
<button class="icon-btn" id="drawer-close" type="button" aria-label="Close">{_icon('close')}</button></div><div class="drawer-body"></div></div>
<script src="/static/vendor/uPlot.iife.min.js" defer></script>{js}
</body></html>"""

    def _nav_count(self, key):
        if key != "offenses":
            return ""
        with self.store.db() as c:
            n = c.execute("SELECT COUNT(*) FROM offenses WHERE status='open' AND drill=''").fetchone()[0]
        return f'<em class="count">{n}</em>' if n else ""

    # ------------------------------------------------------------------ overview
    def overview(self, h, sess, rng) -> str:
        start, end, r = rng
        c = Q.counts(self.store, start, end)
        offs = Q.offenses(self.store, "open")[:8]
        worst = offs[0] if offs else None
        lead = (f'<b>{c["open_offenses"]} open offense{"s" if c["open_offenses"] != 1 else ""}</b>'
                + (f', the highest at magnitude {worst["magnitude"]}: <a href="/offenses/{worst["id"]}">{e(worst["title"])}</a>.' if worst else ".")
                + f' {num(c["total"])} events in this range from {len(c["by_source"])} source{"s" if len(c["by_source"]) != 1 else ""}'
                + (f', {c["new_offenses"]} new offense{"s" if c["new_offenses"] != 1 else ""}.' if c["new_offenses"] else "."))
        ser = Q.series_by_source(self.store, start, end)
        multiples = ""
        for i, src in enumerate(Q.SOURCES):
            ys = ser["series"].get(src)
            total = sum(ys) if ys else 0
            if src == "watchtower" or (src == "aws-flowlogs" and not ys):
                continue
            multiples += (f'<figure class="mini"><figcaption><span>{SRC_LABEL[src]}</span><b class="num">{num(total)}</b></figcaption>'
                          f'<div class="chart" data-kind="bars" data-slot="{i + 1}" data-x=\'{json.dumps(ser["x"])}\' '
                          f'data-y=\'{json.dumps(ys or [0] * len(ser["x"]))}\' data-bucket="{ser["bucket"]}" '
                          f'aria-label="{SRC_LABEL[src]} events over time, {total} total"></div></figure>')
        off_rows = "".join(
            f'<tr data-href="/offenses/{o["id"]}"><td>{mag_bar(o["magnitude"])}</td><td class="num muted">{o["id"]}</td>'
            f'<td><a href="/offenses/{o["id"]}">{e(o["rule"]["name"])}</a></td><td class="mono">{e(o["entity"])}</td>'
            f'<td class="num">{num(o["event_count"])}</td><td class="muted">{ago(o["last_seen"])}</td></tr>' for o in offs) \
            or '<tr><td colspan="6" class="empty">No open offenses. Rules are running on every new event.</td></tr>'

        def ranked(rows, field, label):
            if not rows:
                return f'<p class="empty">No {label.lower()} in this range.</p>'
            mx = max(x["n"] for x in rows) or 1
            body = "".join(
                f'<tr><td class="mono clip-sm" title="{e(str(x["k"]))}"><a href="/events?{urllib.parse.urlencode({field: x["k"], "range": r})}">{e(str(x["k"]))}</a></td>'
                f'<td class="barcell"><span class="hbar" style="--w:{x["n"] / mx:.3f}"></span></td>'
                f'<td class="num">{num(x["n"])}</td><td class="num {"bad" if x["fails"] else "muted"}">{num(x["fails"] or 0)}</td></tr>'
                for x in rows)
            return (f'<table class="grid compact"><thead><tr><th>{label}</th><th class="barcell"></th>'
                    f'<th class="num">Events</th><th class="num">Failed</th></tr></thead><tbody>{body}</tbody></table>')
        actors = ranked(Q.top(self.store, "actor", start, end, where="AND source<>'aws-posture'"), "actor", "Actor")
        ips = ranked(Q.top(self.store, "src_ip", start, end), "src_ip", "Source IP")
        hl = self.health_table()
        return f"""<div class="pagehead"><h1>Overview</h1><p class="lead">{lead}</p></div>
<section class="band"><h2>Events by source</h2><div class="multiples">{multiples}</div></section>
<div class="cols">
 <section class="panel span2"><div class="phead"><h2>Open offenses by magnitude</h2><a href="/offenses" class="more">All offenses</a></div>
 <table class="grid rows"><thead><tr><th>Magnitude</th><th class="num">ID</th><th>Offense</th><th>Offense source</th><th class="num">Events</th><th>Last event</th></tr></thead><tbody>{off_rows}</tbody></table></section>
 <section class="panel"><div class="phead"><h2>Top actors</h2></div>{actors}</section>
 <section class="panel"><div class="phead"><h2>Top source IPs</h2></div>{ips}</section>
 <section class="panel span2"><div class="phead"><h2>Collectors</h2></div>{hl}</section>
</div>"""

    def health_table(self) -> str:
        rows = ""
        hs = {x["name"]: x for x in Q.health(self.store)}
        for name in config.COLLECTORS:
            x = hs.get(name)
            if not x:
                rows += f'<tr><td>{COLLECTOR_LABEL.get(name, name)}</td><td>{status_word("waiting")}</td><td class="muted">never</td><td class="muted">Has not run yet</td></tr>'
                continue
            st = "ok" if x["status"] == "ok" else ("waiting" if "Waiting" in (x["detail"] or "") else "error")
            rows += (f'<tr><td>{COLLECTOR_LABEL.get(name, name)}</td><td>{status_word(st)}</td>'
                     f'<td class="muted">{ago(x["last_ok"])}</td><td class="detail">{e(x["detail"] or "")}</td></tr>')
        return f'<table class="grid compact"><thead><tr><th>Collector</th><th>State</th><th>Last success</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table>'

    # ------------------------------------------------------------------ offenses
    def offenses(self, h, sess, rng) -> str:
        start, end, r = rng
        status = h.qs.get("status", ["open"])[0]
        q = h.qs.get("oq", [""])[0]
        try:
            minm = int(h.qs.get("min", ["0"])[0])
        except ValueError:
            minm = 0
        rows = Q.offenses(self.store, status, q, minm)
        def chip(k, v, label):
            cur = {"status": status, "min": str(minm)}[k]
            args = {"status": status, "min": minm, "oq": q, "range": r, k: v}
            return f'<a class="chip {"on" if str(v) == cur else ""}" href="?{urllib.parse.urlencode(args)}">{label}</a>'
        chips = (chip("status", "open", "Open") + chip("status", "closed", "Closed") + chip("status", "all", "All")
                 + '<span class="sep"></span>' + chip("min", 0, "Any magnitude") + chip("min", 5, "5 and up") + chip("min", 8, "8 and up"))
        body = "".join(
            f'<tr data-href="/offenses/{o["id"]}"><td data-v="{o["magnitude"]}">{mag_bar(o["magnitude"])}</td>'
            f'<td class="num muted" data-v="{o["id"]}">{o["id"]}</td>'
            f'<td><a href="/offenses/{o["id"]}">{e(o["rule"]["name"])}</a>{" <span class=drilltag>DRILL</span>" if o.get("drill") else ""}</td>'
            f'<td class="mono">{e(o["entity"])}</td><td class="num" data-v="{o["event_count"]}">{num(o["event_count"])}</td>'
            f'<td class="muted" data-v="{o["first_seen"]}">{fmt_ts(o["first_seen"])}</td>'
            f'<td class="muted" data-v="{o["last_seen"]}">{fmt_ts(o["last_seen"])}</td>'
            f'<td>{status_word(o["status"])}</td><td class="muted clip">{e(o["assignee"] or "")}{" " if o["assignee"] and o["note"] else ""}{e(o["note"][:60])}</td></tr>'
            for o in rows) or '<tr><td colspan="9" class="empty">Nothing matches these filters.</td></tr>'
        return f"""<div class="pagehead"><h1>Offenses</h1><p class="lead">{len(rows)} shown. An offense groups every event one rule matched for one actor, key, address or device.</p></div>
<div class="toolbar"><div class="chips">{chips}</div>
<form method="get" class="filter"><input type="hidden" name="status" value="{e(status)}"><input type="hidden" name="min" value="{minm}"><input type="hidden" name="range" value="{r}">
<input name="oq" value="{e(q)}" placeholder="Filter by name, source or note" aria-label="Filter offenses"></form></div>
<div class="tablewrap"><table class="grid rows sortable" id="offenses"><thead><tr>
<th data-sort="num">Magnitude</th><th data-sort="num" class="num">ID</th><th data-sort="text">Description</th><th data-sort="text">Offense source</th>
<th data-sort="num" class="num">Events</th><th data-sort="num">First seen</th><th data-sort="num">Last seen</th><th data-sort="text">Status</th><th>Assignee and note</th>
</tr></thead><tbody>{body}</tbody></table></div>"""

    def offense(self, h, sess, rng, oid: int) -> str | None:
        o = Q.offense(self.store, oid)
        if not o:
            return None
        rule = o["rule"]
        bars = "".join(
            f'<div class="factor"><span>{label}</span><span class="track"><span class="fill {sev_band(v) if label == "Severity" else "neutral"}" style="--w:{v / 10:.2f}"></span></span>'
            f'<b class="num">{v}</b><small>{hint}</small></div>'
            for label, v, hint in (("Severity", o["severity"], "How bad it is if real"),
                                   ("Credibility", o["credibility"], "How sure the rule is"),
                                   ("Relevance", o["relevance"], "How important the source is, plus volume")))
        times = sorted(x["ts"] for x in o["events"])
        span = max(3600, (times[-1] - times[0]) if times else 3600)
        b = Q.bucket_for(span * 1.1)
        lo = int((times[0] if times else time.time()) // b) * b - b
        xs = list(range(lo, int((times[-1] if times else time.time()) // b) * b + 2 * b, b))
        ys = [0] * len(xs)
        for t in times:
            i = int((t - lo) // b)
            if 0 <= i < len(ys):
                ys[i] += 1
        evrows = "".join(self.event_row(x) for x in o["events"][:300])
        toggle = "Close offense" if o["status"] == "open" else "Reopen offense"
        return f"""<div class="pagehead offense-head">
<p class="crumb"><a href="/offenses">Offenses</a> / {o["id"]}</p>
<h1>{e(rule["name"])}<span class="ent mono">{e(o["entity"])}</span></h1>
<p class="meta">{status_word(o["status"])}<span>{num(o["event_count"])} event{"s" if o["event_count"] != 1 else ""}</span><span>First {fmt_ts(o["first_seen"], True)}</span><span>Last {fmt_ts(o["last_seen"], True)}</span><span>Rule <code>{e(o["rule_id"])}</code></span></p>
</div>
{T.drill_banner(o)}<div class="cols">
<section class="panel"><div class="phead"><h2>Magnitude {o["magnitude"]} of 10</h2></div>{mag_bar(o["magnitude"])}<div class="factors">{bars}</div></section>
<section class="panel"><div class="phead"><h2>Why this rule fired</h2></div><p class="why">{e(rule.get("why", ""))}</p>
<dl class="kv"><dt>Groups by</dt><dd>{e(rule.get("group_by", ""))}</dd><dt>Window</dt><dd>{_mins(rule.get("window_min", 0))}</dd>
<dt>Threshold</dt><dd>{rule.get("threshold", 1)} event{"s" if rule.get("threshold", 1) != 1 else ""}</dd><dt>MITRE ATT&amp;CK</dt><dd>{mitre_tag(rule, True)}</dd><dt>Source</dt><dd>{SRC_LABEL.get(rule.get("source", ""), rule.get("source", ""))}</dd></dl></section>
<section class="panel"><div class="phead"><h2>Triage</h2></div>
<form method="post" action="/offenses/{o["id"]}" class="triage"><input type="hidden" name="csrf" value="{e(sess['csrf'])}">
<label>Assignee<input name="assignee" value="{e(o["assignee"])}" maxlength="60"></label>
<label>Verdict<select name="verdict"><option value="">Not decided yet</option>{"".join(f'<option value="{k}" {"selected" if o.get("verdict") == k else ""}>{e(lbl)}</option>' for k, lbl in D.VERDICTS)}</select></label>
<label>Note<textarea name="note" rows="4" maxlength="2000" placeholder="What you checked, what you found, what you did or would do">{e(o["note"])}</textarea></label>
<div class="row"><button class="btn secondary" name="op" value="save">Save</button><button class="btn {"primary" if o["status"] == "open" else "secondary"}" name="op" value="toggle">{toggle}</button></div></form></section>
<section class="panel span3"><div class="phead"><h2>Event timeline</h2><span class="muted">{_mins(b // 60)} buckets</span></div>
<div class="chart tall" data-kind="bars" data-slot="1" data-x='{json.dumps(xs)}' data-y='{json.dumps(ys)}' data-bucket="{b}" aria-label="Events in this offense over time"></div></section>
</div>
<section class="band"><div class="phead"><h2>Events in this offense</h2><span class="muted">Select a row for the raw log</span></div>
{self.event_table(evrows)}</section>"""

    # ------------------------------------------------------------------ events
    def event_row(self, x: dict) -> str:
        cells = {"ts": f'<td class="mono nowrap" data-v="{x["ts"]}">{fmt_ts(x["ts"], True)}</td>',
                 "source": f'<td class="nowrap">{SRC_LABEL.get(x["source"], x["source"])}</td>',
                 "category": f'<td>{e(x["category"])}</td>', "action": f'<td class="strong">{e(x["action"])}</td>',
                 "outcome": f'<td><span class="out {e(x["outcome"])}">{e(x["outcome"])}</span></td>',
                 "actor": f'<td class="mono clip">{e(x["actor"])}</td>', "src_ip": f'<td class="mono nowrap">{e(x["src_ip"])}</td>',
                 "target": f'<td class="mono clip">{e(x["target"])}</td>', "region": f'<td class="muted nowrap">{e(x["region"])}</td>'}
        return f'<tr data-id="{x["id"]}" tabindex="0">' + "".join(cells[k].replace("<td", f'<td data-col="{k}"', 1) for k, _ in EVENT_COLS) + "</tr>"

    def event_table(self, rows: str, tid="events") -> str:
        head = "".join(f'<th data-col="{k}">{label}</th>' for k, label in EVENT_COLS)
        return (f'<div class="tablewrap"><table class="grid rows events" id="{tid}"><thead><tr>{head}</tr></thead>'
                f'<tbody>{rows or "<tr><td colspan=9 class=empty>No events match.</td></tr>"}</tbody></table></div>')

    def events(self, h, sess, rng) -> str:
        start, end, r = rng
        f = {k: h.qs.get(k, [""])[0].strip() for k in ("source", "outcome", "category", "actor", "src_ip", "action", "target", "q")}
        before = h.qs.get("before", [None])[0]
        rows = Q.search_events(self.store, f, start, end, before_id=int(before) if before and before.isdigit() else None)
        active = "".join(
            f'<a class="chip on removable" href="?{urllib.parse.urlencode({**{k2: v2 for k2, v2 in f.items() if v2 and k2 != k}, "range": r})}" '
            f'title="Remove filter">{e({"src_ip": "IP", "q": "Text"}.get(k, k.capitalize()))}: {e(SRC_LABEL.get(v, v))}<span aria-hidden="true">x</span></a>'
            for k, v in f.items() if v)
        srcs = "".join(f'<option value="{s}" {"selected" if f["source"] == s else ""}>{SRC_LABEL[s]}</option>' for s in Q.SOURCES)
        outs = "".join(f'<option value="{s}" {"selected" if f["outcome"] == s else ""}>{s}</option>' for s in ("success", "failure", "warning", "info"))
        more = ""
        if len(rows) == 200:
            more = f'<a class="btn secondary" href="?{urllib.parse.urlencode({**{k: v for k, v in f.items() if v}, "range": r, "before": rows[-1]["id"]})}">Older events</a>'
        cols = "".join(f'<label><input type="checkbox" data-colpick="{k}" checked> {label}</label>' for k, label in EVENT_COLS)
        newest = rows[0]["id"] if rows and not before else 0
        return f"""<div class="pagehead"><h1>Log activity</h1><p class="lead">{len(rows)}{"+" if len(rows) == 200 else ""} events, newest first. Select a row to read the raw log.</p></div>
<div class="toolbar">
<form method="get" class="filters"><input type="hidden" name="range" value="{r}"><input type="hidden" name="q" value="{e(f["q"])}">
<select name="source" aria-label="Source"><option value="">All sources</option>{srcs}</select>
<select name="outcome" aria-label="Outcome"><option value="">Any outcome</option>{outs}</select>
<input name="actor" value="{e(f["actor"])}" placeholder="Actor" aria-label="Actor">
<input name="src_ip" value="{e(f["src_ip"])}" placeholder="Source IP" aria-label="Source IP">
<input name="action" value="{e(f["action"])}" placeholder="Event name" aria-label="Event name">
<button class="btn secondary">Filter</button></form>
<div class="tools"><button class="btn secondary" id="live" type="button" data-after="{newest}" aria-pressed="false">{_icon('play')}<span>Live</span></button>
<details class="colpick"><summary class="btn secondary">Columns</summary><div class="pop">{cols}</div></details></div>
</div>
<div class="chips">{active}</div><p class="sr" aria-live="polite" id="live-status"></p>
{self.event_table("".join(self.event_row(x) for x in rows))}
<div class="pager">{more}</div>"""

    # ------------------------------------------------------------------ posture / rules / audit
    def posture(self, h, sess, rng) -> str:
        fs = Q.findings(self.store)
        hs = {x["name"]: x for x in Q.health(self.store)}.get("posture")
        when = f'Checked {ago(hs["last_ok"])}.' if hs and hs.get("last_ok") else "Not checked yet."
        rows = "".join(
            f'<tr><td data-v="{x["severity"]}">{badge(x["severity"])}</td><td class="strong">{e(x["title"])}</td>'
            f'<td class="mono">{e(x["entity"])}</td><td class="detail">{e(x["detail"])}</td><td class="muted">{fmt_ts(x["first_seen"])}</td></tr>'
            for x in fs) or '<tr><td colspan="5" class="empty">No findings. Every check passed.</td></tr>'
        crit = sum(1 for x in fs if x["severity"] >= 7)
        return f"""<div class="pagehead"><h1>Posture</h1><p class="lead"><b>{len(fs)} finding{"s" if len(fs) != 1 else ""}</b>, {crit} rated high or critical. {when} The AWS account is read with a read-only role every 6 hours.</p></div>
<table class="grid rows sortable"><thead><tr><th data-sort="num">Severity</th><th data-sort="text">Finding</th><th data-sort="text">Entity</th><th>Detail</th><th>First seen</th></tr></thead><tbody>{rows}</tbody></table>"""

    def rules_page(self, h, sess, rng) -> str:
        start, end, r = rng
        st = Q.rule_stats(self.store, start, end)
        rows = ""
        for x in R.ALL:
            on = x["id"] not in st["disabled"]
            rows += (f'<tr class="{"" if on else "off"}"><td><form method="post" action="/rules/{x["id"]}"><input type="hidden" name="csrf" value="{e(sess["csrf"])}">'
                     f'<button class="switch" role="switch" aria-checked="{"true" if on else "false"}" aria-label="{e(x["name"])} {"on" if on else "off"}"><i></i></button></form></td>'
                     f'<td class="strong">{e(x["name"])}{" <span class=drilltag>YOURS</span>" if x.get("custom") else ""}<div class="sub mono">{e(x["id"])}</div></td><td data-v="{x["severity"]}">{badge(x["severity"])}</td>'
                     f'<td>{SRC_LABEL.get(x["source"], x["source"])}</td><td class="muted">{_mins(x.get("window_min", 0))}</td>'
                     f'<td class="num">{x.get("threshold", 1)}</td><td class="num">{num(st["hits"].get(x["id"], 0))}</td>'
                     f'<td class="num">{num(st["offenses"].get(x["id"], 0))}</td><td>{mitre_tag(x)}</td><td class="detail">{e(x.get("why", ""))}</td></tr>')
        return f"""<div class="pagehead"><div class="row between"><h1>Rules</h1><a class="btn primary" href="/rules/new">Write a rule</a></div><p class="lead">{len(R.ALL)} rules, {len(R.ALL) - len(st["disabled"])} on. A rule that is off stops matching new events; its open offenses stay.</p></div>
<table class="grid rows sortable"><thead><tr><th>On</th><th data-sort="text">Rule</th><th data-sort="num">Severity</th><th data-sort="text">Source</th><th>Window</th>
<th class="num">Threshold</th><th class="num" data-sort="num">Hits in range</th><th class="num" data-sort="num">Open offenses</th><th data-sort="text">MITRE ATT&amp;CK</th><th>What it means</th></tr></thead><tbody>{rows}</tbody></table>"""

    def audit_page(self, h, sess, rng) -> str:
        rows = "".join(f'<tr><td class="mono nowrap">{fmt_ts(x["ts"], True)}</td><td>{e(x["user"])}</td><td class="mono">{e(x["ip"])}</td>'
                       f'<td class="strong">{e(x["action"])}</td><td class="detail">{e(x["detail"])}</td></tr>' for x in Q.audit(self.store))
        return f"""<div class="pagehead"><h1>Audit log</h1><p class="lead">Every sign-in and every change made in this console.</p></div>
<table class="grid rows"><thead><tr><th>Time</th><th>User</th><th>From</th><th>Action</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table>"""

    def login_page(self, msg="") -> str:
        return f"""<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in | Watchtower</title><link rel="icon" href="/static/icon.svg"><link rel="manifest" href="/static/manifest.webmanifest"><link rel="apple-touch-icon" href="/static/apple-touch-icon.png"><meta name="theme-color" content="#111110"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-title" content="Watchtower"><meta name="apple-mobile-web-app-status-bar-style" content="black-translucent"><link rel="stylesheet" href="/static/app.css"><script src="/static/theme.js"></script></head>
<body class="login"><main><form method="post" action="/login" class="signin">{_logo()}<h1>Watchtower</h1>
<p class="muted">Security monitoring for an AWS account.</p>
{f'<p class="error" role="alert">{e(msg)}</p>' if msg else ""}
<label>User<input name="user" autocomplete="username" required value="admin"></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required autofocus></label>
<button class="btn primary">Sign in</button></form></main></body></html>"""


def mitre_tag(rule: dict, long: bool = False) -> str:
    """Technique id linked to attack.mitre.org, its name, and (long form) the tactic."""
    tid, name, tactic = (rule.get("mitre") or ("", "", ""))
    if not tid:
        return f'<span class="muted">{e(name)}</span>' if name else ""
    link = f'<a class="mitre mono" href="{mitre_url(tid)}" target="_blank" rel="noopener noreferrer">{e(tid)}</a>'
    return f'{link} {e(name)}' + (f'<div class="sub">Tactic: {e(tactic)}</div>' if long and tactic else
                                  (f'<div class="sub">{e(tactic)}</div>' if tactic else ""))


def _mins(m) -> str:
    m = int(m or 0)
    if m >= 1440:
        return f"{m // 1440} day{'s' if m >= 2880 else ''}"
    if m >= 60:
        return f"{m // 60} h"
    return f"{m} min"


ICONS = {
    "overview": '<path d="M3 13h4v8H3zM10 8h4v13h-4zM17 3h4v18h-4z"/>',
    "offenses": '<path d="M12 3 2 20h20L12 3zm0 6v5m0 3v.5"/>',
    "events": '<path d="M4 6h16M4 12h16M4 18h10"/>',
    "posture": '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6l-8-3z"/>',
    "rules": '<path d="M5 7h9M5 17h5M17 4v6M14 7h6M13 14v6M10 17h6"/>',
    "audit": '<path d="M7 3h8l4 4v14H7zM10 11h6M10 15h6"/>',
    "search": '<circle cx="11" cy="11" r="6"/><path d="m20 20-4.5-4.5"/>',
    "theme": '<circle cx="12" cy="12" r="7"/><path d="M12 5a7 7 0 0 1 0 14z" fill="currentColor"/>',
    "close": '<path d="M6 6l12 12M18 6 6 18"/>',
    "play": '<path d="M8 5v14l11-7z"/>',
    "learn": '<path d="M3 7l9-4 9 4-9 4-9-4zM7 9v5c0 2 2.5 3.5 5 3.5s5-1.5 5-3.5V9M21 7v6"/>',
    "drills": '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r=".8" fill="currentColor"/>',
    "analyst": '<path d="M5 4h11l3 3v13H5zM8 10h8M8 14h8M8 18h5"/>',
}


def _icon(k: str) -> str:
    return (f'<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" '
            f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{ICONS.get(k, "")}</svg>')


def _logo() -> str:
    return ('<svg class="logo" viewBox="0 0 32 32" aria-hidden="true"><path d="M21 10.5 30 6v11l-9-4.5z" fill="currentColor" opacity=".38"/>'
            '<path d="M9 10l7-5 7 5zM10.5 10h11v4h-11z" fill="currentColor"/><rect x="13.5" y="11" width="5" height="2" fill="var(--surface)"/>'
            '<path d="M12 14 9 27M20 14l3 13" stroke="currentColor" stroke-width="2.2"/>'
            '<path d="M11 18.5 21 23.5M21 18.5 11 23.5" stroke="currentColor" stroke-width="1.4"/>'
            '<rect x="7" y="27" width="18" height="1.6" fill="currentColor"/></svg>')


# ====================================================================== HTTP
class Handler(BaseHTTPRequestHandler):
    app: App = None
    server_version = "Watchtower"
    sys_version = ""

    def log_message(self, fmt, *args):     # quiet; the audit log records what matters
        pass

    @property
    def ip(self) -> str:
        return self.client_address[0]

    def cookies(self) -> dict:
        out = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                out[k] = v
        return out

    def send(self, code: int, body: bytes | str, ctype="text/html; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                         "script-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
        if ctype.startswith("text/html") or ctype.startswith("application/json"):
            self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            if isinstance(v, list):
                for vv in v:
                    self.send_header(k, vv)
            else:
                self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def redirect(self, to: str, headers=None):
        self.send(303, b"", headers={"Location": to, **(headers or {})})

    def cookie(self, name, value, max_age=None) -> str:
        c = f"{name}={value}; Path=/; HttpOnly; SameSite=Strict"
        if config.SECURE_COOKIE:
            c += "; Secure"
        if max_age is not None:
            c += f"; Max-Age={max_age}"
        return c

    def parse(self):
        u = urllib.parse.urlsplit(self.path)
        self.route, self.qs = u.path, urllib.parse.parse_qs(u.query)

    def form(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n > 64 * 1024:
            return {}
        data = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
        return {k: v[0] for k, v in data.items()}

    def session(self):
        return auth.session(self.app.store, self.cookies().get(COOKIE))

    # ---------------------------------------------------------------- GET
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self.parse()
        a = self.app
        if self.route == "/api/health":
            return self.send(200, b'{"ok":true}', "application/json")
        if self.route.startswith("/static/"):
            return self.static()
        if self.route == "/login":
            return self.send(200, a.login_page())
        sess = self.session()
        if not sess:
            if self.route.startswith("/api/"):
                return self.send(401, b'{"error":"sign in"}', "application/json")
            return self.redirect("/login")
        rng = a.time_range(self.qs, self.cookies())
        set_range = {"Set-Cookie": self.cookie("wt_range", rng[2], 30 * 86400)} if "range" in self.qs and rng[2] != "custom" else {}
        if self.route == "/api/events":
            after = int(self.qs.get("after", ["0"])[0] or 0)
            f = {k: self.qs.get(k, [""])[0] for k in ("source", "outcome", "category", "actor", "src_ip", "action", "target", "q")}
            rows = Q.search_events(a.store, f, 0, time.time() + 60, after_id=after, limit=200)
            return self.send(200, json.dumps({"html": "".join(a.event_row(x) for x in rows),
                                              "newest": rows[0]["id"] if rows else after, "n": len(rows)}), "application/json")
        m = re.fullmatch(r"/api/event/(\d+)", self.route)
        if m:
            ev = Q.event(a.store, int(m.group(1)))
            return self.send(200 if ev else 404, json.dumps(ev or {"error": "not found"}, default=str), "application/json")
        pages = {"/": ("overview", "Overview", a.overview), "/offenses": ("offenses", "Offenses", a.offenses),
                 "/events": ("events", "Log activity", a.events), "/posture": ("posture", "Posture", a.posture),
                 "/rules": ("rules", "Rules", a.rules_page), "/audit": ("audit", "Audit log", a.audit_page),
                 "/learn": ("learn", "Learn", lambda *x: T.learn_page(a, *x)),
                 "/drills": ("drills", "Drills", lambda *x: T.drills_page(a, *x)),
                 "/analyst": ("analyst", "Analyst log", lambda *x: T.analyst_page(a, *x)),
                 "/rules/new": ("rules", "Rule builder", lambda *x: T.builder_page(a, *x))}
        if self.route in pages:
            key, title, fn = pages[self.route]
            return self.send(200, a.page(self, key, title, fn(self, sess, rng), sess, rng), headers=set_range)
        m = re.fullmatch(r"/learn/([a-z0-9-]+)", self.route)
        if m:
            body = T.lesson_page(a, self, sess, rng, m.group(1))
            if body:
                return self.send(200, a.page(self, "learn", "Learn", body, sess, rng))
        m = re.fullmatch(r"/offenses/(\d+)", self.route)
        if m:
            body = a.offense(self, sess, rng, int(m.group(1)))
            if body is None:
                return self.send(404, a.page(self, "offenses", "Not found", '<div class="pagehead"><h1>No such offense</h1></div>', sess, rng))
            return self.send(200, a.page(self, "offenses", f"Offense {m.group(1)}", body, sess, rng))
        return self.send(404, a.page(self, "", "Not found", '<div class="pagehead"><h1>Page not found</h1></div>', sess, rng))

    def static(self):
        rel = self.route[len("/static/"):]
        p = (STATIC / rel).resolve()
        if not str(p).startswith(str(STATIC)) or not p.is_file():
            return self.send(404, b"not found", "text/plain")
        ctype = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
        if p.suffix == ".woff2":
            ctype = "font/woff2"
        if p.suffix == ".webmanifest":
            ctype = "application/manifest+json"
        if p.suffix == ".js":
            ctype = "text/javascript; charset=utf-8"
        return self.send(200, p.read_bytes(), ctype, headers={"Cache-Control": "max-age=300"})

    # ---------------------------------------------------------------- POST
    def do_POST(self):
        self.parse()
        a = self.app
        f = self.form()
        if self.route == "/login":
            user = (f.get("user") or "").strip()[:60]
            got = auth.login(a.store, user, f.get("password") or "", self.ip)
            if not got:
                msg = "Too many failed attempts. Try again in 15 minutes." if auth.locked(a.store, self.ip) else "Wrong user or password."
                a.store.audit(user or "?", self.ip, "sign-in failed")
                return self.send(401, a.login_page(msg))
            a.store.audit(user, self.ip, "signed in")
            return self.redirect("/", {"Set-Cookie": self.cookie(COOKIE, got[0], config.SESSION_HOURS * 3600)})
        sess = self.session()
        if not sess:
            return self.redirect("/login")
        if not f.get("csrf") or f.get("csrf") != sess["csrf"]:
            a.store.audit(sess["user"], self.ip, "blocked request", f"bad CSRF token on {self.route}")
            return self.send(403, b"Request blocked: the form token did not match. Reload the page and try again.", "text/plain; charset=utf-8")
        if self.route == "/logout":
            auth.logout(a.store, self.cookies().get(COOKIE))
            a.store.audit(sess["user"], self.ip, "signed out")
            return self.redirect("/login", {"Set-Cookie": self.cookie(COOKIE, "", 0)})
        m = re.fullmatch(r"/offenses/(\d+)", self.route)
        if m:
            oid = int(m.group(1))
            with a.store.db() as c:
                o = c.execute("SELECT status FROM offenses WHERE id=?", (oid,)).fetchone()
                if not o:
                    return self.send(404, b"not found", "text/plain")
                verdict = f.get("verdict", "") if f.get("verdict", "") in dict(D.VERDICTS) else ""
                c.execute("UPDATE offenses SET assignee=?, note=?, verdict=? WHERE id=?",
                          (f.get("assignee", "")[:60], f.get("note", "")[:2000], verdict, oid))
                detail = "saved assignee, verdict and note"
                new = o["status"]
                if f.get("op") == "toggle":
                    new = "closed" if o["status"] == "open" else "open"
                    c.execute("UPDATE offenses SET status=?, closed_at=? WHERE id=?", (new, time.time() if new == "closed" else None, oid))
                    if new == "open":
                        c.execute("UPDATE offenses SET grade_json='' WHERE id=?", (oid,))
                    detail = f"{'closed' if new == 'closed' else 'reopened'} offense" + (f" as {verdict}" if verdict and new == "closed" else "")
            if f.get("op") == "toggle" and new == "closed":
                T.grade_on_close(a, oid)
            a.store.audit(sess["user"], self.ip, f"offense {oid}", detail)
            return self.redirect(f"/offenses/{oid}")
        m = re.fullmatch(r"/learn/([a-z0-9-]+)/done", self.route)
        if m:
            T.lesson_done(a, m.group(1))
            return self.redirect(f"/learn/{m.group(1)}")
        m = re.fullmatch(r"/drills/start/([a-z0-9-]+)", self.route)
        if m and m.group(1) in D.BY_ID:
            oid = D.start(a.store, m.group(1))
            a.store.audit(sess["user"], self.ip, "drill started", D.BY_ID[m.group(1)]["title"])
            return self.redirect(f"/offenses/{oid}" if oid else "/drills")
        if self.route == "/drills/clear":
            n = D.clear(a.store)
            a.store.audit(sess["user"], self.ip, "drill data removed", f"{n} offenses")
            return self.redirect("/drills")
        if self.route in ("/rules-custom/test", "/rules-custom/save"):
            self.qs = {}
            rng = a.time_range({}, self.cookies())
            spec, msg = RC.validate(f)
            if not spec:
                return self.send(400, a.page(self, "rules", "Rule builder", T.builder_page(a, self, sess, rng, f, None, msg), sess, rng))
            if self.route.endswith("/test"):
                res = RC.test(a.store, spec)
                return self.send(200, a.page(self, "rules", "Rule builder", T.builder_page(a, self, sess, rng, f, res), sess, rng))
            rid = RC.save(a.store, spec, sess["user"])
            a.store.audit(sess["user"], self.ip, f"rule {rid}", "saved a custom rule")
            return self.redirect("/rules")
        m = re.fullmatch(r"/rules-custom/([a-z0-9-]+)/delete", self.route)
        if m and R.BY_ID.get(m.group(1), {}).get("custom"):
            RC.delete(a.store, m.group(1))
            a.store.audit(sess["user"], self.ip, f"rule {m.group(1)}", "deleted a custom rule")
            return self.redirect("/rules/new")
        m = re.fullmatch(r"/rules/([a-z0-9-]+)", self.route)
        if m and m.group(1) in R.BY_ID:
            rid = m.group(1)
            st = Q.rule_stats(a.store, 0, 0)
            on = rid in st["disabled"]                # flip
            with a.store.db() as c:
                c.execute("INSERT INTO rule_state(rule_id,enabled) VALUES(?,?) ON CONFLICT(rule_id) DO UPDATE SET enabled=excluded.enabled",
                          (rid, 1 if on else 0))
            a.store.audit(sess["user"], self.ip, f"rule {rid}", "turned on" if on else "turned off")
            return self.redirect("/rules")
        return self.send(404, b"not found", "text/plain")


def serve(store, binds=None, port=None) -> list[ThreadingHTTPServer]:
    RC.load(store)                                  # the rules the owner wrote in the rule builder
    Handler.app = App(store)
    servers = []
    for host in binds or config.BIND:
        try:
            s = ThreadingHTTPServer((host, port or config.PORT), Handler)
        except OSError:
            continue                                # e.g. Tailscale not up yet
        s.daemon_threads = True
        threading.Thread(target=s.serve_forever, daemon=True, name=f"http-{host}").start()
        servers.append(s)
    return servers
