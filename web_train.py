"""Training pages (2026-11-19): Learn, Drills, Analyst log, and the rule builder. web.py routes here.

Everything that comes from the database or a form is escaped; lesson bodies are trusted static HTML from
learn.py. Every POST goes through web.py's CSRF check before it reaches these handlers.
"""
from __future__ import annotations

import json
import time

import drills as D
import rules as R
from rules import custom as C


def _w():
    import web
    return web


def _csrf(sess) -> str:
    return f'<input type="hidden" name="csrf" value="{_w().e(sess["csrf"])}">'


def _dur(s: float) -> str:
    s = int(s or 0)
    if s < 3600:
        return f"{max(1, s // 60)} min"
    if s < 172800:
        return f"{s / 3600:.1f} h"
    return f"{s / 86400:.1f} days"


# ---------------------------------------------------------------------------------------------- Learn
def _lessons() -> list[dict]:
    try:
        import learn
        return list(learn.LESSONS)
    except Exception:                                    # noqa: BLE001
        return []


def learn_page(app, h, sess, rng) -> str:
    w = _w()
    done = set(app.store.get("lessons_done", []) or [])
    ls = _lessons()
    items = "".join(
        f'<li class="lesson {"done" if x["id"] in done else ""}"><a href="/learn/{w.e(x["id"])}">'
        f'<span class="n num">{i + 1}</span><span class="t">{w.e(x["title"])}</span>'
        f'<span class="muted">{x.get("minutes", 5)} min{" · done" if x["id"] in done else ""}</span></a></li>'
        for i, x in enumerate(ls)) or '<li class="empty">Lessons are on their way.</li>'
    return f"""<div class="pagehead"><h1>Learn</h1><p class="lead">Short lessons on working as a SOC analyst and detection
engineer, using this console and your own data. {len(done & {x["id"] for x in ls})} of {len(ls)} done.</p></div>
<div class="cols train"><section class="panel span2"><div class="phead"><h2>Lessons</h2></div><ol class="lessons">{items}</ol></section>
<section class="panel"><div class="phead"><h2>How to practise</h2></div><ol class="steps">
<li>Read a lesson.</li><li>Run a <a href="/drills">drill</a> and triage it like a real alert.</li>
<li>Close it with a verdict and a note. You get a score and what a pro would have checked.</li>
<li>Write your own detection in the <a href="/rules/new">rule builder</a>.</li>
<li>Your <a href="/analyst">analyst log</a> keeps the record for interviews.</li></ol></section></div>"""


def lesson_page(app, h, sess, rng, lid: str) -> str | None:
    w = _w()
    ls = _lessons()
    idx = next((i for i, x in enumerate(ls) if x["id"] == lid), None)
    if idx is None:
        return None
    x = ls[idx]
    done = lid in set(app.store.get("lessons_done", []) or [])
    tries = "".join(f'<a class="btn secondary" href="{w.e(href)}">{w.e(label)}</a>' for label, href in x.get("try", []))
    checks = "".join(f'<details class="check"><summary>{w.e(q)}</summary><p>{w.e(a)}</p></details>' for q, a in x.get("check", []))
    nxt = (f'<a class="btn secondary" href="/learn/{w.e(ls[idx + 1]["id"])}">Next: {w.e(ls[idx + 1]["title"])}</a>'
           if idx + 1 < len(ls) else '<a class="btn secondary" href="/drills">Go run a drill</a>')
    mark = (f'<form method="post" action="/learn/{w.e(lid)}/done">{_csrf(sess)}<button class="btn {"secondary" if done else "primary"}">'
            f'{"Done ✓" if done else "Mark as done"}</button></form>')
    return f"""<div class="pagehead"><p class="crumb"><a href="/learn">Learn</a> / Lesson {idx + 1}</p><h1>{w.e(x["title"])}</h1>
<p class="lead">{x.get("minutes", 5)} minute read</p></div>
<article class="panel lesson-body">{x["body"]}</article>
{f'<section class="panel"><div class="phead"><h2>Check yourself</h2><span class="muted">Tap a question for the answer</span></div>{checks}</section>' if checks else ""}
{f'<div class="row tryit"><span class="muted">Try it:</span>{tries}</div>' if tries else ""}
<div class="row lesson-nav">{mark}{nxt}</div>"""


def lesson_done(app, lid: str) -> None:
    done = list(app.store.get("lessons_done", []) or [])
    if lid in {x["id"] for x in _lessons()}:
        if lid in done:
            done.remove(lid)
        else:
            done.append(lid)
        app.store.put("lessons_done", done)


# ---------------------------------------------------------------------------------------------- Drills
def drills_page(app, h, sess, rng) -> str:
    w = _w()
    with app.store.db() as c:
        active = [dict(r) for r in c.execute("SELECT id, rule_id, entity, magnitude, status, drill, grade_json FROM offenses "
                                             "WHERE drill<>'' ORDER BY id DESC")]
    hist = list(reversed(app.store.get(D.RESULTS, []) or []))
    best = {}
    for r in hist:
        best[r["drill"].split(":")[0]] = max(best.get(r["drill"].split(":")[0], 0), r["score"])
    cards = "".join(
        f'<article class="drill"><div class="lvl muted">{w.e(s["level"])}</div><h3>{w.e(s["title"])}</h3><p>{w.e(s["brief"])}</p>'
        f'<form method="post" action="/drills/start/{w.e(s["id"])}">{_csrf(sess)}<button class="btn primary">Start drill</button>'
        f'{f"<span class=muted>Best score {best[s["id"]]}</span>" if s["id"] in best else ""}</form></article>'
        for s in D.SCENARIOS)
    main = {}
    for o in active:
        sc = D.scenario_of(o["drill"])
        if sc and o["rule_id"] == sc["primary"]:
            main[o["drill"]] = o
    act = "".join(
        f'<tr data-href="/offenses/{o["id"]}"><td><a href="/offenses/{o["id"]}">{w.e(D.scenario_of(d)["title"])}</a></td>'
        f'<td>{w.status_word(o["status"])}</td>'
        f'<td class="num">{json.loads(o["grade_json"])["score"] if o["grade_json"] else "-"}</td></tr>'
        for d, o in main.items()) or '<tr><td colspan="3" class="empty">No drill running. Start one above.</td></tr>'
    clear = (f'<form method="post" action="/drills/clear">{_csrf(sess)}<button class="btn secondary">Remove drill data</button></form>'
             if active else "")
    return f"""<div class="pagehead"><h1>Drills</h1><p class="lead">Practice on fake attacks that behave like real ones. A drill
writes made-up events into Watchtower, the normal rules raise offenses, and you triage them exactly as you would for real.
Drills never ping Discord and never mix with real offenses.</p></div>
<div class="drills">{cards}</div>
<section class="band"><div class="phead"><h2>Your drills</h2>{clear}</div>
<p class="muted">Open the drill's offense, investigate (events, raw logs, Log activity search), then pick a verdict, write what you
found and what you would do in the note, and close it. You get graded the moment you close.</p>
<table class="grid rows"><thead><tr><th>Drill</th><th>Status</th><th class="num">Score</th></tr></thead><tbody>{act}</tbody></table></section>"""


def drill_banner(o: dict) -> str:
    w = _w()
    sc = D.scenario_of(o.get("drill"))
    if not sc:
        return ""
    if o.get("grade_json"):
        g = json.loads(o["grade_json"])
        facts = "".join(f'<li class="{"hit" if hit else "miss"}">{"✓" if hit else "✗"} {w.e(label)}</li>' for label, hit in g["facts"])
        pro = "".join(f"<li>{w.e(p)}</li>" for p in g["pro"])
        exp = dict(D.VERDICTS).get(g["expected"], g["expected"])
        return f"""<section class="panel drill-result"><div class="phead"><h2>Drill result: {g["score"]} / 100</h2></div>
<p><b>Your verdict:</b> {w.e(dict(D.VERDICTS).get(g["verdict"], g["verdict"] or "none"))} {"✓" if g["verdict_ok"] else f"(expected: {w.e(exp)})"}</p>
<p>{w.e(g["explain"])}</p><div class="cols"><div><h3>What your note covered</h3><ul class="facts">{facts}</ul></div>
<div><h3>What a pro would check</h3><ul>{pro}</ul></div></div>
<p class="muted">Reopen the offense to try again; the next close is graded again.</p></section>"""
    main = "" if o["rule_id"] == sc["primary"] else " This offense is part of the drill; the main one is graded."
    return (f'<section class="panel drill-banner"><b>DRILL:</b> {w.e(sc["title"])}. {w.e(sc["brief"])} Fake data.{w.e(main)} '
            f'Pick a verdict, write what you found and what you would do, then close it.</section>')


def grade_on_close(app, oid: int) -> None:
    with app.store.db() as c:
        o = c.execute("SELECT id, rule_id, drill, verdict, note FROM offenses WHERE id=?", (oid,)).fetchone()
    sc = D.scenario_of(o["drill"]) if o else None
    if not sc or o["rule_id"] != sc["primary"]:
        return
    D.record(app.store, oid, o["drill"], D.grade(sc, o["verdict"], o["note"]))


# ---------------------------------------------------------------------------------------------- Analyst log
def analyst_page(app, h, sess, rng) -> str:
    w = _w()
    with app.store.db() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM offenses WHERE status='closed' AND drill='' ORDER BY closed_at DESC LIMIT 300")]
    mine = [o for o in rows if not (o["note"] or "").startswith("Resolved:")]
    counts = {k: sum(1 for o in mine if o["verdict"] == k) for k, _ in D.VERDICTS}
    ttc = [o["closed_at"] - o["first_seen"] for o in mine if o["closed_at"]]
    mttr = _dur(sorted(ttc)[len(ttc) // 2]) if ttc else "-"
    hist = list(reversed(app.store.get(D.RESULTS, []) or []))
    avg = round(sum(r["score"] for r in hist) / len(hist)) if hist else None
    trs = "".join(
        f'<tr data-href="/offenses/{o["id"]}"><td class="muted nowrap">{w.fmt_ts(o["closed_at"])}</td>'
        f'<td><a href="/offenses/{o["id"]}">{w.e(R.BY_ID.get(o["rule_id"], {"name": o["rule_id"]})["name"])}</a>'
        f'<div class="sub mono">{w.e(o["entity"])}</div></td>'
        f'<td>{w.e(dict(D.VERDICTS).get(o["verdict"], "No verdict").split(":")[0])}</td>'
        f'<td class="muted nowrap">{_dur(o["closed_at"] - o["first_seen"]) if o["closed_at"] else ""}</td>'
        f'<td class="detail">{w.e((o["note"] or "")[:400])}</td></tr>' for o in mine) \
        or '<tr><td colspan="5" class="empty">Nothing closed by you yet.</td></tr>'
    drs = "".join(f'<tr><td class="muted nowrap">{w.fmt_ts(r["at"])}</td><td><a href="/offenses/{r["offense"]}">{w.e(r["title"])}</a></td>'
                  f'<td>{w.e(dict(D.VERDICTS).get(r["verdict"], r["verdict"] or "none").split(":")[0])}</td><td class="num">{r["score"]}</td></tr>'
                  for r in hist[:50]) or '<tr><td colspan="4" class="empty">No drills graded yet. <a href="/drills">Run one</a>.</td></tr>'
    tile = lambda label, v: f'<div class="tile"><span>{label}</span><b class="num">{v}</b></div>'
    return f"""<div class="pagehead"><h1>Analyst log</h1><p class="lead">Every offense you closed, your verdict and your reasoning.
This is the record you can point to in an interview. Offenses Watchtower closed by itself are left out.</p></div>
<div class="tiles">{tile("Closed by you", len(mine))}{tile("True positives", counts["true-positive"])}{tile("Benign", counts["benign"])}
{tile("False positives", counts["false-positive"])}{tile("Median time to close", mttr)}{tile("Average drill score", avg if avg is not None else "-")}</div>
<section class="band"><div class="phead"><h2>Your closed offenses</h2></div>
<div class="tablewrap"><table class="grid rows"><thead><tr><th>Closed</th><th>Offense</th><th>Verdict</th><th>Time to close</th><th>Your note</th></tr></thead>
<tbody>{trs}</tbody></table></div></section>
<section class="band"><div class="phead"><h2>Drill scores</h2></div><table class="grid rows"><thead><tr><th>When</th><th>Drill</th><th>Your verdict</th>
<th class="num">Score</th></tr></thead><tbody>{drs}</tbody></table></section>"""


# ---------------------------------------------------------------------------------------------- Rule builder
def builder_page(app, h, sess, rng, form: dict | None = None, result: dict | None = None, msg: str = "") -> str:
    w = _w()
    f = form or {}
    v = lambda k, d="": w.e(str(f.get(k, d)))
    sel = lambda name, opts, cur: "".join(f'<option value="{w.e(k)}" {"selected" if k == cur else ""}>{w.e(lbl)}</option>' for k, lbl in opts)
    srcs = [(s, w.SRC_LABEL.get(s, s)) for s in C.SOURCES]
    res = ""
    if result:
        top = "".join(f'<li><span class="mono">{w.e(k)}</span>: {n} hit{"s" if n != 1 else ""}</li>' for k, n in result["top"])
        sample = "".join(f'<tr><td class="mono nowrap">{w.fmt_ts(x["ts"], True)}</td><td class="strong">{w.e(x["action"])}</td>'
                         f'<td>{w.e(x["outcome"])}</td><td class="mono">{w.e(x["actor"])}</td><td class="mono">{w.e(x["src_ip"])}</td>'
                         f'<td class="mono clip">{w.e(x["target"])}</td></tr>' for x in result["sample"])
        verdict = ("Quiet: it would not have fired in the last 7 days. Good if the thing is rare; check the condition if you expected hits."
                   if not result["would_open"] else
                   f'It would have opened {result["would_open"]} offense{"s" if result["would_open"] != 1 else ""}. '
                   + ("That is a lot: raise the threshold, shorten the window or tighten the condition."
                      if result["would_open"] > 10 else "A manageable number. Look at the sample: would you want to be told about these?"))
        res = f"""<section class="panel test-result"><div class="phead"><h2>Test against the last 7 days</h2></div>
<p>Scanned {w.num(result["scanned"])} events. <b>{w.num(result["hits"])} matched</b> across {result["entities"]} {w.e(C.GROUP_BY[f.get("group_by", "actor")].lower())} value(s).</p>
<p><b>{w.e(verdict)}</b></p>{f'<ul class="top">{top}</ul>' if top else ""}
{f'<div class="tablewrap"><table class="grid rows"><thead><tr><th>Time</th><th>Event</th><th>Outcome</th><th>Actor</th><th>Source IP</th><th>Target</th></tr></thead><tbody>{sample}</tbody></table></div>' if sample else ""}</section>"""
    mine = [r for r in R.ALL if r.get("custom")]
    lst = "".join(f'<li><b>{w.e(r["name"])}</b> <span class="mono muted">{w.e(r["id"])}</span>'
                  f'<form method="post" action="/rules-custom/{w.e(r["id"])}/delete" class="inline">{_csrf(sess)}'
                  f'<button class="btn secondary small">Delete</button></form></li>' for r in mine)
    return f"""<div class="pagehead"><p class="crumb"><a href="/rules">Rules</a> / New rule</p><h1>Rule builder</h1>
<p class="lead">Detection engineering: describe what to look for, test it on real history, tune it until the noise is right, then save.
A saved rule runs on new events from then on.</p></div>
{f'<p class="error" role="alert">{w.e(msg)}</p>' if msg else ""}
<form method="post" class="builder panel">{_csrf(sess)}
<label>Name<input name="name" value="{v("name")}" maxlength="80" placeholder="Failed console sign-ins for one user" required></label>
<label>What it means (shown on the offense)<input name="why" value="{v("why")}" maxlength="300" placeholder="One plain sentence: what happened and why it matters"></label>
<div class="grid2">
<label>Log source<select name="source">{sel("source", srcs, f.get("source", "aws-cloudtrail"))}</select></label>
<label>Outcome<select name="outcome">{sel("outcome", list(C.OUTCOMES.items()), f.get("outcome", ""))}</select></label>
<label>Event names (comma separated, blank = any)<input name="actions" value="{v("actions")}" placeholder="ConsoleLogin, CreateAccessKey"></label>
<label>Field<select name="field"><option value="">(no extra condition)</option>{sel("field", list(C.FIELDS.items()), f.get("field", ""))}</select></label>
<label>Contains<input name="contains" value="{v("contains")}" maxlength="200" placeholder="text to look for, any case"></label>
<label>Group offenses by<select name="group_by">{sel("group_by", list(C.GROUP_BY.items()), f.get("group_by", "actor"))}</select></label>
<label>Threshold (hits needed)<input type="number" name="threshold" min="1" max="1000" value="{v("threshold", 1)}"></label>
<label>Window (minutes)<input type="number" name="window_min" min="1" max="10080" value="{v("window_min", 60)}"></label>
<label>Severity 1-10 (how bad if real)<input type="number" name="severity" min="1" max="10" value="{v("severity", 5)}"></label>
<label>Credibility 1-10 (how sure)<input type="number" name="credibility" min="1" max="10" value="{v("credibility", 5)}"></label>
<label>MITRE technique id (optional)<input name="mitre" value="{v("mitre")}" placeholder="T1110"></label>
<label>MITRE technique name<input name="mitre_name" value="{v("mitre_name")}" placeholder="Brute Force"></label>
</div>
<div class="row"><button class="btn secondary" formaction="/rules-custom/test">Test against the last 7 days</button>
<button class="btn primary" formaction="/rules-custom/save">Save rule</button></div></form>
{res}
{f'<section class="panel"><div class="phead"><h2>Your rules</h2></div><ul class="myrules">{lst}</ul></section>' if lst else ""}"""
