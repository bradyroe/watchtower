"""Round 1 (2026-11-19): a silent feed opens an offense and closes it when the feed is back; the morning summary."""
import time

import engine
import healthwatch
import notify
from db import Store


def _health(st, name, status, last_ok, detail=""):
    with st.db() as c:
        c.execute("INSERT OR REPLACE INTO collector_health(name,last_run,last_ok,status,detail,count_last) "
                  "VALUES(?,?,?,?,?,0)", (name, time.time(), last_ok, status, detail))


def _open(st):
    with st.db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM offenses WHERE status='open'")]


def test_silent_feed_opens_then_closes(tmp_path):
    st = Store(tmp_path / "t.db")
    now = time.time()
    _health(st, "windows", "error", now - 600, "boom")             # 10 min: not silent yet
    assert healthwatch.check(st, now)[0] == 0
    _health(st, "windows", "error", now - 3 * 3600, "boom")        # 3 h: silent
    assert healthwatch.check(st, now)[0] == 1
    assert healthwatch.check(st, now + 60)[0] == 0                 # same outage, no second event
    engine.process(st)
    offs = _open(st)
    assert [o["rule_id"] for o in offs] == ["wt-feed-silent"] and offs[0]["entity"] == "windows"
    assert offs[0]["magnitude"] >= notify.PING_AT                  # a dead feed pings
    _health(st, "windows", "ok", now)
    closed = healthwatch.check(st, now + 120)[1]
    assert closed == [offs[0]["id"]] and not _open(st)


def test_aws_login_expiry_is_its_own_quiet_rule(tmp_path):
    st = Store(tmp_path / "t.db")
    now = time.time()
    _health(st, "cloudtrail", "error", now - 7200, "AWS login expired, run: aws sso login --profile siem-readonly")
    healthwatch.check(st, now)
    engine.process(st)
    offs = _open(st)
    assert [o["rule_id"] for o in offs] == ["wt-aws-login-expired"]
    assert offs[0]["magnitude"] < notify.PING_AT                   # aws_login() already pings with the fix


def test_digest_once_a_day_in_the_morning(tmp_path):
    st = Store(tmp_path / "t.db")
    _health(st, "cloudtrail", "error", None, "AWS login expired")
    _health(st, "windows", "ok", time.time())
    sent = []
    sender = lambda text, mention: sent.append((text, mention))
    morning = time.mktime(time.strptime("2026-11-19 08:30", "%Y-%m-%d %H:%M"))
    night = time.mktime(time.strptime("2026-11-19 23:30", "%Y-%m-%d %H:%M"))
    assert not notify.digest(st, sender, night)
    assert notify.digest(st, sender, morning)
    assert not notify.digest(st, sender, morning + 600)            # once a day
    text, mention = sent[0]
    assert "morning summary" in text and "cloudtrail (AWS login expired)" in text and not mention
    assert len(text) < 2000
