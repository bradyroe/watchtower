"""2026-11-18: posture offenses close on their own once fixed; serious new offenses ping Discord."""
import datetime as dt
import time

import engine
import normalize
import notify
from db import Store
from tests.test_rules import ev

DAY = dt.date.today().isoformat()
ADMIN = {"key": "admin-no-mfa:dana", "kind": "AdminWithoutMFA", "severity": 8, "entity": "dana",
         "title": "Admin user dana signs in without MFA", "detail": "x"}
ADMIN2 = {**ADMIN, "key": "admin-no-mfa:erin", "entity": "erin", "title": "Admin user erin signs in without MFA"}
KEY = {"key": "key-unused:AKIAEXAMPLEW9QZ", "kind": "AccessKeyUnused90", "severity": 7, "entity": "erin",
       "target": "AKIA...W9QZ", "title": "Access key unused", "detail": "x"}


def _file(st, found):
    st.add_events([normalize.finding({**f, "ts": time.time()}, DAY) for f in found])
    engine.process(st)


def _open(st):
    with st.db() as c:
        return {(r["rule_id"], r["entity"]) for r in c.execute("SELECT * FROM offenses WHERE status='open'")}


def test_fixed_posture_findings_close_and_others_stay(tmp_path):
    st = Store(tmp_path / "t.db")
    _file(st, [ADMIN, ADMIN2, KEY])
    st.add_events([ev(1, action="ConsoleLogin", extra={"mfa": "No"}, actor="dana")])   # history, may or may not match
    engine.process(st)
    before = _open(st)
    assert {("posture-admin-no-mfa", "dana"), ("posture-admin-no-mfa", "erin"), ("posture-key-unused", "AKIA...W9QZ")} <= before
    closed = engine.resolve_posture(st, [ADMIN2], DAY)            # dana got MFA, the key was turned off
    after = _open(st)
    assert len(closed) == 2
    assert ("posture-admin-no-mfa", "erin") in after
    assert ("posture-admin-no-mfa", "dana") not in after and ("posture-key-unused", "AKIA...W9QZ") not in after
    assert {k for k in before if not k[0].startswith("posture-")} <= after         # event offenses never auto-close
    with st.db() as c:
        o = c.execute("SELECT * FROM offenses WHERE rule_id='posture-admin-no-mfa' AND entity='dana'").fetchone()
        assert o["status"] == "closed" and o["note"].startswith("Resolved: no longer found in AWS")
        assert c.execute("SELECT COUNT(*) FROM audit WHERE user='system' AND action='auto-closed offense'").fetchone()[0] == 2


def test_a_finding_that_comes_back_opens_a_new_offense(tmp_path):
    st = Store(tmp_path / "t.db")
    _file(st, [ADMIN])
    engine.resolve_posture(st, [], DAY)
    assert _open(st) == set()
    tomorrow = (dt.date.today() + dt.timedelta(days=1)).isoformat()
    st.add_events([normalize.finding({**ADMIN, "ts": time.time() + 86400}, tomorrow)])
    engine.process(st)
    assert ("posture-admin-no-mfa", "dana") in _open(st)


def test_pings_new_serious_offenses_once_with_no_ids(tmp_path, monkeypatch):
    st = Store(tmp_path / "t.db")
    monkeypatch.setattr(notify, "webhook", lambda: "https://discord.com/api/webhooks/x/y")
    sent = []
    _file(st, [ADMIN, {**KEY, "severity": 5}])
    n = notify.flush(st, sender=lambda text, mention: sent.append((text, mention)))
    assert n == 1 and len(sent) == 1                                 # admin is magnitude 7+, the key offense is not
    text, mention = sent[0]
    assert text.startswith("Watchtower: Admin user without MFA (dana), magnitude") and "/offenses/" in text
    assert "AKIA" not in text and mention is False
    assert notify.flush(st, sender=lambda t, m: sent.append((t, m))) == 0   # never twice


def test_hourly_cap_folds_the_rest_into_one_summary(tmp_path, monkeypatch):
    st = Store(tmp_path / "t.db")
    monkeypatch.setattr(notify, "webhook", lambda: "https://discord.com/api/webhooks/x/y")
    _file(st, [{**ADMIN, "key": f"admin-no-mfa:u{i}", "entity": f"u{i}"} for i in range(15)])
    sent = []
    notify.flush(st, sender=lambda t, m: sent.append(t))
    assert len(sent) == notify.MAX_PER_HOUR
    assert "more new offenses" in sent[-1]


def test_clean_strips_ips_arns_keys_and_mentions():
    out = notify.clean("from 203.0.113.200 arn:aws:iam::1:user/x AKIAIOSFODNN7EXAMPLE AKIA...W9QZ @everyone")
    assert "203.0.113" not in out and "arn:aws" not in out and "AKIA" not in out and "@everyone" not in out


def test_aws_expiry_pings_once(tmp_path):
    st = Store(tmp_path / "t.db")
    sent = []
    for _ in range(3):
        notify.aws_login(st, True, sender=lambda t, m: sent.append(t))
    assert len(sent) == 1
    notify.aws_login(st, False, sender=lambda t, m: sent.append(t))
    notify.aws_login(st, True, sender=lambda t, m: sent.append(t))
    assert len(sent) == 2
