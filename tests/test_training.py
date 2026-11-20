"""Training (2026-11-19): drills grade, custom rules validate/test/save, pages render."""
import json

import drills as D
import engine
import rules as R
from db import Store
from rules import custom as RC


def test_every_drill_opens_its_primary_offense(tmp_path):
    st = Store(tmp_path / "t.db")
    for s in D.SCENARIOS:
        oid = D.start(st, s["id"])
        assert oid, s["id"]
        with st.db() as c:
            o = c.execute("SELECT * FROM offenses WHERE id=?", (oid,)).fetchone()
        assert o["rule_id"] == s["primary"], s["id"]
        assert o["drill"].startswith(s["id"] + ":")


def test_grading():
    s = D.BY_ID["stolen-password"]
    good = D.grade(s, "true-positive", "No MFA, new country (Germany), made an access key. Deactivate the key and reset.")
    bad = D.grade(s, "benign", "looks fine")
    assert good["score"] == 100 and good["verdict_ok"]
    assert bad["score"] == 0


def test_drill_clear_keeps_real_data(tmp_path):
    from tests.test_rules import ev
    st = Store(tmp_path / "t.db")
    st.add_events([ev(1, extra={"identity_type": "Root"}, actor="root")])
    engine.process(st)
    D.start(st, "trail-off")
    assert D.clear(st) >= 1
    with st.db() as c:
        assert c.execute("SELECT COUNT(*) FROM offenses").fetchone()[0] == 1
        assert c.execute("SELECT COUNT(*) FROM events WHERE uid LIKE 'drill:%'").fetchone()[0] == 0


def test_custom_rule_validate_test_save(tmp_path):
    from tests.test_rules import ev
    st = Store(tmp_path / "t.db")
    spec, msg = RC.validate({"name": "x"})
    assert spec is None and "name" in msg
    spec, msg = RC.validate({"name": "Bob fails", "source": "aws-cloudtrail", "actions": "ConsoleLogin",
                             "outcome": "failure", "field": "actor", "contains": "bob", "threshold": "2",
                             "window_min": "10", "mitre": "t1110"})
    assert spec and spec["mitre"] == "T1110"
    import time
    now = time.time()
    st.add_events([ev(i, ts=now - 100 + i, action="ConsoleLogin", outcome="failure", actor="bob") for i in range(3)])
    res = RC.test(st, spec)
    assert res["hits"] == 3 and res["would_open"] == 1
    rid = RC.save(st, spec, "admin")
    try:
        assert R.BY_ID[rid]["custom"]
        engine.process(st)
        with st.db() as c:
            assert c.execute("SELECT COUNT(*) FROM offenses WHERE rule_id=?", (rid,)).fetchone()[0] == 1
    finally:
        RC.delete(st, rid)
    assert rid not in R.BY_ID
    bad, msg = RC.validate({"name": "abc", "source": "aws-cloudtrail", "mitre": "T1110"})
    assert bad is None                                   # matches everything: refused


def test_lessons_are_clean():
    import learn
    ids = [x["id"] for x in learn.LESSONS]
    assert len(ids) == len(set(ids)) >= 8
    for x in learn.LESSONS:
        assert "<script" not in x["body"].lower() and "—" not in x["body"]
