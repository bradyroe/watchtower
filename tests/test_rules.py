import json

import pytest

import engine
import rules as R
from db import Store
from rules.builtin import matches

DEF = "Microsoft-Windows-Windows Defender/Operational"


def ev(i, **k):
    base = {"uid": f"u{i}", "ts": 1_000_000.0 + i, "source": "aws-cloudtrail", "category": "x", "action": "Describe",
            "outcome": "success", "actor": "alice", "src_ip": "198.51.100.1", "target": "", "region": "us-west-2",
            "extra": {}, "raw_json": "{}"}
    base.update(k)
    return base


CASES = [
    ("aws-root-used", ev(1, extra={"identity_type": "Root"}), ev(2)),
    ("aws-console-login-no-mfa", ev(1, action="ConsoleLogin", extra={"mfa_used": "No"}),
     ev(2, action="ConsoleLogin", extra={"mfa_used": "Yes"})),
    ("aws-console-login-failures", ev(1, action="ConsoleLogin", outcome="failure"), ev(2, action="ConsoleLogin")),
    ("aws-iam-change", ev(1, action="CreateAccessKey"), ev(2, action="ListUsers")),
    ("aws-cloudtrail-tamper", ev(1, action="StopLogging"), ev(2, action="StopLogging", outcome="failure")),
    ("aws-sg-open-world", ev(1, action="AuthorizeSecurityGroupIngress", raw_json='{"cidrIp":"0.0.0.0/0"}'),
     ev(2, action="AuthorizeSecurityGroupIngress", raw_json='{"cidrIp":"10.0.0.0/8"}')),
    ("aws-s3-public-block-changed", ev(1, action="PutAccountPublicAccessBlock"), ev(2, action="GetPublicAccessBlock")),
    ("aws-detection-disabled", ev(1, action="DeleteDetector"), ev(2, action="CreateDetector")),
    ("aws-guardduty-paused", ev(1, action="UpdateDetector", raw_json='{"enable":false}'),
     ev(2, action="UpdateDetector", raw_json='{"enable":true}')),
    ("tailscale-new-device", ev(1, source="tailscale", action="NewDevice"), ev(2, source="tailscale", action="DeviceBaseline")),
    ("win-defender-detection", ev(1, source="windows", extra={"log": DEF, "event_id": 1116}),
     ev(2, source="windows", extra={"log": DEF, "event_id": 5007})),
    ("win-defender-off", ev(1, source="windows", extra={"log": DEF, "event_id": 5001}),
     ev(2, source="windows", extra={"log": "System", "event_id": 5001})),
    ("posture-admin-no-mfa", ev(1, source="aws-posture", action="AdminWithoutMFA"),
     ev(2, source="aws-posture", action="UserWithoutMFA")),
    ("posture-key-unused", ev(1, source="aws-posture", action="AccessKeyUnused90"),
     ev(2, source="aws-cloudtrail", action="AccessKeyUnused90")),
    ("posture-root", ev(1, source="aws-posture", action="RootWithoutMFA"), ev(2, source="aws-posture", action="AdminWithoutMFA")),
    ("posture-sg-open", ev(1, source="aws-posture", action="SecurityGroupOpenToWorld"), ev(2, source="aws-posture", action="X")),
    ("posture-no-trail", ev(1, source="aws-posture", action="CloudTrailNotLogging"), ev(2, source="aws-posture", action="X")),
    ("aws-flow-port-scan", ev(1, source="aws-flowlogs", action="REJECT"), ev(2, source="aws-flowlogs", action="ACCEPT")),
    ("win-logon-failures", ev(1, source="windows", extra={"log": "Security", "event_id": 4625}),
     ev(2, source="windows", extra={"log": "Security", "event_id": 4624})),
    ("win-user-created", ev(1, source="windows", extra={"log": "Security", "event_id": 4720}),
     ev(2, source="windows", extra={"log": "System", "event_id": 4720})),
    ("win-admin-added", ev(1, source="windows", target="Administrators", extra={"log": "Security", "event_id": 4732}),
     ev(2, source="windows", target="Users", extra={"log": "Security", "event_id": 4732})),
    ("win-log-cleared", ev(1, source="windows", extra={"log": "System", "event_id": 104}),
     ev(2, source="windows", extra={"log": "System", "event_id": 105})),
    ("aws-signin-new-country", ev(1, action="ConsoleLogin", extra={"new_country": True}),
     ev(2, action="ConsoleLogin", extra={"new_country": False})),
    ("aws-new-network", ev(1, extra={"new_network": True}), ev(2, extra={"new_network": True, "new_country": True})),
    ("aws-new-region", ev(1, extra={"new_region": True}), ev(2, extra={"new_region": True}, outcome="failure")),
    ("corr-multi-rule", ev(1, source="watchtower", action="Correlated"), ev(2, source="watchtower", action="FeedSilent")),
    ("wt-feed-silent", ev(1, source="watchtower", action="FeedSilent"), ev(2, source="watchtower", action="AwsLoginExpired")),
    ("wt-aws-login-expired", ev(1, source="watchtower", action="AwsLoginExpired"), ev(2, source="windows", action="AwsLoginExpired")),
]


def test_every_rule_has_mitre():
    for r in R.ALL:
        tid, name, _ = r["mitre"]
        assert name, r["id"]
        assert not tid or tid.startswith("T"), r["id"]


def test_every_rule_has_a_case():
    assert {c[0] for c in CASES} == set(R.BY_ID)


@pytest.mark.parametrize("rid,hit,miss", CASES, ids=[c[0] for c in CASES])
def test_rule(rid, hit, miss):
    rule = R.BY_ID[rid]
    assert matches(rule, hit)
    assert not matches(rule, miss)
    stored = dict(hit, extra_json=json.dumps(hit["extra"]))      # the shape read back from SQLite
    stored.pop("extra")
    assert matches(rule, stored)


def test_offense_grouping_and_threshold(tmp_path):
    st = Store(tmp_path / "t.db")
    st.add_events([ev(i, action="ConsoleLogin", outcome="failure", src_ip="203.0.113.9") for i in range(2)])
    engine.process(st)
    with st.db() as c:
        assert c.execute("SELECT COUNT(*) FROM offenses").fetchone()[0] == 0      # under the threshold of 3
    st.add_events([ev(i, action="ConsoleLogin", outcome="failure", src_ip="203.0.113.9") for i in (2, 3)])
    engine.process(st)
    with st.db() as c:
        offs = c.execute("SELECT * FROM offenses").fetchall()
    assert len(offs) == 1 and offs[0]["event_count"] == 4 and offs[0]["entity"] == "203.0.113.9"
    st.add_events([ev(10 + i, action="ConsoleLogin", outcome="failure", src_ip="198.51.100.77") for i in range(3)])
    st.add_events([ev(10 * 86400 + i, action="ConsoleLogin", outcome="failure", src_ip="203.0.113.9") for i in range(3)])
    engine.process(st)
    with st.db() as c:
        assert c.execute("SELECT COUNT(*) FROM offenses").fetchone()[0] == 3      # new address; and after 5 quiet days


def test_closed_offense_starts_fresh_and_magnitude(tmp_path):
    st = Store(tmp_path / "t.db")
    st.add_events([ev(1, extra={"identity_type": "Root"}, actor="root")])
    engine.process(st)
    with st.db() as c:
        o = c.execute("SELECT * FROM offenses").fetchone()
        assert 1 <= o["magnitude"] <= 10 and o["relevance"] >= 7               # root is an important entity
        c.execute("UPDATE offenses SET status='closed'")
    st.add_events([ev(2, extra={"identity_type": "Root"}, actor="root")])
    engine.process(st)
    with st.db() as c:
        assert c.execute("SELECT COUNT(*) FROM offenses WHERE status='open'").fetchone()[0] == 1


def test_disabled_rule_does_not_fire(tmp_path):
    st = Store(tmp_path / "t.db")
    with st.db() as c:
        c.execute("INSERT INTO rule_state VALUES('aws-root-used',0)")
    st.add_events([ev(1, extra={"identity_type": "Root"}, actor="root")])
    engine.process(st)
    with st.db() as c:
        assert c.execute("SELECT COUNT(*) FROM offenses").fetchone()[0] == 0


def test_dedupe(tmp_path):
    st = Store(tmp_path / "t.db")
    assert st.add_events([ev(1)]) == 1 and st.add_events([ev(1)]) == 0


def test_out_of_order_backfill_makes_one_offense(tmp_path):
    """lookup-events returns newest first; days-apart hits for one actor must still land in one offense."""
    st = Store(tmp_path / "t.db")
    day = 86400
    hits = [ev(i, ts=1_000_000.0 + t * day, action="ConsoleLogin", extra={"mfa_used": "No"}, actor="dana")
            for i, t in enumerate([6, 4.5, 3, 1, 0])]
    st.add_events(hits[:2])
    engine.process(st)
    st.add_events(hits[2:])
    engine.process(st)
    with st.db() as c:
        offs = c.execute("SELECT * FROM offenses").fetchall()
        assert len(offs) == 1 and offs[0]["event_count"] == 5
        assert offs[0]["first_seen"] == 1_000_000.0 and offs[0]["last_seen"] == 1_000_000.0 + 6 * day
