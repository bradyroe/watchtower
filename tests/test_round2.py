"""Round 2 (2026-11-19): offline geo, learned baselines, correlation."""
import engine
import geo
from db import Store
import ipaddress

import pytest

from tests.test_rules import ev


@pytest.fixture(autouse=True)
def small_geo_table(monkeypatch):
    """The real DB-IP file is downloaded into data/geo/ at runtime and is not in the repo, so the
    tests use a three-row table instead. Lookup logic is the same."""
    rows = [("8.8.4.0", "8.8.8.255", "US"), ("81.2.69.0", "81.2.69.255", "GB")]
    v4 = ([int(ipaddress.ip_address(a)) for a, _, _ in rows],
          [int(ipaddress.ip_address(b)) for _, b, _ in rows],
          [c for _, _, c in rows])
    monkeypatch.setattr(geo, "_tables", {4: v4, 6: ([], [], [])})


def test_geo_offline_lookup():
    assert geo.country("8.8.8.8") == "US"
    assert geo.country("10.0.0.1") == "" and geo.country("100.64.0.10") == ""   # private, tailnet
    assert geo.country("ec2.amazonaws.com") == ""
    assert geo.network("203.0.113.9") == "203.0.0.0/16"


def _offs(st, rule):
    with st.db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM offenses WHERE rule_id=?", (rule,))]


def login(i, ip, actor="alice"):
    return ev(i, action="ConsoleLogin", src_ip=ip, actor=actor, extra={"identity_type": "IAMUser", "mfa_used": "Yes"})


def test_new_country_needs_history_first(tmp_path):
    st = Store(tmp_path / "t.db")
    st.add_events([login(1, "8.8.8.8")])                  # first ever: learning, no alert
    engine.process(st)
    assert not _offs(st, "aws-signin-new-country")
    st.add_events([login(2, "8.8.4.4")])                  # same country again
    engine.process(st)
    assert not _offs(st, "aws-signin-new-country")
    st.add_events([login(3, "81.2.69.142")])              # GB
    engine.process(st)
    offs = _offs(st, "aws-signin-new-country")
    assert len(offs) == 1 and offs[0]["entity"] == "alice"


def test_new_region_write_only(tmp_path):
    st = Store(tmp_path / "t.db")
    w = lambda i, region, ro=False: ev(i, action="RunInstances", region=region, src_ip="8.8.8.8",
                                      extra={"read_only": ro, "event_type": "AwsApiCall", "identity_type": "IAMUser"})
    st.add_events([w(1, "us-west-2")])
    engine.process(st)
    st.add_events([w(2, "ap-southeast-3", ro=True)])     # a read in a new region is not a write
    engine.process(st)
    assert not _offs(st, "aws-new-region")
    st.add_events([w(3, "ap-southeast-3")])
    engine.process(st)
    assert [o["entity"] for o in _offs(st, "aws-new-region")] == ["ap-southeast-3"]


def test_two_rules_one_entity_correlate(tmp_path):
    st = Store(tmp_path / "t.db")
    st.add_events([ev(1, action="ConsoleLogin", actor="mallory", extra={"mfa_used": "No"}),
                   ev(2, action="CreateAccessKey", actor="mallory")])
    engine.process(st)
    corr = _offs(st, "corr-multi-rule")
    assert len(corr) == 1 and corr[0]["entity"] == "mallory"
    engine.process(st)                                    # idempotent
    assert len(_offs(st, "corr-multi-rule")) == 1


def test_drills_do_not_correlate_or_ping(tmp_path):
    import notify
    st = Store(tmp_path / "t.db")
    st.add_events([ev(1, action="ConsoleLogin", actor="drill-x", extra={"mfa_used": "No", "drill": "d1"}),
                   ev(2, action="CreateAccessKey", actor="drill-x", extra={"drill": "d1"})])
    engine.process(st)
    corr = _offs(st, "corr-multi-rule")
    assert len(corr) == 1 and corr[0]["drill"] == "d1"           # correlates inside its own drill only
    sent = []
    st.put("notify_queue", [o["id"] for o in _offs(st, "aws-console-login-no-mfa")])
    notify._flush(st, lambda t, m: sent.append(t))
    assert not sent
