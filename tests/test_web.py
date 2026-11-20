"""Auth and page tests against a real server on a free port."""
import http.cookiejar
import re
import socket
import urllib.error
import urllib.parse
import urllib.request

import pytest

import auth
import engine
import web
from db import Store
from tests.test_rules import ev


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture()
def srv(tmp_path):
    st = Store(tmp_path / "w.db")
    auth.set_password(st, "admin", "correct horse battery")
    st.add_events([ev(1, extra={"identity_type": "Root"}, actor="root", ts=__import__("time").time() - 60)])
    engine.process(st)
    port = free_port()
    servers = web.serve(st, ["127.0.0.1"], port)
    yield st, f"http://127.0.0.1:{port}"
    for s in servers:
        s.shutdown()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def client():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect()), jar


def get(op, url):
    try:
        r = op.open(url)
        return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers


def post(op, url, data):
    try:
        r = op.open(url, urllib.parse.urlencode(data).encode())
        return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers


def login(op, base, pw="correct horse battery"):
    return post(op, base + "/login", {"user": "admin", "password": pw})


def test_login_required(srv):
    st, base = srv
    op, _ = client()
    for path in ("/", "/offenses", "/events", "/posture", "/rules", "/audit", "/offenses/1"):
        code, _, h = get(op, base + path)
        assert code == 303 and h["Location"] == "/login", path
    code, body, _ = get(op, base + "/api/events")
    assert code == 401
    assert get(op, base + "/api/health")[0] == 200


def test_bad_password_and_lockout(srv):
    st, base = srv
    op, jar = client()
    code, body, _ = login(op, base, "wrong")
    assert code == 401 and "Wrong user or password" in body and not list(jar)
    for _ in range(5):
        login(op, base, "wrong")
    code, body, _ = login(op, base)             # right password, but this address is locked out
    assert code == 401 and "Too many failed attempts" in body


def test_login_pages_and_cookie_flags(srv):
    st, base = srv
    op, jar = client()
    code, _, h = login(op, base)
    assert code == 303
    sc = h["Set-Cookie"]
    assert "HttpOnly" in sc and "SameSite=Strict" in sc
    for path in ("/", "/offenses", "/events", "/posture", "/rules", "/audit", "/offenses/1", "/events?q=root&range=7d"):
        code, body, hd = get(op, base + path)
        assert code == 200, path
        assert "script-src 'self'" in hd["Content-Security-Policy"]
        assert "<script>" not in body                  # no inline script
    assert "Root account used" in get(op, base + "/offenses")[1]


def test_csrf_required(srv):
    st, base = srv
    op, _ = client()
    login(op, base)
    code, body, _ = post(op, base + "/offenses/1", {"op": "toggle", "csrf": "nope"})
    assert code == 403
    with st.db() as c:
        assert c.execute("SELECT status FROM offenses WHERE id=1").fetchone()[0] == "open"
    page = get(op, base + "/offenses/1")[1]
    tok = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    code, _, _ = post(op, base + "/offenses/1", {"op": "toggle", "csrf": tok, "note": "checked, it was me"})
    assert code == 303
    with st.db() as c:
        r = c.execute("SELECT status, note FROM offenses WHERE id=1").fetchone()
        assert r["status"] == "closed" and r["note"] == "checked, it was me"
        assert c.execute("SELECT COUNT(*) FROM audit WHERE action='offense 1'").fetchone()[0] == 1


def test_static_cannot_escape(srv):
    st, base = srv
    op, _ = client()
    assert get(op, base + "/static/../db.py")[0] == 404
    assert get(op, base + "/static/app.css")[0] == 200
