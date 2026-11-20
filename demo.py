"""Fake data for WATCHTOWER_DEMO=1 (screenshots and a future public repo). Nothing here is real:
made-up users, documentation IP ranges (RFC 5737), example account ids."""
from __future__ import annotations

import random
import time

USERS = ["alice", "deploy-bot", "bob", "ci-runner", "carol"]
IPS = ["198.51.100.23", "203.0.113.7", "192.0.2.44", "198.51.100.90", "203.0.113.150"]
ACTIONS = ["DescribeInstances", "GetObject", "ListBuckets", "AssumeRole", "PutObject", "StartSession", "GetCallerIdentity"]


def events(n: int = 1500, days: int = 7, seed: int = 7) -> list[dict]:
    rnd = random.Random(seed)
    now = time.time()
    out = []
    for i in range(n):
        ts = now - rnd.random() * days * 86400
        u = rnd.choice(USERS)
        a = rnd.choice(ACTIONS)
        out.append({"uid": f"demo:{i}", "ts": ts, "source": "aws-cloudtrail", "category": "compute", "action": a,
                    "outcome": "failure" if rnd.random() < .04 else "success", "actor": u, "src_ip": rnd.choice(IPS),
                    "target": f"arn:aws:example:{rnd.randint(1, 9)}", "region": "us-west-2",
                    "extra": {"identity_type": "IAMUser"}, "raw_json": f'{{"eventName":"{a}","demo":true}}'})
    for k in range(5):                                  # a failed-login burst
        out.append({"uid": f"demo:fail:{k}", "ts": now - 3600 + k * 60, "source": "aws-cloudtrail", "category": "authentication",
                    "action": "ConsoleLogin", "outcome": "failure", "actor": "alice", "src_ip": "203.0.113.66",
                    "target": "", "region": "us-east-1", "extra": {"identity_type": "IAMUser", "mfa_used": "No"},
                    "raw_json": '{"eventName":"ConsoleLogin","demo":true}'})
    out.append({"uid": "demo:root", "ts": now - 7200, "source": "aws-cloudtrail", "category": "authentication",
                "action": "ConsoleLogin", "outcome": "success", "actor": "root", "src_ip": "198.51.100.23", "target": "",
                "region": "us-east-1", "extra": {"identity_type": "Root", "mfa_used": "Yes"}, "raw_json": '{"demo":true}'})
    for i in range(300):
        ts = now - rnd.random() * days * 86400
        out.append({"uid": f"demo:win:{i}", "ts": ts, "source": "windows", "category": "system",
                    "action": rnd.choice(["7036 Service Control Manager", "19 WindowsUpdateClient", "5007 Windows Defender"]),
                    "outcome": "info", "actor": "", "src_ip": "", "target": "", "region": "demo-pc",
                    "extra": {"log": "System", "event_id": 7036}, "raw_json": '{"demo":true}'})
    out.append({"uid": "demo:ts:new", "ts": now - 5400, "source": "tailscale", "category": "network", "action": "NewDevice",
                "outcome": "info", "actor": "unknown-laptop", "src_ip": "100.64.0.99", "target": "linux", "region": "tailnet",
                "extra": {}, "raw_json": '{"demo":true}'})
    for f in [("AdminWithoutMFA", "bob", 8), ("AccessKeyUnused90", "ci-runner", 5)]:
        out.append({"uid": f"demo:posture:{f[0]}:{f[1]}", "ts": now - 600, "source": "aws-posture", "category": "posture",
                    "action": f[0], "outcome": "info", "actor": f[1], "src_ip": "", "target": f"AKIA...{f[1][:4].upper()}",
                    "region": "us-west-2", "extra": {"severity": f[2]}, "raw_json": '{"demo":true}'})
    return out


def findings() -> list[dict]:
    return [{"key": "admin-no-mfa:bob", "kind": "AdminWithoutMFA", "severity": 8, "entity": "bob",
             "title": "Admin user bob signs in without MFA", "detail": "Demo data."},
            {"key": "key-unused:demo", "kind": "AccessKeyUnused90", "severity": 5, "entity": "ci-runner",
             "title": "Access key AKIA...CI-R on ci-runner unused for 140 days", "detail": "Demo data."}]
