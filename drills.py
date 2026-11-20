"""Practice drills (2026-11-19, the owner: "teach me ... like a cybersecurity analyst and engineer").

A drill writes a short, realistic, FAKE attack (or a harmless lookalike) into Watchtower as ordinary events
marked extra.drill. The normal rules turn them into offenses, so the owner triages exactly as he would a real
one. When he closes the drill's main offense, grade() scores his verdict and his note against what a
working analyst would have checked, and the result is kept in his analyst log.

Drill offenses never ping Discord, never count in the morning summary, and only correlate with offenses
from the same drill. All drill data can be wiped with clear(); graded results are kept.
"""
from __future__ import annotations

import json
import time

import engine

# Documentation-only addresses (RFC 5737) where an address must look ordinary; well-known scanner and
# Tor-exit ranges only where the point of the drill is that the address is foreign.
SCENARIOS = [
    {
        "id": "stolen-password", "level": "Starter", "title": "A 3 am sign-in from far away",
        "brief": "Your phone buzzes at 3 am. Someone signed in to the AWS console as a real employee. Work out "
                 "whether it was them.",
        "primary": "aws-signin-new-country",
        "events": [
            (-900, dict(action="ConsoleLogin", outcome="success", actor="dana", src_ip="185.220.101.47",
                        target="", region="us-east-1", category="authentication",
                        extra={"identity_type": "IAMUser", "mfa_used": "No", "new_country": True, "country": "DE",
                               "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0"})),
            (-840, dict(action="GetCallerIdentity", outcome="success", actor="dana", src_ip="185.220.101.47",
                        region="us-east-1", category="authentication", extra={"identity_type": "IAMUser"})),
            (-780, dict(action="ListUsers", outcome="success", actor="dana", src_ip="185.220.101.47",
                        region="us-east-1", category="iam", extra={"identity_type": "IAMUser", "read_only": True})),
            (-720, dict(action="CreateAccessKey", outcome="success", actor="dana", src_ip="185.220.101.47",
                        target="dana", region="us-east-1", category="iam",
                        extra={"identity_type": "IAMUser", "read_only": False})),
        ],
        "accept": ["true-positive"], "partial": [],
        "facts": [
            ("Noticed there was no MFA on the sign-in", ["mfa", "password only", "password alone"]),
            ("Noticed the new country", ["country", "germany", "abroad", "foreign", "overseas", "location"]),
            ("Saw the new access key (how they stay in)", ["access key", "createaccesskey", "new key", "persist"]),
            ("Said what to do next", ["disable", "deactivate", "revoke", "reset", "rotate", "delete", "lock"]),
        ],
        "explain": "True positive. Dana normally signs in from the US with MFA. This sign-in came from a Tor exit "
                   "address in Germany with a password alone, looked around (who am I, who else is here), then made "
                   "a new access key. That last step is persistence: even after a password reset, the key still works.",
        "pro": ["Ask Dana directly (by phone, not email) whether this was them",
                "Deactivate the new access key first, then reset the password and sign out all sessions",
                "Search Log activity for everything the address did after the key was made",
                "Require MFA for every console user so a password alone is never enough"],
    },
    {
        "id": "typo-storm", "level": "Starter", "title": "Six failed sign-ins in a row",
        "brief": "Watchtower opened an offense for repeated failed console sign-ins. Decide whether someone is "
                 "guessing passwords.",
        "primary": "aws-console-login-failures",
        "events": [(-600 + i * 25, dict(action="ConsoleLogin", outcome="failure", actor="sam", src_ip="198.51.100.23",
                                       region="us-east-1", category="authentication",
                                       extra={"identity_type": "IAMUser", "country": "US",
                                              "error_message": "Failed authentication"})) for i in range(6)]
        + [(-420, dict(action="ConsoleLogin", outcome="success", actor="sam", src_ip="198.51.100.23",
                       region="us-east-1", category="authentication",
                       extra={"identity_type": "IAMUser", "mfa_used": "Yes", "country": "US"}))],
        "accept": ["benign"], "partial": ["false-positive"],
        "facts": [
            ("Saw the same address finally succeeded", ["succeed", "success", "got in", "logged in", "signed in"]),
            ("Noticed MFA was used on the success", ["mfa"]),
            ("Noticed it was one user from a normal place", ["same ip", "same address", "usual", "normal", "home", "us"]),
        ],
        "explain": "Benign. Six misses then a success from the same US address, with MFA, two minutes later: that is a "
                   "person who forgot their password, not an attacker. A guesser rarely has the MFA code. The rule did "
                   "its job (it really was repeated failures), so this is benign rather than a false positive.",
        "pro": ["Check whether the failures came from the same address as the success",
                "Check MFA on the successful sign-in",
                "Compare with the user's usual country and time of day",
                "Close with a one-line note so the next analyst does not redo the work"],
    },
    {
        "id": "trail-off", "level": "Intermediate", "title": "The audit trail went quiet",
        "brief": "A high-severity offense says CloudTrail logging was stopped. Find out who did it and what it means.",
        "primary": "aws-cloudtrail-tamper",
        "events": [
            (-1500, dict(action="AssumeRole", outcome="success", actor="ci-deploy", src_ip="203.0.113.80",
                         region="us-west-2", category="authentication", extra={"identity_type": "AssumedRole"})),
            (-1440, dict(action="StopLogging", outcome="success", actor="ci-deploy", src_ip="203.0.113.80",
                         target="org-trail", region="us-west-2", category="audit",
                         extra={"identity_type": "AssumedRole", "read_only": False})),
            (-1300, dict(action="RunInstances", outcome="success", actor="ci-deploy", src_ip="203.0.113.80",
                         target="i-0drill00000000001", region="us-west-2", category="compute",
                         extra={"identity_type": "AssumedRole", "read_only": False})),
        ],
        "accept": ["true-positive"], "partial": [],
        "facts": [
            ("Named who stopped it (the ci-deploy role)", ["ci-deploy", "role", "pipeline", "deploy"]),
            ("Noticed something was launched right after", ["runinstances", "instance", "launched", "server", "ec2"]),
            ("Said to turn logging back on", ["turn it back on", "re-enable", "reenable", "startlogging", "turn on", "restart"]),
            ("Said to check what happened while it was off", ["while it was off", "gap", "after", "what happened", "other logs", "flow"]),
        ],
        "explain": "True positive. A deployment role has no reason to stop the audit trail, and it launched a server two "
                   "minutes later. Stopping logs first and then acting is the classic order of an attacker hiding. Even "
                   "if a person says it was them, it is a real policy problem: nothing should be able to stop the trail.",
        "pro": ["Start logging again immediately",
                "Find out where the ci-deploy credentials live and who can use them",
                "Look at everything the role did while the trail was off (flow logs, the instance itself)",
                "Remove cloudtrail:StopLogging from every role that does not strictly need it"],
    },
    {
        "id": "internet-noise", "level": "Starter", "title": "Somebody knocking on every door",
        "brief": "Dozens of blocked connections from one address. Is the website under attack?",
        "primary": "aws-flow-port-scan",
        "events": [(-300 + i * 5, dict(source="aws-flowlogs", category="network", action="REJECT", outcome="failure",
                                      actor="45.155.205.233", src_ip="45.155.205.233",
                                      target=f"10.0.1.15:{port}", region="us-west-2",
                                      extra={"dst_port": port, "protocol": "6", "bytes": 40}))
                   for i, port in enumerate([22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 1521, 2375, 3306, 3389, 5432,
                                             5900, 6379, 8080, 8443, 9200, 11211, 27017, 22, 3389, 445])],
        "accept": ["benign"], "partial": ["false-positive"],
        "facts": [
            ("Noticed every connection was blocked", ["reject", "blocked", "denied", "dropped", "none got"]),
            ("Noticed nothing was accepted", ["no accept", "nothing accepted", "never accepted", "didn't get in", "did not get in"]),
            ("Recognised routine internet scanning", ["scan", "noise", "background", "bot", "everyone"]),
        ],
        "explain": "Benign. Every server on the internet is scanned like this many times a day. All 25 attempts were "
                   "rejected by the firewall and none was accepted, so nothing reached the server. The useful check is "
                   "whether the same address ever got an ACCEPT.",
        "pro": ["Search Log activity for the address with outcome success (any ACCEPT?)",
                "Confirm only the web ports are open in Posture",
                "Close as benign; do not spend time chasing scanners",
                "Raise the threshold if this rule is noisy, rather than ignoring it"],
    },
    {
        "id": "jakarta-miner", "level": "Intermediate", "title": "A server nobody asked for",
        "brief": "Something was created in an AWS region this company never uses. Work out what and who.",
        "primary": "aws-new-region",
        "events": [
            (-2000, dict(action="DescribeRegions", outcome="success", actor="uploader-bot", src_ip="203.0.113.200",
                         region="us-east-1", category="compute",
                         extra={"identity_type": "IAMUser", "read_only": True, "new_network": True, "country": "NL"})),
            (-1900, dict(action="AuthorizeSecurityGroupIngress", outcome="success", actor="uploader-bot",
                         src_ip="203.0.113.200", target="sg-0drill0001", region="ap-southeast-3", category="compute",
                         extra={"identity_type": "IAMUser", "read_only": False, "new_region": True}),
             '{"ipPermissions":{"items":[{"fromPort":22,"toPort":22,"ipRanges":{"items":[{"cidrIp":"0.0.0.0/0"}]}}]}}'),
            (-1850, dict(action="RunInstances", outcome="success", actor="uploader-bot", src_ip="203.0.113.200",
                         target="i-0drill00000000002", region="ap-southeast-3", category="compute",
                         extra={"identity_type": "IAMUser", "read_only": False, "new_region": True}),
             '{"instanceType":"p3.8xlarge","minCount":4,"maxCount":4}'),
        ],
        "accept": ["true-positive"], "partial": [],
        "facts": [
            ("Noticed the region is one the company never uses", ["region", "jakarta", "ap-southeast", "asia"]),
            ("Noticed expensive GPU servers", ["gpu", "p3", "expensive", "mining", "miner", "crypto"]),
            ("Blamed the key, not a person", ["key", "leaked", "stolen", "compromised", "uploader"]),
            ("Said to stop it", ["terminate", "stop", "deactivate", "disable", "delete", "billing"]),
        ],
        "explain": "True positive, and a costly one. An upload robot's key was used from a new network to open SSH to "
                   "the world and start four GPU servers in Jakarta. That is the standard crypto-mining pattern: "
                   "attackers pick a region you never look at. The key has leaked.",
        "pro": ["Deactivate the uploader key now, then terminate the instances",
                "Check the bill and open an AWS support case (AWS often credits fraud)",
                "Find where the key leaked: a public repo, a laptop, a log",
                "Block regions the company does not use with an SCP or IAM condition"],
    },
]
BY_ID = {s["id"]: s for s in SCENARIOS}
VERDICTS = [("true-positive", "True positive: real and harmful"), ("benign", "Benign: real, but not harmful"),
            ("false-positive", "False positive: the rule was wrong")]
RESULTS = "drill_results"


def scenario_of(drill: str) -> dict | None:
    return BY_ID.get((drill or "").split(":")[0])


def start(store, sid: str) -> int | None:
    """Write the drill's events, run the rules, and return the main offense id."""
    s = BY_ID[sid]
    run = f"{sid}:{int(time.time())}"
    now = time.time()
    evs = []
    for i, item in enumerate(s["events"]):
        off, ev = item[0], dict(item[1])
        raw = item[2] if len(item) > 2 else "{}"
        ev.setdefault("source", "aws-cloudtrail")
        ev.setdefault("target", "")
        ev["extra"] = {**ev.get("extra", {}), "drill": run, "event_type": ev.get("extra", {}).get("event_type", "AwsApiCall")}
        ev.update(uid=f"drill:{run}:{i}", ts=now + off,
                  raw_json=json.dumps({"drill": True, "eventName": ev["action"], "sourceIPAddress": ev["src_ip"],
                                       "user": ev["actor"], "awsRegion": ev["region"], **json.loads(raw)}))
        evs.append(ev)
    store.add_events(evs)
    engine.process(store)
    with store.db() as c:
        r = c.execute("SELECT id FROM offenses WHERE drill=? AND rule_id=? ORDER BY id LIMIT 1", (run, s["primary"])).fetchone()
        r = r or c.execute("SELECT id FROM offenses WHERE drill=? ORDER BY magnitude DESC LIMIT 1", (run,)).fetchone()
    store.audit("system", "", "drill started", f"{s['title']} ({run})")
    return r["id"] if r else None


def grade(scenario: dict, verdict: str, note: str) -> dict:
    """Score out of 100: half for the verdict, half for what the note shows was checked."""
    text = f" {(note or '').lower()} "
    v_pts = 50 if verdict in scenario["accept"] else (25 if verdict in scenario["partial"] else 0)
    facts = [(label, any(k in text for k in keys)) for label, keys in scenario["facts"]]
    f_pts = round(50 * sum(hit for _, hit in facts) / max(1, len(facts)))
    return {"score": v_pts + f_pts, "verdict": verdict, "verdict_ok": v_pts == 50, "expected": scenario["accept"][0],
            "facts": facts, "explain": scenario["explain"], "pro": scenario["pro"], "title": scenario["title"],
            "at": time.time()}


def record(store, oid: int, drill: str, g: dict) -> None:
    with store.db() as c:
        c.execute("UPDATE offenses SET grade_json=? WHERE id=?", (json.dumps(g), oid))
    hist = store.get(RESULTS, []) or []
    hist.append({"offense": oid, "drill": drill, "title": g["title"], "score": g["score"], "verdict": g["verdict"],
                 "expected": g["expected"], "at": g["at"]})
    store.put(RESULTS, hist[-500:])


def clear(store) -> int:
    """Delete every drill event and offense. Graded results stay in the analyst log."""
    with store.db() as c:
        ids = [r["id"] for r in c.execute("SELECT id FROM offenses WHERE drill<>''")]
        for oid in ids:
            c.execute("DELETE FROM offense_events WHERE offense_id=?", (oid,))
        c.execute("DELETE FROM offenses WHERE drill<>''")
        c.execute("DELETE FROM rule_hits WHERE event_id IN (SELECT id FROM events WHERE uid LIKE 'drill:%' "
                  "OR (uid LIKE 'wt:corr:%' AND extra_json LIKE '%\"drill\"%'))")
        c.execute("DELETE FROM events WHERE uid LIKE 'drill:%' OR (uid LIKE 'wt:corr:%' AND extra_json LIKE '%\"drill\"%')")
    return len(ids)
