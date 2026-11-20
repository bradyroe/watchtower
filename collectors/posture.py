"""AWS posture snapshot: the account's security settings as findings.

Findings are current state (the Posture page). Each active finding is also written as one event
per day, so the posture rules raise an offense per entity and keep it fresh while it lasts.
"""
from __future__ import annotations

import datetime as dt
import time

import config
import normalize
from collectors import awsutil

NAME = "posture"
WEB_PORTS = {80, 443}
ADMIN_POLICIES = {"AdministratorAccess"}


def _days(d) -> int | None:
    if not d:
        return None
    return int((time.time() - d.timestamp()) // 86400)


def snapshot(sess) -> list[dict]:
    """Every finding as a dict: key, kind, severity, entity, title, detail, target."""
    out = []
    iam = sess.client("iam")
    summ = iam.get_account_summary()["SummaryMap"]
    if not summ.get("AccountMFAEnabled"):
        out.append({"key": "root-no-mfa", "kind": "RootWithoutMFA", "severity": 10, "entity": "root",
                    "title": "Root account has no MFA", "detail": "The root login is protected by a password only."})
    if summ.get("AccountAccessKeysPresent"):
        out.append({"key": "root-keys", "kind": "RootAccessKeys", "severity": 9, "entity": "root",
                    "title": "Root account has access keys", "detail": "Root keys cannot be limited and should not exist."})
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            name = u["UserName"]
            mfa = iam.list_mfa_devices(UserName=name)["MFADevices"]
            policies = {p["PolicyName"] for p in iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]}
            for g in iam.list_groups_for_user(UserName=name)["Groups"]:
                policies |= {p["PolicyName"] for p in iam.list_attached_group_policies(GroupName=g["GroupName"])["AttachedPolicies"]}
            admin = bool(policies & ADMIN_POLICIES)
            has_console = True
            try:
                iam.get_login_profile(UserName=name)
            except iam.exceptions.NoSuchEntityException:
                has_console = False
            if admin and not mfa and has_console:
                out.append({"key": f"admin-no-mfa:{name}", "kind": "AdminWithoutMFA", "severity": 8, "entity": name,
                            "title": f"Admin user {name} signs in without MFA",
                            "detail": f"{name} has AdministratorAccess and a console password but no MFA device."})
            elif has_console and not mfa:
                out.append({"key": f"user-no-mfa:{name}", "kind": "UserWithoutMFA", "severity": 5, "entity": name,
                            "title": f"User {name} signs in without MFA", "detail": f"{name} has a console password and no MFA device."})
            for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                if k["Status"] != "Active":
                    continue
                last = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])["AccessKeyLastUsed"].get("LastUsedDate")
                idle = _days(last) if last else _days(k["CreateDate"])
                if idle is not None and idle >= 90:
                    short = k["AccessKeyId"][:4] + "..." + k["AccessKeyId"][-4:]
                    used = f"last used {last:%Y-%m-%d}" if last else "never used"
                    out.append({"key": f"key-unused:{k['AccessKeyId']}", "kind": "AccessKeyUnused90",
                                "severity": 7 if admin else 5, "entity": name, "target": short,
                                "title": f"Access key {short} on {name} unused for {idle} days",
                                "detail": f"Active key, {used}, created {k['CreateDate']:%Y-%m-%d}."
                                          + (" The user is an admin, so this key has full control." if admin else "")})
    ec2 = sess.client("ec2")
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for g in page["SecurityGroups"]:
            for p in g.get("IpPermissions", []):
                world = any(r.get("CidrIp") == "0.0.0.0/0" for r in p.get("IpRanges", [])) or \
                        any(r.get("CidrIpv6") == "::/0" for r in p.get("Ipv6Ranges", []))
                if not world:
                    continue
                lo, hi = p.get("FromPort", -1), p.get("ToPort", -1)
                ports = "all" if p.get("IpProtocol") == "-1" else (str(lo) if lo == hi else f"{lo}-{hi}")
                if p.get("IpProtocol") != "-1" and lo in WEB_PORTS and hi == lo:
                    continue                        # the website's own ports are expected
                out.append({"key": f"sg-open:{g['GroupId']}:{ports}", "kind": "SecurityGroupOpenToWorld",
                            "severity": 8, "entity": g["GroupId"], "target": ports,
                            "title": f"{g['GroupName']} allows port {ports} from anywhere",
                            "detail": f"{g['GroupId']} ({g['GroupName']}) accepts {p.get('IpProtocol')} {ports} from the internet."})
    ct = sess.client("cloudtrail")
    trails = ct.describe_trails()["trailList"]
    logging_on = False
    for t in trails:
        try:
            if ct.get_trail_status(Name=t["TrailARN"])["IsLogging"]:
                logging_on = True
        except Exception:                          # noqa: BLE001
            pass
    if not logging_on:
        out.append({"key": "no-trail", "kind": "CloudTrailNotLogging", "severity": 8, "entity": "cloudtrail",
                    "title": "No CloudTrail trail is logging", "detail": "Only the 90-day event history exists."})
    s3c = sess.client("s3control")
    try:
        b = s3c.get_public_access_block(AccountId=config.AWS_ACCOUNT_ID)["PublicAccessBlockConfiguration"]
        if not all(b.values()):
            out.append({"key": "s3-account-block", "kind": "S3AccountBlockOff", "severity": 4, "entity": "s3",
                        "title": "Account-wide S3 public access block is partly off", "detail": str(b)})
    except s3c.exceptions.NoSuchPublicAccessBlockConfiguration:
        out.append({"key": "s3-account-block", "kind": "S3AccountBlockOff", "severity": 4, "entity": "s3",
                    "title": "Account-wide S3 public access block is off", "detail": "New buckets are not covered."})
    except Exception as exc:                       # noqa: BLE001
        if "NoSuchPublicAccessBlockConfiguration" in str(exc):
            out.append({"key": "s3-account-block", "kind": "S3AccountBlockOff", "severity": 4, "entity": "s3",
                        "title": "Account-wide S3 public access block is off", "detail": "New buckets are not covered."})
        else:
            raise
    return out


def save(store, found: list[dict]) -> int:
    now = time.time()
    day = dt.date.today().isoformat()
    keys = [f["key"] for f in found]
    with store.db() as c:
        c.execute("UPDATE findings SET active=0")
        for f in found:
            c.execute("INSERT INTO findings(key,kind,severity,entity,title,detail,first_seen,last_seen,active) "
                      "VALUES(?,?,?,?,?,?,?,?,1) ON CONFLICT(key) DO UPDATE SET severity=excluded.severity, "
                      "title=excluded.title, detail=excluded.detail, last_seen=excluded.last_seen, active=1",
                      (f["key"], f["kind"], f["severity"], f["entity"], f["title"], f["detail"], now, now))
    return store.add_events([normalize.finding({**f, "ts": now}, day) for f in found]) if keys else 0


def run(store, sess=None) -> int:
    try:
        found = snapshot(sess or awsutil.session())
    except Exception as exc:                       # noqa: BLE001
        store.health(NAME, False, awsutil.explain(exc))
        return 0
    n = save(store, found)
    import engine
    engine.process(store)                          # file today's finding events into their offenses first
    closed = engine.resolve_posture(store, found, dt.date.today().isoformat())
    store.health(NAME, True, f"{len(found)} findings" + (f", {len(closed)} resolved" if closed else ""), len(found))
    return n
