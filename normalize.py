"""Turn each source's native record into one event shape (ECS-lite).

Event keys: uid, ts (epoch s), source, category, action, outcome (success|failure|unknown|info),
actor, src_ip, target, region, extra (dict), raw_json (str).
"""
from __future__ import annotations

import datetime as dt
import json
import xml.etree.ElementTree as ET

import config


def _epoch(s) -> float:
    if isinstance(s, (int, float)):
        return float(s)
    if isinstance(s, dt.datetime):
        return s.timestamp() if s.tzinfo else s.replace(tzinfo=dt.timezone.utc).timestamp()
    s = str(s).strip().replace("Z", "+00:00")
    if "." in s:                                   # Windows gives 7 fractional digits
        head, _, tail = s.partition(".")
        frac = "".join(ch for ch in tail if ch.isdigit())[:6]
        tz = tail[len("".join(ch for ch in tail if ch.isdigit())):]
        s = f"{head}.{frac}{tz}"
    d = dt.datetime.fromisoformat(s)
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.timestamp()


def _raw(obj) -> str:
    s = json.dumps(obj, default=str, separators=(",", ":"))
    return s if len(s) <= config.RAW_MAX else s[: config.RAW_MAX - 20] + '..."TRUNCATED"'


# ---------------------------------------------------------------- AWS CloudTrail
CT_CATEGORY = {
    "iam.amazonaws.com": "iam", "signin.amazonaws.com": "authentication", "sts.amazonaws.com": "authentication",
    "sso.amazonaws.com": "authentication", "ec2.amazonaws.com": "compute", "s3.amazonaws.com": "storage",
    "cloudtrail.amazonaws.com": "audit", "guardduty.amazonaws.com": "detection", "config.amazonaws.com": "audit",
    "ssm.amazonaws.com": "remote-access", "kms.amazonaws.com": "crypto",
}


def actor_of(ui: dict) -> tuple[str, str]:
    """(actor name, identity type) from a CloudTrail userIdentity."""
    t = ui.get("type") or ""
    if t == "Root":
        return "root", t
    if ui.get("userName"):
        return ui["userName"], t
    arn = ui.get("arn") or ""
    if t == "AssumedRole" and "/" in arn:          # arn:...:assumed-role/Role/session
        parts = arn.split("/")
        return (parts[-1] if len(parts) >= 3 else parts[-1]), t
    if ui.get("invokedBy"):
        return ui["invokedBy"], t
    return (arn.rsplit("/", 1)[-1] or ui.get("principalId") or t or "unknown"), t


def cloudtrail(rec: dict) -> dict:
    """rec: a CloudTrail record (the JSON inside lookup-events' CloudTrailEvent, or an S3 log record)."""
    ui = rec.get("userIdentity") or {}
    actor, atype = actor_of(ui)
    action = rec.get("eventName") or "unknown"
    outcome = "failure" if rec.get("errorCode") else "success"
    resp = rec.get("responseElements") or {}
    extra = {"event_source": rec.get("eventSource", ""), "identity_type": atype,
             "user_agent": (rec.get("userAgent") or "")[:200], "read_only": rec.get("readOnly"),
             "error_code": rec.get("errorCode", ""), "error_message": (rec.get("errorMessage") or "")[:300],
             "event_type": rec.get("eventType", "")}
    if action == "ConsoleLogin":
        if isinstance(resp, dict) and resp.get("ConsoleLogin") == "Failure":
            outcome = "failure"
        extra["mfa_used"] = ((rec.get("additionalEventData") or {}).get("MFAUsed") or "")
    target = ""
    req = rec.get("requestParameters") or {}
    if actor in ("unknown", "") and isinstance(req, dict) and req.get("sessionId"):
        actor = str(req["sessionId"]).rsplit("-", 1)[0]        # SSM data channels carry only "<user>-<id>"
        extra["actor_from"] = "ssm session id"
    if isinstance(req, dict):
        for k in ("userName", "bucketName", "groupId", "instanceId", "name", "roleName", "policyArn",
                  "accessKeyId", "trailName", "detectorId", "configurationRecorderName"):
            if req.get(k):
                target = str(req[k])
                break
        if not target and isinstance(req.get("instancesSet"), dict):
            items = req["instancesSet"].get("items") or []
            if items:
                target = str(items[0].get("instanceId", ""))
    if not target and rec.get("resources"):
        target = str((rec["resources"][0] or {}).get("ARN", ""))
    return {"uid": "ct:" + str(rec.get("eventID") or hash(json.dumps(rec, sort_keys=True, default=str))),
            "ts": _epoch(rec.get("eventTime")), "source": "aws-cloudtrail",
            "category": CT_CATEGORY.get(rec.get("eventSource", ""), (rec.get("eventSource") or "aws").split(".")[0]),
            "action": action, "outcome": outcome, "actor": actor, "src_ip": rec.get("sourceIPAddress") or "",
            "target": target, "region": rec.get("awsRegion") or "", "extra": extra, "raw_json": _raw(rec)}


# ---------------------------------------------------------------- Windows event log
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
LEVEL = {"1": "critical", "2": "error", "3": "warning", "4": "info", "0": "info", "5": "verbose"}


def windows(xml_event: str, log_name: str, host: str = "demo-pc") -> dict | None:
    try:
        root = ET.fromstring(xml_event)
    except ET.ParseError:
        return None
    sysn = root.find(f"{NS}System")
    if sysn is None:
        return None
    prov = sysn.find(f"{NS}Provider")
    provider = prov.get("Name", "") if prov is not None else ""
    eid = (sysn.findtext(f"{NS}EventID") or "").strip()
    rid = (sysn.findtext(f"{NS}EventRecordID") or "").strip()
    tc = sysn.find(f"{NS}TimeCreated")
    ts = _epoch(tc.get("SystemTime")) if tc is not None else 0.0
    level = LEVEL.get((sysn.findtext(f"{NS}Level") or "").strip(), "info")
    data = {}
    ed = root.find(f"{NS}EventData")
    if ed is not None:
        for i, d in enumerate(ed.findall(f"{NS}Data")):
            data[d.get("Name") or f"Data{i}"] = (d.text or "")[:1000]
    actor = data.get("SubjectUserName") or data.get("TargetUserName") or data.get("Detection User") or ""
    src_ip = data.get("IpAddress") or data.get("SourceAddress") or ""
    target = data.get("Threat Name") or data.get("Path") or data.get("TargetUserName") or ""
    short = {"Microsoft-Windows-Windows Defender/Operational": "defender",
             "Microsoft-Windows-PowerShell/Operational": "powershell",
             "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall": "firewall"}.get(log_name, log_name.lower())
    return {"uid": f"win:{log_name}:{rid or eid + str(ts)}", "ts": ts, "source": "windows", "category": short,
            "action": f"{eid} {provider.replace('Microsoft-Windows-', '')}".strip(),
            "outcome": "failure" if level in ("error", "critical") else ("info" if level == "info" else level),
            "actor": actor, "src_ip": src_ip if src_ip not in ("-", "::1", "127.0.0.1") else "", "target": target[:300],
            "region": host, "extra": {"event_id": int(eid) if eid.isdigit() else eid, "level": level,
                                      "provider": provider, "log": log_name},
            "raw_json": _raw({"log": log_name, "provider": provider, "event_id": eid, "level": level, "data": data})}


# ---------------------------------------------------------------- Tailscale
def tailscale(action: str, peer: dict, ts: float) -> dict:
    name = peer.get("HostName") or peer.get("DNSName") or "unknown"
    ips = peer.get("TailscaleIPs") or []
    return {"uid": f"ts:{action}:{peer.get('ID', name)}:{int(ts)}", "ts": ts, "source": "tailscale",
            "category": "network", "action": action, "outcome": "info", "actor": name,
            "src_ip": ips[0] if ips else "", "target": peer.get("OS", ""), "region": "tailnet",
            "extra": {"peer_id": peer.get("ID", ""), "os": peer.get("OS", ""), "online": peer.get("Online")},
            "raw_json": _raw({k: peer.get(k) for k in ("ID", "HostName", "DNSName", "OS", "TailscaleIPs",
                                                        "Online", "LastSeen", "Created", "Relay")})}


# ---------------------------------------------------------------- AWS posture finding -> event
def finding(f: dict, day: str) -> dict:
    return {"uid": f"posture:{f['key']}:{day}", "ts": f["ts"], "source": "aws-posture", "category": "posture",
            "action": f["kind"], "outcome": "info", "actor": f["entity"], "src_ip": "", "target": f.get("target", ""),
            "region": config.AWS_REGION, "extra": {"severity": f["severity"], "detail": f["detail"]},
            "raw_json": _raw(f)}


# ---------------------------------------------------------------- VPC flow logs (default v2 format)
FLOW_FIELDS = ["version", "account_id", "interface_id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol",
               "packets", "bytes", "start", "end", "action", "log_status"]


def flowlog(line: str) -> dict | None:
    parts = line.split()
    if len(parts) != len(FLOW_FIELDS) or parts[0] == "version" or parts[12] == "-":
        return None
    r = dict(zip(FLOW_FIELDS, parts))
    return {"uid": f"flow:{r['interface_id']}:{r['srcaddr']}:{r['srcport']}:{r['dstaddr']}:{r['dstport']}:{r['start']}",
            "ts": float(r["start"]), "source": "aws-flowlogs", "category": "network", "action": r["action"],
            "outcome": "failure" if r["action"] == "REJECT" else "success", "actor": r["srcaddr"],
            "src_ip": r["srcaddr"], "target": f"{r['dstaddr']}:{r['dstport']}", "region": config.AWS_REGION,
            "extra": {"dst_port": int(r["dstport"]) if r["dstport"].isdigit() else 0, "protocol": r["protocol"],
                      "bytes": int(r["bytes"]) if r["bytes"].isdigit() else 0},
            "raw_json": _raw(r)}
