"""The shipped rules.

A rule:
  id, name, severity (1-10), credibility (1-10: how sure a hit means something),
  source, actions (set, or None for any), outcome (or None), where(event) -> bool (optional),
  group_by: the event field naming the entity the offense is about,
  window_min: hits for the same entity inside this window join one offense,
  threshold: hits needed inside the window before an offense opens (default 1),
  why: one plain sentence shown on the offense.
"""
from __future__ import annotations

import json


def _x(e: dict) -> dict:
    x = e.get("extra")
    if isinstance(x, dict):
        return x
    try:
        return json.loads(e.get("extra_json") or "{}")
    except ValueError:
        return {}


def _raw_has(*needles):
    return lambda e: any(n in (e.get("raw_json") or "") for n in needles)


IAM_CHANGES = {
    "CreateUser", "DeleteUser", "CreateAccessKey", "UpdateAccessKey", "DeleteAccessKey", "CreateLoginProfile",
    "UpdateLoginProfile", "AttachUserPolicy", "DetachUserPolicy", "PutUserPolicy", "AttachRolePolicy",
    "PutRolePolicy", "AttachGroupPolicy", "PutGroupPolicy", "AddUserToGroup", "CreatePolicy", "CreatePolicyVersion",
    "SetDefaultPolicyVersion", "CreateRole", "UpdateAssumeRolePolicy", "DeactivateMFADevice", "DeleteVirtualMFADevice",
}

RULES = [
    {"id": "aws-root-used", "name": "Root account used", "severity": 9, "credibility": 9,
     "source": "aws-cloudtrail", "actions": None, "outcome": None,
     "where": lambda e: _x(e).get("identity_type") == "Root" and _x(e).get("event_type") != "AwsServiceEvent",
     "group_by": "actor", "window_min": 60,
     "why": "The root login can do anything and cannot be limited. Day-to-day work should never use it."},
    {"id": "aws-console-login-no-mfa", "name": "Console sign-in without MFA", "severity": 7, "credibility": 9,
     "source": "aws-cloudtrail", "actions": {"ConsoleLogin"}, "outcome": "success",
     "where": lambda e: _x(e).get("mfa_used") == "No", "group_by": "actor", "window_min": 24 * 60,
     "why": "Someone signed in to the AWS console with a password alone."},
    {"id": "aws-console-login-failures", "name": "Repeated console sign-in failures", "severity": 7,
     "credibility": 7, "source": "aws-cloudtrail", "actions": {"ConsoleLogin"}, "outcome": "failure",
     "group_by": "src_ip", "window_min": 15, "threshold": 3,
     "why": "Three or more failed console sign-ins from one address inside 15 minutes."},
    {"id": "aws-iam-change", "name": "IAM user, key or policy changed", "severity": 6, "credibility": 8,
     "source": "aws-cloudtrail", "actions": IAM_CHANGES, "outcome": "success",
     "group_by": "actor", "window_min": 60,
     "why": "Changes to who can sign in or what they can do."},
    {"id": "aws-cloudtrail-tamper", "name": "CloudTrail stopped, deleted or changed", "severity": 9,
     "credibility": 9, "source": "aws-cloudtrail",
     "actions": {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "PutInsightSelectors"},
     "outcome": "success", "group_by": "actor", "window_min": 60,
     "why": "Turning off or changing the audit trail is how an attacker hides."},
    {"id": "aws-sg-open-world", "name": "Security group opened to the internet", "severity": 7, "credibility": 8,
     "source": "aws-cloudtrail", "actions": {"AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"},
     "outcome": "success", "where": _raw_has('"0.0.0.0/0"', '"::/0"'), "group_by": "target", "window_min": 60,
     "why": "A firewall rule now accepts traffic from any address."},
    {"id": "aws-s3-public-block-changed", "name": "S3 public access block changed", "severity": 6,
     "credibility": 8, "source": "aws-cloudtrail",
     "actions": {"PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock", "PutAccountPublicAccessBlock",
                 "DeleteAccountPublicAccessBlock"},
     "outcome": "success", "group_by": "actor", "window_min": 60,
     "why": "The setting that keeps buckets private was changed. Expected when it is being turned on."},
    {"id": "aws-detection-disabled", "name": "GuardDuty or Config turned off", "severity": 8, "credibility": 9,
     "source": "aws-cloudtrail",
     "actions": {"DeleteDetector", "DisassociateFromMasterAccount", "StopConfigurationRecorder",
                 "DeleteConfigurationRecorder", "DeleteDeliveryChannel"},
     "outcome": "success", "group_by": "actor", "window_min": 60,
     "why": "A detection service was switched off."},
    {"id": "aws-guardduty-paused", "name": "GuardDuty detector paused", "severity": 8, "credibility": 9,
     "source": "aws-cloudtrail", "actions": {"UpdateDetector"}, "outcome": "success",
     "where": _raw_has('"enable":false'), "group_by": "actor", "window_min": 60,
     "why": "GuardDuty was set to disabled."},
    {"id": "tailscale-new-device", "name": "New device joined the tailnet", "severity": 6, "credibility": 8,
     "source": "tailscale", "actions": {"NewDevice"}, "outcome": None, "group_by": "actor", "window_min": 24 * 60,
     "why": "A device that was not on the tailnet before can now reach these machines."},
    {"id": "win-defender-detection", "name": "Defender found malware", "severity": 9, "credibility": 9,
     "source": "windows", "actions": None, "outcome": None,
     "where": lambda e: _x(e).get("log") == "Microsoft-Windows-Windows Defender/Operational"
     and _x(e).get("event_id") in (1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119),
     "group_by": "target", "window_min": 24 * 60,
     "why": "Microsoft Defender reported a threat on this PC."},
    {"id": "win-defender-off", "name": "Defender protection turned off", "severity": 8, "credibility": 8,
     "source": "windows", "actions": None, "outcome": None,
     "where": lambda e: _x(e).get("log") == "Microsoft-Windows-Windows Defender/Operational"
     and _x(e).get("event_id") in (5001, 5010, 5012),
     "group_by": "region", "window_min": 24 * 60,
     "why": "Real-time or scheduled scanning was disabled on this PC."},
    {"id": "posture-admin-no-mfa", "name": "Admin user without MFA", "severity": 8, "credibility": 10,
     "source": "aws-posture", "actions": {"AdminWithoutMFA"}, "outcome": None, "group_by": "actor",
     "window_min": 7 * 24 * 60,
     "why": "A stolen password alone gives full control of the AWS account."},
    {"id": "posture-key-unused", "name": "Access key unused 90+ days", "severity": 5, "credibility": 10,
     "source": "aws-posture", "actions": {"AccessKeyUnused90"}, "outcome": None, "group_by": "target",
     "window_min": 7 * 24 * 60,
     "why": "An active key nobody uses is risk with no benefit. Deactivate it if nothing needs it."},
    {"id": "posture-root", "name": "Root account weakness", "severity": 10, "credibility": 10,
     "source": "aws-posture", "actions": {"RootWithoutMFA", "RootAccessKeys"}, "outcome": None,
     "group_by": "actor", "window_min": 7 * 24 * 60, "why": "The root login is not locked down."},
    {"id": "posture-sg-open", "name": "Non-web port open to the internet", "severity": 8, "credibility": 10,
     "source": "aws-posture", "actions": {"SecurityGroupOpenToWorld"}, "outcome": None, "group_by": "actor",
     "window_min": 7 * 24 * 60, "why": "Only the website ports should accept traffic from anywhere."},
    {"id": "posture-no-trail", "name": "No CloudTrail trail logging", "severity": 8, "credibility": 10,
     "source": "aws-posture", "actions": {"CloudTrailNotLogging"}, "outcome": None, "group_by": "actor",
     "window_min": 7 * 24 * 60, "why": "Without a trail, account activity older than 90 days is lost."},
    {"id": "aws-flow-port-scan", "name": "Many rejected connections from one address", "severity": 5,
     "credibility": 6, "source": "aws-flowlogs", "actions": {"REJECT"}, "outcome": None, "group_by": "src_ip",
     "window_min": 10, "threshold": 20,
     "why": "Twenty or more blocked connection attempts inside 10 minutes looks like a scan."},
    # ---- 2026-11-19 round 1: Windows accounts and log tampering (Security log needs Event Log Readers)
    {"id": "win-logon-failures", "name": "Repeated failed Windows sign-ins", "severity": 6, "credibility": 6,
     "source": "windows", "actions": None, "outcome": None,
     "where": lambda e: _x(e).get("log") == "Security" and _x(e).get("event_id") == 4625,
     "group_by": "region", "window_min": 10, "threshold": 5,
     "why": "Five or more failed sign-ins on this PC inside 10 minutes: a wrong password typed a lot, or someone guessing."},
    {"id": "win-user-created", "name": "New Windows account created", "severity": 6, "credibility": 8,
     "source": "windows", "actions": None, "outcome": None,
     "where": lambda e: _x(e).get("log") == "Security" and _x(e).get("event_id") == 4720,
     "group_by": "target", "window_min": 60,
     "why": "A new local account appeared on this PC. Attackers add one so they can come back later."},
    {"id": "win-admin-added", "name": "Account added to Administrators", "severity": 8, "credibility": 9,
     "source": "windows", "actions": None, "outcome": None,
     "where": lambda e: _x(e).get("log") == "Security" and _x(e).get("event_id") == 4732
     and (e.get("target") or "").lower() == "administrators",
     "group_by": "region", "window_min": 60,
     "why": "Someone was given full admin rights on this PC."},
    {"id": "win-log-cleared", "name": "Windows event log cleared", "severity": 8, "credibility": 9,
     "source": "windows", "actions": None, "outcome": None,
     "where": lambda e: (_x(e).get("log") == "Security" and _x(e).get("event_id") == 1102)
     or (_x(e).get("log") == "System" and _x(e).get("event_id") == 104),
     "group_by": "region", "window_min": 60,
     "why": "Wiping the logs is how an attacker covers their tracks. Rare on a normal PC."},
    # ---- 2026-11-19 round 2: behaviour against a learned baseline (enrich.py)
    {"id": "aws-signin-new-country", "name": "Sign-in from a new country", "severity": 7, "credibility": 6,
     "source": "aws-cloudtrail", "actions": {"ConsoleLogin"}, "outcome": "success",
     "where": lambda e: _x(e).get("new_country") is True, "group_by": "actor", "window_min": 24 * 60,
     "why": "This person has signed in before, but never from this country. Travel or a VPN explains it; so does a stolen password."},
    {"id": "aws-new-network", "name": "Account used from a new network", "severity": 4, "credibility": 5,
     "source": "aws-cloudtrail", "actions": None, "outcome": "success",
     "where": lambda e: _x(e).get("new_network") is True and not _x(e).get("new_country"),
     "group_by": "actor", "window_min": 24 * 60,
     "why": "A user or key showed up from an internet line it has never used. Often a new Wi-Fi; sometimes a stolen key."},
    {"id": "aws-new-region", "name": "Activity in a new AWS region", "severity": 7, "credibility": 7,
     "source": "aws-cloudtrail", "actions": None, "outcome": "success",
     "where": lambda e: _x(e).get("new_region") is True, "group_by": "region", "window_min": 24 * 60,
     "why": "Something was created or changed in a region this account never uses. Attackers hide crypto miners there."},
    {"id": "corr-multi-rule", "name": "One entity tripped several rules", "severity": 8, "credibility": 7,
     "source": "watchtower", "actions": {"Correlated"}, "outcome": None, "group_by": "actor",
     "window_min": 24 * 60,
     "why": "Two or more different rules fired for the same user or address within a day. Read them together: it may be one story."},
    # ---- Watchtower watching itself (healthwatch.py writes these events)
    {"id": "wt-feed-silent", "name": "A log feed went silent", "severity": 7, "credibility": 10,
     "source": "watchtower", "actions": {"FeedSilent"}, "outcome": None, "group_by": "actor",
     "window_min": 24 * 60,
     "why": "A feed stopped delivering logs, so anything that happens there is invisible. Closes by itself when the feed is back."},
    {"id": "wt-aws-login-expired", "name": "AWS login expired", "severity": 5, "credibility": 10,
     "source": "watchtower", "actions": {"AwsLoginExpired"}, "outcome": None, "group_by": "actor",
     "window_min": 24 * 60,
     "why": "The read-only AWS sign-in timed out, so AWS data stopped. Run: aws sso login --profile siem-readonly. Closes by itself."},
]

# MITRE ATT&CK: the shared catalogue of attacker techniques. Every rule says which technique it would catch,
# so an offense reads in the same words a SOC or an interviewer uses. (technique id, technique name, tactic)
MITRE = {
    "aws-root-used": ("T1078.004", "Valid Accounts: Cloud Accounts", "Privilege Escalation"),
    "aws-console-login-no-mfa": ("T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access"),
    "aws-console-login-failures": ("T1110", "Brute Force", "Credential Access"),
    "aws-iam-change": ("T1098", "Account Manipulation", "Persistence"),
    "aws-cloudtrail-tamper": ("T1562.008", "Impair Defenses: Disable or Modify Cloud Logs", "Defense Evasion"),
    "aws-sg-open-world": ("T1562.007", "Impair Defenses: Disable or Modify Cloud Firewall", "Defense Evasion"),
    "aws-s3-public-block-changed": ("T1530", "Data from Cloud Storage", "Collection"),
    "aws-detection-disabled": ("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    "aws-guardduty-paused": ("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    "tailscale-new-device": ("T1133", "External Remote Services", "Initial Access"),
    "win-defender-detection": ("T1204", "User Execution", "Execution"),
    "win-defender-off": ("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    "posture-admin-no-mfa": ("T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access"),
    "posture-key-unused": ("T1552", "Unsecured Credentials", "Credential Access"),
    "posture-root": ("T1078.004", "Valid Accounts: Cloud Accounts", "Privilege Escalation"),
    "posture-sg-open": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "posture-no-trail": ("T1562.008", "Impair Defenses: Disable or Modify Cloud Logs", "Defense Evasion"),
    "aws-flow-port-scan": ("T1046", "Network Service Discovery", "Discovery"),
    "win-logon-failures": ("T1110", "Brute Force", "Credential Access"),
    "win-user-created": ("T1136.001", "Create Account: Local Account", "Persistence"),
    "win-admin-added": ("T1098", "Account Manipulation", "Privilege Escalation"),
    "win-log-cleared": ("T1070.001", "Indicator Removal: Clear Windows Event Logs", "Defense Evasion"),
    "aws-signin-new-country": ("T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access"),
    "aws-new-network": ("T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access"),
    "aws-new-region": ("T1535", "Unused/Unsupported Cloud Regions", "Defense Evasion"),
    "corr-multi-rule": ("", "Several techniques, one entity (correlation)", ""),
    "wt-feed-silent": ("T1562", "Impair Defenses (possible)", "Defense Evasion"),
    "wt-aws-login-expired": ("", "Not an attack: monitoring health", ""),
}
for _r in RULES:
    _r["mitre"] = MITRE.get(_r["id"], ("", "", ""))


def mitre_url(tid: str) -> str:
    """attack.mitre.org page for a technique id like T1562.008."""
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/" if tid else ""


def matches(rule: dict, e: dict) -> bool:
    if rule["source"] != e.get("source"):
        return False
    if rule.get("actions") is not None and e.get("action") not in rule["actions"]:
        return False
    if rule.get("outcome") and e.get("outcome") != rule["outcome"]:
        return False
    w = rule.get("where")
    return bool(w(e)) if w else True
