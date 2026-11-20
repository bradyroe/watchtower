import normalize

CT = {"eventVersion": "1.08", "eventID": "abc-1", "eventTime": "2026-11-18T21:33:00Z", "eventSource": "signin.amazonaws.com",
      "eventName": "ConsoleLogin", "awsRegion": "us-east-1", "sourceIPAddress": "198.51.100.5",
      "userIdentity": {"type": "IAMUser", "userName": "dana", "arn": "arn:aws:iam::1:user/dana"},
      "responseElements": {"ConsoleLogin": "Success"}, "additionalEventData": {"MFAUsed": "No"}}


def test_cloudtrail_console_login():
    e = normalize.cloudtrail(CT)
    assert e["uid"] == "ct:abc-1" and e["source"] == "aws-cloudtrail" and e["category"] == "authentication"
    assert e["action"] == "ConsoleLogin" and e["outcome"] == "success" and e["actor"] == "dana"
    assert e["src_ip"] == "198.51.100.5" and e["extra"]["mfa_used"] == "No"
    assert abs(e["ts"] - 1795037580.0) < 1


def test_cloudtrail_failure_root_and_assumed_role():
    f = normalize.cloudtrail({**CT, "eventID": "x", "responseElements": {"ConsoleLogin": "Failure"}})
    assert f["outcome"] == "failure"
    r = normalize.cloudtrail({**CT, "eventID": "y", "userIdentity": {"type": "Root", "arn": "arn:aws:iam::1:root"}})
    assert r["actor"] == "root" and r["extra"]["identity_type"] == "Root"
    a = normalize.cloudtrail({**CT, "eventID": "z", "eventName": "CreateAccessKey", "errorCode": "AccessDenied",
                              "eventSource": "iam.amazonaws.com", "requestParameters": {"userName": "erin"},
                              "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/AWSReservedSSO_X/frank"}})
    assert a["actor"] == "frank" and a["outcome"] == "failure" and a["target"] == "erin" and a["category"] == "iam"


def test_windows_event():
    xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender'/>"
           "<EventID>1116</EventID><Level>3</Level><TimeCreated SystemTime='2026-11-18T21:25:23.8679123Z'/>"
           "<EventRecordID>42</EventRecordID></System><EventData><Data Name='Threat Name'>Trojan:Win32/Test</Data></EventData></Event>")
    e = normalize.windows(xml, "Microsoft-Windows-Windows Defender/Operational")
    assert e["uid"].endswith(":42") and e["category"] == "defender" and e["extra"]["event_id"] == 1116
    assert e["target"] == "Trojan:Win32/Test" and e["outcome"] == "warning"
    assert normalize.windows("<not xml", "System") is None


def test_flowlog_and_tailscale():
    line = "2 111122223333 eni-1 203.0.113.9 172.31.0.5 51515 22 6 3 180 1795000000 1795000060 REJECT OK"
    e = normalize.flowlog(line)
    assert e["action"] == "REJECT" and e["outcome"] == "failure" and e["target"] == "172.31.0.5:22"
    assert normalize.flowlog("version account-id ...") is None
    t = normalize.tailscale("NewDevice", {"ID": "n1", "HostName": "laptop", "TailscaleIPs": ["100.1.2.3"], "OS": "linux"}, 10.0)
    assert t["actor"] == "laptop" and t["src_ip"] == "100.1.2.3"


def test_ssm_channel_actor_from_session_id():
    e = normalize.cloudtrail({"eventID": "s1", "eventTime": "2026-11-18T21:27:12Z", "eventSource": "ssm.amazonaws.com",
                              "eventName": "OpenDataChannel", "userIdentity": {"accountId": "1"},
                              "requestParameters": {"sessionId": "erin-abcdefghijklmnopqrstuvwxyz"}})
    assert e["actor"] == "erin" and e["category"] == "remote-access"
