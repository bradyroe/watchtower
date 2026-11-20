"""Logs delivered to the security log bucket: CloudTrail files and VPC flow logs.

Needs s3:ListBucket + s3:GetObject on the log bucket, which the read-only role does not have yet
(aws/readonly-logbucket-policy.json is what to add). Until then this records "waiting for access"
and does nothing else. When access works it reads new objects since the last run.
Flow logs: only REJECT records become events (the accepted traffic is counted, not stored).
"""
from __future__ import annotations

import gzip
import json

import config
import normalize
from collectors import awsutil

NAME = "s3logs"
WAITING = "Waiting for read access to the log bucket (see aws/readonly-logbucket-policy.json)"
MAX_OBJECTS = 200


def run(store, sess=None) -> int:
    try:
        s3 = (sess or awsutil.session()).client("s3")
        added, read, accepted = 0, 0, 0
        for prefix in (f"cloudtrail/AWSLogs/{config.AWS_ACCOUNT_ID}/", f"flowlogs/AWSLogs/{config.AWS_ACCOUNT_ID}/"):
            key = f"s3_after:{prefix}"
            after = store.get(key) or ""
            kw = {"Bucket": config.LOG_BUCKET, "Prefix": prefix, "MaxKeys": MAX_OBJECTS}
            if after:
                kw["StartAfter"] = after
            objs = s3.list_objects_v2(**kw).get("Contents", [])
            for o in objs:
                body = s3.get_object(Bucket=config.LOG_BUCKET, Key=o["Key"])["Body"].read()
                text = gzip.decompress(body).decode("utf-8", "replace") if o["Key"].endswith(".gz") else body.decode()
                if prefix.startswith("cloudtrail"):
                    evs = [normalize.cloudtrail(r) for r in json.loads(text).get("Records", [])]
                else:
                    evs = []
                    for line in text.splitlines():
                        e = normalize.flowlog(line)
                        if e and e["action"] == "REJECT":
                            evs.append(e)
                        elif e:
                            accepted += 1
                added += store.add_events(evs)
                read += 1
                store.put(key, o["Key"])
        store.health(NAME, True, f"{read} log files read, {accepted} accepted flows counted", added)
        return added
    except Exception as exc:                       # noqa: BLE001
        msg = awsutil.explain(exc)
        store.health(NAME, False, WAITING if "AccessDenied" in msg else msg)
        return 0
