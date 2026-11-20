"""AWS CloudTrail management events via lookup-events (90 days kept by AWS, read-only role allows it).

First run backfills config.CLOUDTRAIL_BACKFILL_DAYS; later runs start a few minutes before the
newest event already stored per region (lookup-events lags, and the uid dedupes the overlap).
"""
from __future__ import annotations

import datetime as dt
import json
import time

import config
import normalize
from collectors import awsutil

NAME = "cloudtrail"
OVERLAP = 15 * 60


def run(store, client_for=None) -> int:
    added, errors = 0, []
    try:
        sess = None if client_for else awsutil.session()
    except Exception as exc:                       # noqa: BLE001
        store.health(NAME, False, awsutil.explain(exc))
        return 0
    for region in config.CLOUDTRAIL_REGIONS:
        key = f"ct_since:{region}"
        since = store.get(key)
        start = (since - OVERLAP) if since else time.time() - config.CLOUDTRAIL_BACKFILL_DAYS * 86400
        try:
            client = client_for(region) if client_for else sess.client("cloudtrail", region_name=region)
            newest, batch = since or 0, []
            kwargs = {"StartTime": dt.datetime.fromtimestamp(start, dt.timezone.utc), "MaxResults": 50}
            while True:
                resp = client.lookup_events(**kwargs)
                for ev in resp.get("Events", []):
                    rec = json.loads(ev.get("CloudTrailEvent") or "{}")
                    if not rec:
                        continue
                    e = normalize.cloudtrail(rec)
                    newest = max(newest, e["ts"])
                    batch.append(e)
                if len(batch) >= 500:
                    added += store.add_events(batch)
                    batch = []
                tok = resp.get("NextToken")
                if not tok:
                    break
                kwargs["NextToken"] = tok
                time.sleep(0.55)                    # lookup-events allows 2 calls a second
            added += store.add_events(batch)
            if newest:
                store.put(key, newest)
        except Exception as exc:                   # noqa: BLE001
            errors.append(f"{region}: {awsutil.explain(exc)}")
    if errors:
        msg = errors[0] if all(awsutil.EXPIRED in e for e in errors) and len(errors) else "; ".join(errors)
        store.health(NAME, False, msg.replace(f"{config.CLOUDTRAIL_REGIONS[0]}: ", "") if awsutil.EXPIRED in msg else msg, added)
    else:
        store.health(NAME, True, f"{added} new events from {', '.join(config.CLOUDTRAIL_REGIONS)}", added)
    return added
