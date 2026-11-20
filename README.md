# Watchtower

A small SIEM for one AWS account, modeled on the core functions of IBM QRadar. It collects logs from
several sources, normalizes them into one event shape, runs detection rules tagged with MITRE ATT&CK
techniques, rolls matching events into offenses ranked by magnitude, correlates offenses across rules,
and shows everything in a web console. A training mode injects practice attacks so an analyst can
work real triage end to end.

Built with AI tools. I planned it, directed the build, and tested it. It runs against a real AWS account in
private use; this repository ships with fake demo data only.

## Run the demo

Demo mode is the default. It loads about 1,800 generated events (made-up users, RFC 5737 documentation
IP ranges, example account ids) and never contacts AWS.

```
python -m venv .venv
.venv/bin/pip install -r requirements.txt        # Windows: .venv\Scripts\pip
.venv/bin/python app.py
```

Open http://127.0.0.1:8778. On first start the server creates an `admin` login and writes the password
to `FIRST-LOGIN.txt` next to the `data/` folder. Tests: `python -m pytest -q`.

To monitor a real account, set `WATCHTOWER_DEMO=0` and point `WATCHTOWER_AWS_PROFILE` at a read-only
profile (see Security below).

## What it does

| Area | What it covers |
| --- | --- |
| Collectors | CloudTrail management events, AWS posture (IAM users, MFA, access keys, security groups, trails, S3 account block), VPC flow logs and trail files from S3, Windows event logs, Tailscale devices |
| Normalization | Every source becomes one event shape: time, source, category, action, outcome, actor, source IP, target, region |
| Rules | 28 built-in rules with severity, credibility, group-by, time window and threshold. Each carries a MITRE ATT&CK technique and tactic. A rule builder lets the analyst write and test custom rules against stored events |
| Offenses | Rule hits grouped per entity. Magnitude (1 to 10) combines severity, credibility and relevance, where relevance rises with event count and with entities marked important |
| Correlation | One entity tripping several rules opens a higher-level correlated offense |
| Baselines | Sign-in from a new country, use from a new network, activity in a new region, all learned from history first so the first sighting does not alert |
| Posture | Findings such as an admin without MFA or a stale access key open offenses and close on their own when the finding goes away |
| Self-monitoring | A silent log feed or an expired AWS session raises its own offense |
| Notifications | Optional Discord webhook for new offenses at magnitude 7 or more, with IPs, ARNs and key ids stripped before sending |
| Training | Drills inject realistic attack sequences (root use, trail tampering, port scans and more) that the normal rules turn into offenses. Drills are graded, never notify and never mix with real offenses. A Learn page and an analyst log support practice |

## Architecture

```
collectors/   one module per source; each records its own health
normalize.py  source record -> common event
db.py         SQLite schema and writes (WAL mode)
rules/        built-in rules with MITRE mapping; custom rules from the rule builder
engine.py     rules -> offenses, magnitude, correlation, posture auto-close
geo.py        offline IP-to-country lookup (DB-IP Lite file, downloaded into data/geo/)
queries.py    read side for the console
web.py        console: Python standard-library HTTP server, auth, CSRF, audit log
drills.py     practice attack scenarios; web_train.py and learn.py serve the training pages
notify.py     optional Discord pings
app.py        entry point and collector scheduler: serve, set-password, collect-once
demo.py       generated demo data
static/       CSS, JS, vendored uPlot and IBM Plex fonts (no CDN at runtime)
```

The only third-party Python dependency is `boto3`.

## Security

- **Read-only AWS access.** In live use the collectors run on an IAM Identity Center permission set
  made of the AWS managed `SecurityAudit` and `ViewOnlyAccess` policies, with short-lived SSO sessions
  and no stored access keys. `aws/readonly-logbucket-policy.json` is the one extra statement it needs:
  `s3:ListBucket` and `s3:GetObject` on the security log bucket.
- **Changes go through a separate role.** Watchtower never writes to AWS. Fixes to findings are made
  under a different permission set, one approved change at a time, and every call lands in CloudTrail.
- **Console.** One admin account, PBKDF2 password hash, hashed session tokens, login lockout, CSRF
  tokens on every form, and an audit log of console actions. Binds to 127.0.0.1 by default.
- **Data stays local.** Logs and the database stay in `data/`. Geo lookups use an offline file.
  Discord messages carry only a title, an entity and a link.

## Deploying to AWS

The same code runs on a small instance; only environment variables change.

1. An instance with no public IP, reached over a VPN such as Tailscale, with an instance role holding
   `SecurityAudit`, `ViewOnlyAccess` and the log bucket policy. No access keys.
2. `docker compose up -d --build`. The container runs as a non-root user and keeps its database in a volume.
3. Set `WATCHTOWER_DEMO=0`, `WATCHTOWER_LOG_BUCKET`, `WATCHTOWER_AWS_ACCOUNT` and
   `WATCHTOWER_SECURE_COOKIE=1` (behind HTTPS).
4. Run `python app.py set-password` inside the container once.

All settings are environment variables read in `config.py`.
