"""Every Watchtower setting, read from the environment with a default.

The same code runs on this PC today and on a small AWS server later. Moving it
means changing env vars only (see README "Moving to AWS"), never code.
"""
from __future__ import annotations

import os
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _list(name: str, default: str) -> list[str]:
    return [x.strip() for x in _env(name, default).split(",") if x.strip()]


DEMO = _env("WATCHTOWER_DEMO", "1") == "1"     # 1 = fake demo data
DATA_DIR = Path(_env("WATCHTOWER_DATA", str(HERE / "data")))
DB_PATH = Path(_env("WATCHTOWER_DB", str(DATA_DIR / ("demo.db" if DEMO else "watchtower.db"))))

# Bind addresses: loopback + the PC's Tailscale IP, like the other apps. On AWS: the
# instance's private/Tailscale address. An address that is not up is skipped, not fatal.
BIND = _list("WATCHTOWER_BIND", "127.0.0.1")
PORT = int(_env("WATCHTOWER_PORT", "8778"))
SECURE_COOKIE = _env("WATCHTOWER_SECURE_COOKIE", "0") == "1"     # set to 1 behind HTTPS
SESSION_HOURS = int(_env("WATCHTOWER_SESSION_HOURS", "12"))

# AWS. On the PC: the read-only SSO profile. On EC2: leave AWS_PROFILE empty and the
# instance role is used. Never a write profile.
AWS_PROFILE = _env("WATCHTOWER_AWS_PROFILE", "siem-readonly") or None
AWS_REGION = _env("WATCHTOWER_AWS_REGION", "us-west-2")
# lookup-events is regional; IAM and sign-in events are recorded in us-east-1.
CLOUDTRAIL_REGIONS = _list("WATCHTOWER_CLOUDTRAIL_REGIONS", "us-west-2,us-east-1")
CLOUDTRAIL_BACKFILL_DAYS = int(_env("WATCHTOWER_BACKFILL_DAYS", "7"))
LOG_BUCKET = _env("WATCHTOWER_LOG_BUCKET", "example-security-logs-111122223333")
AWS_ACCOUNT_ID = _env("WATCHTOWER_AWS_ACCOUNT", "111122223333")

# Collectors to run. On AWS drop "windows" and "tailscale" (they read this PC).
COLLECTORS = _list("WATCHTOWER_COLLECTORS", "cloudtrail,posture,windows,tailscale,s3logs")
INTERVALS = {                      # seconds
    "cloudtrail": int(_env("WATCHTOWER_EVERY_CLOUDTRAIL", "300")),
    "posture": int(_env("WATCHTOWER_EVERY_POSTURE", str(6 * 3600))),
    "windows": int(_env("WATCHTOWER_EVERY_WINDOWS", "300")),
    "tailscale": int(_env("WATCHTOWER_EVERY_TAILSCALE", "120")),
    "s3logs": int(_env("WATCHTOWER_EVERY_S3LOGS", "900")),
}

WINDOWS_LOGS = _list("WATCHTOWER_WINDOWS_LOGS",
                     "Security,System,Microsoft-Windows-Windows Defender/Operational,"
                     "Microsoft-Windows-PowerShell/Operational,"
                     "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall")
WINDOWS_BACKFILL_HOURS = int(_env("WATCHTOWER_WINDOWS_BACKFILL_HOURS", "48"))
WINDOWS_MAX_PER_RUN = int(_env("WATCHTOWER_WINDOWS_MAX", "2000"))
# Discord pings for new serious offenses (notify.py). The webhook URL is in data/discord_webhook.txt only.
DISCORD_PINGS = _env("WATCHTOWER_DISCORD", "0" if DEMO else "1") == "1"
DISCORD_MENTION = _env("WATCHTOWER_DISCORD_MENTION", "")   # Discord user id to tag at magnitude 9+, optional
# The address links in pings point at (the tailnet HTTPS name on this PC; the server's own name on AWS).
PUBLIC_URL = _env("WATCHTOWER_PUBLIC_URL", "http://127.0.0.1:8778").rstrip("/")
TAILSCALE_BIN = _env("WATCHTOWER_TAILSCALE", r"C:\Program Files\Tailscale\tailscale.exe")

# Entities that matter more raise an offense's relevance (magnitude input).
IMPORTANT_ENTITIES = {x.lower() for x in _list("WATCHTOWER_IMPORTANT", "root,admin")}

RAW_MAX = 8000                     # bytes of raw JSON kept per event
