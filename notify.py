"""Discord pings for serious offenses (the owner, 2026-11-18).

A new offense at magnitude PING_AT or more posts one short message to the #watchtower channel's webhook.
The message carries the offense title, entity, magnitude and a link, nothing else: no raw logs, IPs, ARNs
or key ids leave this machine. The owner is mentioned only at MENTION_AT or more, and allowed_mentions permits
exactly that one user id, so nothing in an offense title can turn into an @everyone.

Fire-and-forget: every send runs on a daemon thread with a short timeout and never raises into the
collectors. At most one message per offense and MAX_PER_HOUR in total; anything over that is folded into
one summary line on the next flush.

The webhook URL lives only in data/discord_webhook.txt (data/ is gitignored). Off switch:
WATCHTOWER_DISCORD=0.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
import urllib.request

import config

log = logging.getLogger("watchtower.notify")

PING_AT = 7
MENTION_AT = 9
MAX_PER_HOUR = 10
MENTION_USER = config.DISCORD_MENTION   # optional Discord user id
WEBHOOK_FILE = config.DATA_DIR / "discord_webhook.txt"
SENT_META = "notify_sent"          # offense ids already pinged
TIMES_META = "notify_times"        # send timestamps in the last hour
HELD_META = "notify_held"          # ids over the hourly cap, summarized next time
EXPIRY_META = "notify_aws_expired"


def webhook() -> str | None:
    if not config.DISCORD_PINGS:
        return None
    try:
        url = WEBHOOK_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return url if url.startswith("https://discord.com/api/webhooks/") else None


def clean(text: str) -> str:
    """No IPs, ARNs or access key ids in a message, whatever a title holds."""
    text = re.sub(r"arn:aws[\w:/.\-*]*", "[arn]", text)
    text = re.sub(r"\bA[KS]IA[0-9A-Z.]{4,}\b|\bAKIA\.\.\.\w+", "[key]", text)
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "[ip]", text)
    text = re.sub(r"\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){3,7}\b", "[ip]", text, flags=re.I)
    return text.replace("@", "@\u200b")[:300]


def _post(url: str, content: str, mention: bool) -> None:
    body = {"content": (f"<@{MENTION_USER}> " if mention and MENTION_USER else "") + content,
            "allowed_mentions": {"parse": [], "users": [MENTION_USER] if mention and MENTION_USER else []}}
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "Watchtower"})
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except Exception as exc:                       # noqa: BLE001
        log.warning("discord ping failed: %s", type(exc).__name__)


def send(content: str, mention: bool = False, wait: bool = False) -> bool:
    url = webhook()
    if not url:
        return False
    t = threading.Thread(target=_post, args=(url, content, mention), daemon=True)
    t.start()
    if wait:
        t.join(15)
    return True


def line(o: dict) -> str:
    title = (o.get("title") or "").split(": ")[0]
    return (f"Watchtower: {clean(title)} ({clean(str(o.get('entity') or ''))}), magnitude {o['magnitude']}. "
            f"{config.PUBLIC_URL}/offenses/{o['id']}")


def flush(store, sender=send) -> int:
    """Ping every queued offense that qualifies. Never raises. Returns the number of messages sent."""
    try:
        return _flush(store, sender)
    except Exception as exc:                       # noqa: BLE001
        log.warning("notify flush failed: %s: %s", type(exc).__name__, exc)
        return 0


def _flush(store, sender) -> int:
    queue = store.get("notify_queue", []) or []
    held = store.get(HELD_META, []) or []
    if not queue and not held:
        return 0
    store.put("notify_queue", [])
    if not webhook() and sender is send:
        return 0
    sent_ids = set(store.get(SENT_META, []) or [])
    now = time.time()
    times = [t for t in (store.get(TIMES_META, []) or []) if now - t < 3600]
    with store.db() as c:
        rows = [dict(r) for r in c.execute(
            f"SELECT * FROM offenses WHERE id IN ({','.join('?' * len(queue + held))})", queue + held)] if queue + held else []
    todo = sorted([o for o in rows if o["id"] not in sent_ids and o["status"] == "open" and o["magnitude"] >= PING_AT
                   and not o.get("drill")],                     # drills never ping
                  key=lambda o: -o["magnitude"])
    n = 0
    over = []
    for o in todo:
        if len(times) >= MAX_PER_HOUR - 1 and len(todo) - n > 1:
            over.append(o)                         # keep the last slot for one summary line
            continue
        if len(times) >= MAX_PER_HOUR:
            over.append(o)
            continue
        sender(line(o), o["magnitude"] >= MENTION_AT)
        times.append(now)
        sent_ids.add(o["id"])
        n += 1
    if over and len(times) < MAX_PER_HOUR:
        top = max(o["magnitude"] for o in over)
        sender(f"Watchtower: {len(over)} more new offenses (highest magnitude {top}). {config.PUBLIC_URL}/offenses",
               top >= MENTION_AT)
        times.append(now)
        sent_ids |= {o["id"] for o in over}
        n += 1
        over = []
    store.put(HELD_META, [o["id"] for o in over])
    store.put(SENT_META, sorted(sent_ids)[-2000:])
    store.put(TIMES_META, times)
    return n


def aws_login(store, expired: bool, sender=send) -> None:
    """One ping when the AWS login expires, none again until it has worked once in between."""
    try:
        was = bool(store.get(EXPIRY_META, False))
        if expired and not was:
            sender("Watchtower: the AWS login expired, so AWS data has stopped. On the PC run: "
                   "aws sso login --profile siem-readonly", False)
            store.put(EXPIRY_META, True)
        elif not expired and was:
            store.put(EXPIRY_META, False)
    except Exception as exc:                       # noqa: BLE001
        log.warning("notify aws_login failed: %s", type(exc).__name__)


# ---------------------------------------------------------------- morning summary (2026-11-19)
DIGEST_META = "digest_last"
DIGEST_HOUR = int(__import__("os").environ.get("WATCHTOWER_DIGEST_HOUR", "8"))


def digest_text(store, now: float | None = None) -> str:
    """One message: what happened in the last 24 h, what is still open, and whether every feed is delivering."""
    now = now or time.time()
    with store.db() as c:
        new = c.execute("SELECT COUNT(*), MAX(magnitude) FROM offenses WHERE drill='' AND first_seen >= ?", (now - 86400,)).fetchone()
        auto = c.execute("SELECT COUNT(*) FROM offenses WHERE drill='' AND status='closed' AND closed_at >= ?", (now - 86400,)).fetchone()[0]
        opened = [dict(r) for r in c.execute("SELECT id, title, entity, magnitude FROM offenses WHERE status='open' AND drill='' "
                                             "ORDER BY magnitude DESC, last_seen DESC")]
        feeds = [dict(r) for r in c.execute("SELECT name, status, detail FROM collector_health ORDER BY name")]
    hi = sum(1 for o in opened if o["magnitude"] >= PING_AT)
    bad = [f for f in feeds if f["status"] != "ok" and f["name"] in config.COLLECTORS]
    day = time.strftime("%b %d", time.localtime(now)).replace(" 0", " ")
    lines = [f"**Watchtower morning summary, {day}**",
             f"- New offenses in the last 24 h: {new[0]}" + (f" (highest magnitude {new[1]})" if new[0] else ""),
             f"- Closed in the last 24 h: {auto}",
             f"- Still open: {len(opened)}" + (f", {hi} at magnitude {PING_AT}+" if hi else "")]
    if bad:
        why = lambda f: "AWS login expired" if "login expired" in (f["detail"] or "").lower() else "not delivering"
        lines.append("- Feeds down: " + ", ".join(f"{f['name']} ({why(f)})" for f in bad))
    else:
        lines.append("- Feeds: all delivering")
    for o in opened[:3]:
        lines.append(f"  - {clean((o['title'] or '').split(': ')[0])} ({clean(str(o['entity']))}), magnitude {o['magnitude']}")
    lines.append(f"{config.PUBLIC_URL}/offenses")
    return "\n".join(lines)[:1900]


def digest(store, sender=send, now: float | None = None) -> bool:
    """Send the summary once a day, between DIGEST_HOUR and four hours after (the PC may be off at 8).
    Never raises. Returns True when it sent."""
    try:
        now = now or time.time()
        lt = time.localtime(now)
        today = time.strftime("%Y-%m-%d", lt)
        if not (DIGEST_HOUR <= lt.tm_hour < DIGEST_HOUR + 4) or store.get(DIGEST_META) == today:
            return False
        if sender is send and not webhook():
            return False
        store.put(DIGEST_META, today)
        sender(digest_text(store, now), False)
        return True
    except Exception as exc:                       # noqa: BLE001
        log.warning("digest failed: %s: %s", type(exc).__name__, exc)
        return False
