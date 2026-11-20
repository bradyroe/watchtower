"""Watchtower: our own SIEM. Collect, normalize, correlate into offenses, and show it.

  python app.py               serve the console and run the collectors on their intervals
  python app.py set-password  make (or reset) the admin login; writes FIRST-LOGIN.txt
  python app.py collect-once  run every collector once, then the rules, and print what happened
"""
from __future__ import annotations

import logging
import secrets
import sys
import threading
import time
from logging.handlers import RotatingFileHandler

import auth
import config
import db
import engine
import healthwatch
import notify
import web
from collectors import cloudtrail, posture, s3logs, tailscale, windows

MODULES = {"cloudtrail": cloudtrail, "posture": posture, "windows": windows, "tailscale": tailscale, "s3logs": s3logs}
log = logging.getLogger("watchtower")
LOCK = threading.Lock()


def setup_logging() -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    h = RotatingFileHandler(config.DATA_DIR / "watchtower.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[h])


def collect(store, name: str) -> int:
    with LOCK:                                      # one collector at a time; SQLite and AWS rate limits both like it
        try:
            n = MODULES[name].run(store)
        except Exception as exc:                    # noqa: BLE001
            store.health(name, False, f"{type(exc).__name__}: {exc}")
            log.exception("collector %s crashed", name)
            n = 0
        try:
            healthwatch.check(store)                # a silent feed becomes an offense; a recovered one closes it
        except Exception:                           # noqa: BLE001
            log.exception("healthwatch failed")
        hits = engine.process(store)
        log.info("%s: %d new events, %d rule hits", name, n, hits)
        if name in ("cloudtrail", "posture"):          # one ping when the AWS login lapses
            with store.db() as c:
                h = c.execute("SELECT status, detail FROM collector_health WHERE name=?", (name,)).fetchone()
            if h:
                notify.aws_login(store, h["status"] == "error" and "login expired" in (h["detail"] or "").lower())
        notify.flush(store)
        return n


def scheduler(store, stop: threading.Event) -> None:
    due = {name: 0.0 for name in config.COLLECTORS if name in MODULES}
    while not stop.is_set():
        now = time.time()
        for name, at in due.items():
            if now >= at:
                collect(store, name)
                due[name] = time.time() + config.INTERVALS.get(name, 300)
        notify.digest(store)                        # once a day at DIGEST_HOUR, never raises
        stop.wait(5)


def seed_demo(store) -> None:
    import demo
    if store.get("demo_seeded"):
        return
    store.add_events(demo.events())
    now = time.time()
    with store.db() as c:
        for f in demo.findings():
            c.execute("INSERT OR REPLACE INTO findings(key,kind,severity,entity,title,detail,first_seen,last_seen,active) "
                      "VALUES(?,?,?,?,?,?,?,?,1)", (f["key"], f["kind"], f["severity"], f["entity"], f["title"], f["detail"], now, now))
    for name in MODULES:
        store.health(name, True, "demo data")
    engine.process(store)
    store.put("demo_seeded", True)


def set_password(store) -> str:
    pw = "-".join(secrets.token_urlsafe(6) for _ in range(3))
    auth.set_password(store, "admin", pw)
    path = config.DATA_DIR.parent / "FIRST-LOGIN.txt"
    path.write_text(f"Watchtower sign-in\nURL: http://127.0.0.1:{config.PORT}\n"
                    f"User: admin\nPassword: {pw}\n\nDelete this file once the password is saved somewhere safe.\n"
                    f"Reset any time with: .venv\\Scripts\\python app.py set-password\n", encoding="utf-8")
    return str(path)


def main(argv: list[str]) -> int:
    setup_logging()
    store = db.Store(config.DB_PATH)
    cmd = argv[1] if len(argv) > 1 else "serve"
    if cmd == "set-password":
        print("written to", set_password(store))
        return 0
    if cmd == "collect-once":
        for name in config.COLLECTORS:
            if name in MODULES:
                n = collect(store, name)
                h = {r["name"]: r for r in __import__("queries").health(store)}.get(name, {})
                print(f"{name:11s} {h.get('status')!s:6s} +{n:<6d} {h.get('detail', '')}")
        return 0
    if not auth.has_user(store):
        set_password(store)
    servers = web.serve(store)
    log.info("serving on %s", [s.server_address for s in servers])
    if not servers:
        log.error("could not bind any address")
        return 1
    stop = threading.Event()
    if config.DEMO:
        seed_demo(store)
    else:
        threading.Thread(target=scheduler, args=(store, stop), daemon=True, name="scheduler").start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
