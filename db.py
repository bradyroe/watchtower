"""SQLite storage. One file, path from config. Safe across threads (one connection per call)."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uid TEXT UNIQUE NOT NULL,           -- dedupe id from the source
  ts REAL NOT NULL,                   -- epoch seconds, UTC
  source TEXT NOT NULL,               -- aws-cloudtrail, aws-posture, windows, tailscale, aws-flowlogs
  category TEXT NOT NULL,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL DEFAULT 'unknown',
  actor TEXT NOT NULL DEFAULT '',
  src_ip TEXT NOT NULL DEFAULT '',
  target TEXT NOT NULL DEFAULT '',
  region TEXT NOT NULL DEFAULT '',
  extra_json TEXT NOT NULL DEFAULT '{}',
  raw_json TEXT NOT NULL DEFAULT '{}',
  ingested REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ev_src ON events(source, ts);
CREATE INDEX IF NOT EXISTS ev_actor ON events(actor);
CREATE INDEX IF NOT EXISTS ev_ip ON events(src_ip);

CREATE TABLE IF NOT EXISTS rule_hits (
  rule_id TEXT NOT NULL, entity TEXT NOT NULL, event_id INTEGER NOT NULL, ts REAL NOT NULL,
  PRIMARY KEY (rule_id, event_id)
);
CREATE TABLE IF NOT EXISTS offenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id TEXT NOT NULL,
  entity TEXT NOT NULL,
  title TEXT NOT NULL,
  severity INTEGER NOT NULL,
  credibility INTEGER NOT NULL,
  relevance INTEGER NOT NULL,
  magnitude INTEGER NOT NULL,
  event_count INTEGER NOT NULL DEFAULT 0,
  first_seen REAL NOT NULL,
  last_seen REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',      -- open | closed
  assignee TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  closed_at REAL
);
CREATE INDEX IF NOT EXISTS off_key ON offenses(rule_id, entity, status);
CREATE TABLE IF NOT EXISTS offense_events (
  offense_id INTEGER NOT NULL, event_id INTEGER NOT NULL, PRIMARY KEY (offense_id, event_id)
);
CREATE TABLE IF NOT EXISTS findings (
  key TEXT PRIMARY KEY, kind TEXT NOT NULL, severity INTEGER NOT NULL, entity TEXT NOT NULL,
  title TEXT NOT NULL, detail TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS collector_health (
  name TEXT PRIMARY KEY, last_run REAL, last_ok REAL, status TEXT, detail TEXT, count_last INTEGER
);
CREATE TABLE IF NOT EXISTS rule_state (rule_id TEXT PRIMARY KEY, enabled INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
  name TEXT PRIMARY KEY, pw_hash TEXT NOT NULL, created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user TEXT NOT NULL, csrf TEXT NOT NULL, expires REAL NOT NULL, created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, user TEXT NOT NULL, ip TEXT NOT NULL,
  action TEXT NOT NULL, detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_fail (ip TEXT NOT NULL, ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS baseline (
  kind TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, first_seen REAL NOT NULL,
  PRIMARY KEY (kind, key, value)
);
CREATE TABLE IF NOT EXISTS custom_rules (
  id TEXT PRIMARY KEY, spec_json TEXT NOT NULL, author TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL
);
"""

# Columns added after the first release. ALTER TABLE ADD COLUMN is a no-op error when it already exists.
MIGRATIONS = [
    "ALTER TABLE offenses ADD COLUMN drill TEXT NOT NULL DEFAULT ''",       # drill scenario id; '' = real
    "ALTER TABLE offenses ADD COLUMN verdict TEXT NOT NULL DEFAULT ''",     # true-positive | false-positive | benign
    "ALTER TABLE offenses ADD COLUMN grade_json TEXT NOT NULL DEFAULT ''",  # drill grading result
]


class Store:
    def __init__(self, path: Path | str):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self.db() as c:
            c.executescript(SCHEMA)
            for m in MIGRATIONS:
                try:
                    c.execute(m)
                except sqlite3.OperationalError:
                    pass

    @contextmanager
    def db(self):
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        try:
            yield c
            c.commit()
        finally:
            c.close()

    # ---- events
    def add_events(self, events: list[dict]) -> int:
        """Insert normalized events; duplicates (same uid) are ignored. Returns new rows."""
        if not events:
            return 0
        now = time.time()
        rows = [(e["uid"], e["ts"], e["source"], e["category"], e["action"], e.get("outcome", "unknown"),
                 e.get("actor", ""), e.get("src_ip", ""), e.get("target", ""), e.get("region", ""),
                 json.dumps(e.get("extra", {}), default=str), e.get("raw_json", "{}"), now) for e in events]
        with self._lock, self.db() as c:
            before = c.total_changes
            c.executemany("INSERT OR IGNORE INTO events(uid,ts,source,category,action,outcome,actor,src_ip,"
                          "target,region,extra_json,raw_json,ingested) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            return c.total_changes - before

    def events_after(self, last_id: int, limit: int = 5000) -> list[dict]:
        with self.db() as c:
            return [dict(r) for r in c.execute("SELECT * FROM events WHERE id>? ORDER BY id LIMIT ?", (last_id, limit))]

    # ---- kv
    def get(self, k: str, default=None):
        with self.db() as c:
            r = c.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return json.loads(r["v"]) if r else default

    def put(self, k: str, v) -> None:
        with self.db() as c:
            c.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, json.dumps(v)))

    # ---- health
    def health(self, name: str, ok: bool, detail: str = "", count: int | None = None) -> None:
        now = time.time()
        with self.db() as c:
            c.execute("INSERT INTO collector_health(name,last_run,last_ok,status,detail,count_last) VALUES(?,?,?,?,?,?) "
                      "ON CONFLICT(name) DO UPDATE SET last_run=excluded.last_run, "
                      "last_ok=COALESCE(excluded.last_ok, collector_health.last_ok), status=excluded.status, "
                      "detail=excluded.detail, count_last=excluded.count_last",
                      (name, now, now if ok else None, "ok" if ok else "error", detail[:500], count))

    def audit(self, user: str, ip: str, action: str, detail: str = "") -> None:
        with self.db() as c:
            c.execute("INSERT INTO audit(ts,user,ip,action,detail) VALUES(?,?,?,?,?)",
                      (time.time(), user, ip, action, detail[:500]))
