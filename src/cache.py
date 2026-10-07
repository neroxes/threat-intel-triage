"""SQLite cache so we never look up the same IP twice within the TTL."""
import json
import sqlite3
import time

from src import config


class Cache:
    def __init__(self, path=None, ttl_hours=None):
        self.path = str(path or config.CACHE_DB_PATH)
        self.ttl_seconds = (ttl_hours or config.CACHE_TTL_HOURS) * 3600
        self.conn = sqlite3.connect(self.path)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS lookups (
                   ip TEXT PRIMARY KEY,
                   data TEXT NOT NULL,
                   checked_at REAL NOT NULL
               )"""
        )
        self.conn.commit()

    def get(self, ip):
        """Return the cached result, or None if missing or expired."""
        row = self.conn.execute(
            "SELECT data, checked_at FROM lookups WHERE ip = ?", (ip,)
        ).fetchone()
        if row is None:
            return None
        data, checked_at = row
        if time.time() - checked_at > self.ttl_seconds:
            return None
        return json.loads(data)

    def set(self, ip, data):
        self.conn.execute(
            "INSERT OR REPLACE INTO lookups (ip, data, checked_at) VALUES (?, ?, ?)",
            (ip, json.dumps(data), time.time()),
        )
        self.conn.commit()

    def close(self):
        self.conn.close()
