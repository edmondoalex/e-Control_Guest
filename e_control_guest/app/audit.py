from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SENSITIVE_FRAGMENTS = ("pin", "password", "token", "secret", "cookie", "authorization", "credential")


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if any(part in str(key).lower() for part in SENSITIVE_FRAGMENTS) else _sanitize(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class AuditLog:
    def __init__(self, database: Path, key: bytes):
        self.database = database
        self.key = key
        self._lock = threading.RLock()
        database.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    seq INTEGER PRIMARY KEY,
                    occurred_at TEXT NOT NULL,
                    actor_type TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                )
            """)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def append(self, *, actor_type: str, actor_id: str = "", session_id: str = "",
               action: str, resource: str = "", request_id: str = "", outcome: str,
               metadata: dict | None = None, occurred_at: str | None = None) -> dict:
        clean = _sanitize(metadata or {})
        timestamp = occurred_at or datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT seq, event_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            seq = (int(previous["seq"]) + 1) if previous else 1
            previous_hash = str(previous["event_hash"]) if previous else "0" * 64
            body = {
                "seq": seq,
                "occurred_at": timestamp,
                "actor_type": actor_type,
                "actor_id": actor_id,
                "session_id": session_id,
                "action": action,
                "resource": resource,
                "request_id": request_id,
                "outcome": outcome,
                "metadata": clean,
                "previous_hash": previous_hash,
            }
            event_hash = hmac.new(self.key, _canonical(body), hashlib.sha256).hexdigest()
            connection.execute(
                "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (seq, timestamp, actor_type, actor_id, session_id, action, resource,
                 request_id, outcome, json.dumps(clean, ensure_ascii=False, sort_keys=True,
                                                 separators=(",", ":")), previous_hash, event_hash),
            )
            connection.commit()
        return {**body, "event_hash": event_hash}

    def verify(self) -> tuple[bool, int | None]:
        previous_hash = "0" * 64
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()
        for expected_seq, row in enumerate(rows, 1):
            metadata = json.loads(row["metadata_json"])
            body = {
                "seq": row["seq"], "occurred_at": row["occurred_at"],
                "actor_type": row["actor_type"], "actor_id": row["actor_id"],
                "session_id": row["session_id"], "action": row["action"],
                "resource": row["resource"], "request_id": row["request_id"],
                "outcome": row["outcome"], "metadata": metadata,
                "previous_hash": row["previous_hash"],
            }
            calculated = hmac.new(self.key, _canonical(body), hashlib.sha256).hexdigest()
            if row["seq"] != expected_seq or row["previous_hash"] != previous_hash \
                    or not hmac.compare_digest(row["event_hash"], calculated):
                return False, int(row["seq"])
            previous_hash = row["event_hash"]
        return True, None

    def recent(self, limit: int = 200) -> list[dict]:
        limit = max(1, min(1000, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_events ORDER BY seq DESC LIMIT ?", (limit,)
            ).fetchall()
        return [{**dict(row), "metadata": json.loads(row["metadata_json"])} for row in rows]
