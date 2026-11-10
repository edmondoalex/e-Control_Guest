from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
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
    def __init__(self, database: Path, key: bytes, *, retention_days: int = 365,
                 max_events: int = 100_000):
        self.database = database
        self.key = key
        self.retention_days = max(1, int(retention_days))
        self.max_events = max(1000, int(max_events))
        self._lock = threading.RLock()
        self._maintenance_day = ""
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
            connection.execute("""
                CREATE TABLE IF NOT EXISTS audit_anchor (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    seq INTEGER NOT NULL, event_hash TEXT NOT NULL, signature TEXT NOT NULL
                )
            """)
            row = connection.execute(
                "SELECT 1 FROM audit_anchor WHERE singleton=1"
            ).fetchone()
            if row is None:
                anchor_hash = "0" * 64
                connection.execute(
                    "INSERT INTO audit_anchor VALUES (1,0,?,?)",
                    (anchor_hash, self._anchor_signature(0, anchor_hash)),
                )
        self.prune()

    def _anchor_signature(self, seq: int, event_hash: str) -> str:
        value = f"audit-anchor:{int(seq)}:{event_hash}".encode("utf-8")
        return hmac.new(self.key, value, hashlib.sha256).hexdigest()

    def _anchor(self, connection: sqlite3.Connection) -> tuple[int, str, bool]:
        row = connection.execute(
            "SELECT seq,event_hash,signature FROM audit_anchor WHERE singleton=1"
        ).fetchone()
        if row is None:
            return 0, "0" * 64, False
        seq, event_hash = int(row["seq"]), str(row["event_hash"])
        valid = hmac.compare_digest(
            str(row["signature"]), self._anchor_signature(seq, event_hash)
        )
        return seq, event_hash, valid

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def append(self, *, actor_type: str, actor_id: str = "", session_id: str = "",
               action: str, resource: str = "", request_id: str = "", outcome: str,
               metadata: dict | None = None, occurred_at: str | None = None) -> dict:
        today = datetime.now(timezone.utc).date().isoformat()
        if self._maintenance_day != today:
            self.prune()
        clean = _sanitize(metadata or {})
        timestamp = occurred_at or datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT seq, event_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if previous:
                seq = int(previous["seq"]) + 1
                previous_hash = str(previous["event_hash"])
            else:
                anchor_seq, previous_hash, anchor_valid = self._anchor(connection)
                if not anchor_valid:
                    raise RuntimeError("Audit anchor non valido")
                seq = anchor_seq + 1
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
        with self._connect() as connection:
            anchor_seq, previous_hash, anchor_valid = self._anchor(connection)
            if not anchor_valid:
                return False, anchor_seq
            rows = connection.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()
        for expected_seq, row in enumerate(rows, anchor_seq + 1):
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

    def prune(self) -> dict:
        """Remove the expired prefix while preserving a signed HMAC chain anchor."""
        with self._lock:
            valid, broken_at = self.verify()
            if not valid:
                return {"deleted": 0, "skipped": True, "broken_at": broken_at}
            cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).isoformat()
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                total = int(connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0])
                by_age = connection.execute(
                    "SELECT seq,event_hash FROM audit_events WHERE occurred_at<? "
                    "ORDER BY seq DESC LIMIT 1", (cutoff,),
                ).fetchone()
                excess = max(0, total - self.max_events)
                by_count = None
                if excess:
                    by_count = connection.execute(
                        "SELECT seq,event_hash FROM audit_events ORDER BY seq LIMIT 1 OFFSET ?",
                        (excess - 1,),
                    ).fetchone()
                candidates = [row for row in (by_age, by_count) if row is not None]
                if not candidates:
                    connection.rollback()
                    self._maintenance_day = datetime.now(timezone.utc).date().isoformat()
                    return {"deleted": 0, "skipped": False, "broken_at": None}
                boundary = max(candidates, key=lambda row: int(row["seq"]))
                boundary_seq, boundary_hash = int(boundary["seq"]), str(boundary["event_hash"])
                deleted = int(connection.execute(
                    "SELECT COUNT(*) FROM audit_events WHERE seq<=?", (boundary_seq,),
                ).fetchone()[0])
                connection.execute("DELETE FROM audit_events WHERE seq<=?", (boundary_seq,))
                connection.execute(
                    "UPDATE audit_anchor SET seq=?,event_hash=?,signature=? WHERE singleton=1",
                    (boundary_seq, boundary_hash,
                     self._anchor_signature(boundary_seq, boundary_hash)),
                )
                connection.commit()
            with self._connect() as connection:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                connection.execute("VACUUM")
            self._maintenance_day = datetime.now(timezone.utc).date().isoformat()
            return {"deleted": deleted, "skipped": False, "broken_at": None}

    def stats(self) -> dict:
        with self._connect() as connection:
            count = int(connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0])
            anchor_seq, _, anchor_valid = self._anchor(connection)
        size = sum(
            path.stat().st_size for path in (
                self.database, Path(f"{self.database}-wal"), Path(f"{self.database}-shm")
            ) if path.exists()
        )
        return {"events": count, "archived_events": anchor_seq, "bytes": size,
                "retention_days": self.retention_days, "max_events": self.max_events,
                "anchor_valid": anchor_valid}

    def recent(self, limit: int = 200) -> list[dict]:
        limit = max(1, min(1000, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_events ORDER BY seq DESC LIMIT ?", (limit,)
            ).fetchall()
        return [{**dict(row), "metadata": json.loads(row["metadata_json"])} for row in rows]
