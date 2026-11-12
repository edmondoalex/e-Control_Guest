from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from contextlib import contextmanager
from contextvars import ContextVar
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
        self._request_origin = ContextVar("audit_request_origin", default=None)
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
        origin = self._request_origin.get()
        if origin is not None:
            clean["origin"] = dict(origin)
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
            connection.execute("BEGIN")
            return self._verify_connection(connection)

    def _verify_connection(self, connection) -> tuple[bool, int | None]:
        anchor_seq, previous_hash, anchor_valid = self._anchor(connection)
        if not anchor_valid:
            return False, anchor_seq
        rows = connection.execute("SELECT * FROM audit_events ORDER BY seq")
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

    @contextmanager
    def request_context(self, origin):
        token = self._request_origin.set(dict(origin))
        try:
            yield
        finally:
            self._request_origin.reset(token)

    def page(self, *, page=1, snapshot_seq=None, query="", labels_database=None,
             actions=(), outcomes=()):
        """Bounded read of all retained events; new appends do not shift pages."""
        with self._connect() as connection:
            labels_join, label_text = "", "''"
            if labels_database is not None:
                connection.execute("ATTACH DATABASE ? AS labels", (str(labels_database),))
                labels_join = (" LEFT JOIN labels.sessions s ON s.id=a.session_id AND a.actor_type='guest'"
                               " LEFT JOIN labels.shares h ON h.id=s.share_id")
                label_text = "COALESCE(h.label,'')"
            connection.execute("BEGIN")
            valid, broken_at = self._verify_connection(connection)
            newest = int(connection.execute("SELECT COALESCE(MAX(seq),0) FROM audit_events").fetchone()[0])
            snapshot_seq = newest if snapshot_seq is None else min(newest, max(0, int(snapshot_seq)))
            where, params = "a.seq<=?", [snapshot_seq]
            if query:
                connection.create_function("casefold", 1, lambda value: str(value or "").casefold(),
                                           deterministic=True)
                searchable = ("a.occurred_at||' '||a.actor_type||' '||a.actor_id||' '||a.session_id||' '||"
                              "a.action||' '||a.resource||' '||a.outcome||' '||a.metadata_json||' '||" + label_text)
                conditions = ["instr(casefold(" + searchable + "),?)>0"]
                params.append(query.casefold())
                for column, values in (("action", actions), ("outcome", outcomes)):
                    if values:
                        conditions.append("a." + column + " IN (" + ",".join("?" for _ in values) + ")")
                        params.extend(values)
                where += " AND (" + " OR ".join(conditions) + ")"
            base = " FROM audit_events a" + labels_join + " WHERE " + where
            count_base = base if query else " FROM audit_events a WHERE " + where
            total = int(connection.execute("SELECT COUNT(*)" + count_base, params).fetchone()[0])
            pages = max(1, (total + 99) // 100)
            page = max(1, min(pages, int(page)))
            rows = connection.execute("SELECT a.*," + label_text + " AS resolved_label" + base + " ORDER BY a.seq DESC LIMIT 100 OFFSET ?",
                                      [*params, (page - 1) * 100]).fetchall()
        events = []
        for row in rows:
            event = dict(row)
            label = event.pop("resolved_label", "")
            event["metadata"] = json.loads(event["metadata_json"])
            # Presentation-only enrichment, already used by RC34. Do not
            # rewrite the original JSON/hash or open one connection per row.
            if event["actor_type"] == "guest" and not event["metadata"].get("label") and label:
                event["metadata"]["label"] = label
            events.append(event)
        return {"events": events,
                "page": page, "pages": pages, "page_size": 100, "total": total,
                "snapshot_seq": snapshot_seq, "valid": valid, "broken_at": broken_at}
