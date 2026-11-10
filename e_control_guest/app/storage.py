from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from .crypto import hash_pin, new_share_token, token_digest, verify_pin


def _now() -> float:
    return time.time()


class StoreError(RuntimeError):
    pass


class GuestStore:
    def __init__(self, database: Path, token_key: bytes):
        self.database = database
        self.token_key = token_key
        self._lock = threading.RLock()
        database.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript("""
                PRAGMA foreign_keys=ON;
                CREATE TABLE IF NOT EXISTS profiles (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, active INTEGER NOT NULL,
                    revision INTEGER NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cards (
                    id TEXT PRIMARY KEY, profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
                    title TEXT NOT NULL, source_ref TEXT NOT NULL, source_hash TEXT NOT NULL,
                    config_json TEXT NOT NULL, permissions_json TEXT NOT NULL,
                    created_at REAL NOT NULL, updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS shares (
                    id TEXT PRIMARY KEY, profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
                    token_digest TEXT NOT NULL UNIQUE, pin_hash TEXT, enabled INTEGER NOT NULL, label TEXT NOT NULL DEFAULT '',
                    expires_at REAL NOT NULL, max_sessions INTEGER NOT NULL,
                    profile_revision INTEGER NOT NULL, created_at REAL NOT NULL,
                    revoked_reason TEXT NOT NULL DEFAULT '', revoked_by TEXT NOT NULL DEFAULT '', revoked_at REAL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
                    profile_id TEXT NOT NULL, profile_revision INTEGER NOT NULL,
                    csrf_digest TEXT NOT NULL, device_digest TEXT NOT NULL,
                    expires_at REAL NOT NULL, revoked INTEGER NOT NULL,
                    created_at REAL NOT NULL, last_seen_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS operations (
                    request_id TEXT PRIMARY KEY, session_id TEXT NOT NULL,
                    created_at REAL NOT NULL, result_json TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_cards_profile ON cards(profile_id);
                CREATE INDEX IF NOT EXISTS ix_sessions_share ON sessions(share_id, expires_at);
            """)
            columns = {row[1] for row in connection.execute("PRAGMA table_info(shares)")}
            if "label" not in columns:
                connection.execute("ALTER TABLE shares ADD COLUMN label TEXT NOT NULL DEFAULT ''")
            if "revoked_reason" not in columns:
                connection.execute("ALTER TABLE shares ADD COLUMN revoked_reason TEXT NOT NULL DEFAULT ''")
            if "revoked_by" not in columns:
                connection.execute("ALTER TABLE shares ADD COLUMN revoked_by TEXT NOT NULL DEFAULT ''")
            if "revoked_at" not in columns:
                connection.execute("ALTER TABLE shares ADD COLUMN revoked_at REAL")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict | None:
        return dict(row) if row is not None else None

    def create_profile(self, name: str) -> dict:
        name = name.strip()
        if not 1 <= len(name) <= 100:
            raise ValueError("Nome profilo non valido")
        profile_id, now = str(uuid.uuid4()), _now()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO profiles VALUES (?,?,?,?,?,?)",
                (profile_id, name, 1, 1, now, now),
            )
        return self.get_profile(profile_id)

    def get_profile(self, profile_id: str) -> dict:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        if row is None:
            raise KeyError(profile_id)
        return dict(row)

    def list_profiles(self) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM profiles ORDER BY name COLLATE NOCASE").fetchall()
        return [dict(row) for row in rows]

    def set_profile_active(self, profile_id: str, active: bool) -> dict:
        now = _now()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE profiles SET active=?, revision=revision+1, updated_at=? WHERE id=?",
                (1 if active else 0, now, profile_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(profile_id)
            connection.execute(
                "UPDATE sessions SET revoked=1 WHERE profile_id=?", (profile_id,)
            )
            connection.commit()
        return self.get_profile(profile_id)

    def add_card(self, profile_id: str, snapshot: dict) -> dict:
        required = {"source_ref", "source_hash", "title", "type", "appearance", "entities", "permissions"}
        if not isinstance(snapshot, dict) or set(snapshot) != required:
            raise ValueError("Snapshot card non valido")
        card_id, now = str(uuid.uuid4()), _now()
        config = {key: snapshot[key] for key in ("type", "appearance", "entities")}
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            profile = connection.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
            if profile is None or not profile["active"]:
                raise KeyError(profile_id)
            connection.execute(
                "INSERT INTO cards VALUES (?,?,?,?,?,?,?,?,?)",
                (card_id, profile_id, str(snapshot["title"])[:100], str(snapshot["source_ref"])[:300],
                 str(snapshot["source_hash"]), json.dumps(config, separators=(",", ":")),
                 json.dumps(snapshot["permissions"], separators=(",", ":")), now, now),
            )
            connection.execute(
                "UPDATE profiles SET revision=revision+1, updated_at=? WHERE id=?", (now, profile_id)
            )
            connection.commit()
        return self.get_card(card_id)

    def get_card(self, card_id: str) -> dict:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM cards WHERE id=?", (card_id,)).fetchone()
        if row is None:
            raise KeyError(card_id)
        value = dict(row)
        value["config"] = json.loads(value.pop("config_json"))
        value["permissions"] = json.loads(value.pop("permissions_json"))
        return value

    def delete_card(self, card_id: str) -> str:
        now = _now()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            card = connection.execute(
                "SELECT profile_id FROM cards WHERE id=?", (card_id,)
            ).fetchone()
            if card is None:
                raise KeyError(card_id)
            profile_id = str(card["profile_id"])
            connection.execute("DELETE FROM cards WHERE id=?", (card_id,))
            connection.execute(
                "UPDATE profiles SET revision=revision+1, updated_at=? WHERE id=?",
                (now, profile_id),
            )
            connection.execute(
                "UPDATE sessions SET revoked=1 WHERE profile_id=?", (profile_id,)
            )
            connection.commit()
        return profile_id

    def update_card_permissions(self, card_id: str, permissions: dict) -> dict:
        if not isinstance(permissions, dict):
            raise ValueError("Permessi non validi")
        now = _now()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            card = connection.execute("SELECT profile_id FROM cards WHERE id=?", (card_id,)).fetchone()
            if card is None:
                raise KeyError(card_id)
            connection.execute(
                "UPDATE cards SET permissions_json=?, updated_at=? WHERE id=?",
                (json.dumps(permissions, separators=(",", ":")), now, card_id),
            )
            connection.execute(
                "UPDATE profiles SET revision=revision+1, updated_at=? WHERE id=?",
                (now, card["profile_id"]),
            )
            connection.commit()
        return self.get_card(card_id)

    def update_profile_permissions(self, profile_id: str, cards: dict[str, dict]) -> dict:
        if not isinstance(cards, dict):
            raise ValueError("Permessi non validi")
        now = _now()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT id FROM cards WHERE profile_id=? ORDER BY created_at", (profile_id,)
            ).fetchall()
            if connection.execute("SELECT 1 FROM profiles WHERE id=?", (profile_id,)).fetchone() is None:
                raise KeyError(profile_id)
            card_ids = {str(row["id"]) for row in rows}
            if set(cards) != card_ids:
                raise ValueError("I permessi devono coprire esattamente tutte le schede del profilo")
            for card_id, permissions in cards.items():
                if not isinstance(permissions, dict):
                    raise ValueError("Permessi non validi")
                connection.execute(
                    "UPDATE cards SET permissions_json=?, updated_at=? WHERE id=?",
                    (json.dumps(permissions, separators=(",", ":")), now, card_id),
                )
            connection.execute(
                "UPDATE profiles SET revision=revision+1, updated_at=? WHERE id=?",
                (now, profile_id),
            )
            connection.commit()
        return self.dashboard(profile_id)

    def dashboard(self, profile_id: str) -> dict:
        profile = self.get_profile(profile_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM cards WHERE profile_id=? ORDER BY created_at", (profile_id,)
            ).fetchall()
        cards = []
        for row in rows:
            card = dict(row)
            cards.append({
                "id": card["id"], "title": card["title"],
                "source_hash": card["source_hash"],
                "config": json.loads(card["config_json"]),
                "permissions": json.loads(card["permissions_json"]),
            })
        return {"profile": profile, "cards": cards}

    def create_share(self, profile_id: str, *, label: str = "", pin: str | None, expires_at: float,
                     max_sessions: int = 1) -> tuple[dict, str]:
        profile = self.get_profile(profile_id)
        if not profile["active"] or expires_at <= _now():
            raise ValueError("Scadenza condivisione non valida")
        if not 1 <= int(max_sessions) <= 20:
            raise ValueError("Numero sessioni non valido")
        label = label.strip()
        if not 1 <= len(label) <= 100:
            raise ValueError("Nome ospite o descrizione non validi")
        raw_token = new_share_token()
        share_id, now = str(uuid.uuid4()), _now()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO shares (id,profile_id,token_digest,pin_hash,enabled,label,expires_at,max_sessions,profile_revision,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (share_id, profile_id, token_digest(self.token_key, raw_token), hash_pin(pin),
                 1, label, float(expires_at), int(max_sessions), int(profile["revision"]), now),
            )
        return self.get_share(share_id), raw_token

    def token_fingerprint(self, raw_token: str) -> str:
        """Stable keyed identifier for throttling; never returns the token or its raw hash."""
        return token_digest(self.token_key, raw_token)[:24]

    def get_share(self, share_id: str) -> dict:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT id,profile_id,enabled,label,expires_at,max_sessions,profile_revision,created_at,revoked_reason,revoked_by,revoked_at "
                "FROM shares WHERE id=?", (share_id,),
            ).fetchone()
        if row is None:
            raise KeyError(share_id)
        return dict(row)

    def list_shares(self, profile_id: str | None = None) -> list[dict]:
        query = (
            "SELECT s.id,s.profile_id,s.enabled,s.label,s.expires_at,s.max_sessions,s.profile_revision,s.created_at,"
            "s.revoked_reason,s.revoked_by,s.revoked_at,(s.profile_revision=p.revision) AS revision_valid "
            "FROM shares s JOIN profiles p ON p.id=s.profile_id"
        )
        args: tuple = ()
        if profile_id:
            query += " WHERE s.profile_id=?"
            args = (profile_id,)
        query += " ORDER BY s.created_at DESC"
        with self._connect() as connection:
            rows = connection.execute(query, args).fetchall()
        return [dict(row) for row in rows]

    def authenticate_share(self, raw_token: str, pin: str | None, *, csrf_token: str,
                           device_token: str, lifetime_seconds: int) -> dict:
        digest, now = token_digest(self.token_key, raw_token), _now()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            share = connection.execute("SELECT * FROM shares WHERE token_digest=?", (digest,)).fetchone()
            if share is None or not share["enabled"] or share["expires_at"] <= now:
                raise StoreError("share_unavailable")
            profile = connection.execute("SELECT * FROM profiles WHERE id=?", (share["profile_id"],)).fetchone()
            if profile is None or not profile["active"] or profile["revision"] != share["profile_revision"]:
                raise StoreError("share_revision_pending")
            if not verify_pin(share["pin_hash"], pin):
                raise StoreError("invalid_pin")
            active = connection.execute(
                "SELECT COUNT(*) FROM sessions WHERE share_id=? AND revoked=0 AND expires_at>?",
                (share["id"], now),
            ).fetchone()[0]
            if active >= share["max_sessions"]:
                raise StoreError("session_limit")
            session_id = str(uuid.uuid4())
            expires_at = min(float(share["expires_at"]), now + int(lifetime_seconds))
            connection.execute(
                "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?)",
                (session_id, share["id"], profile["id"], profile["revision"],
                 token_digest(self.token_key, csrf_token), token_digest(self.token_key, device_token),
                 expires_at, 0, now, now),
            )
            connection.commit()
        return {
            "id": session_id, "share_id": share["id"], "profile_id": profile["id"],
            "profile_revision": profile["revision"], "expires_at": expires_at,
        }

    def validate_session(self, session_id: str, share_id: str, profile_id: str, revision: int,
                         csrf_token: str | None = None, device_token: str | None = None) -> dict:
        now = _now()
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            profile = connection.execute("SELECT revision,active FROM profiles WHERE id=?", (profile_id,)).fetchone()
        if row is None or row["revoked"] or row["expires_at"] <= now:
            raise StoreError("session_unavailable")
        if row["share_id"] != share_id or row["profile_id"] != profile_id \
                or row["profile_revision"] != revision or profile is None \
                or not profile["active"] or profile["revision"] != revision:
            raise StoreError("session_revision_mismatch")
        if csrf_token is not None and token_digest(self.token_key, csrf_token) != row["csrf_digest"]:
            raise StoreError("csrf_failed")
        if device_token is not None and token_digest(self.token_key, device_token) != row["device_digest"]:
            raise StoreError("device_mismatch")
        with self._connect() as connection:
            connection.execute("UPDATE sessions SET last_seen_at=? WHERE id=?", (now, session_id))
        return dict(row)

    def share_label_for_session(self, session_id: str) -> str:
        if not session_id:
            return ""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT s.label FROM sessions x JOIN shares s ON s.id=x.share_id WHERE x.id=?",
                (session_id,),
            ).fetchone()
        return str(row["label"]) if row is not None else ""

    def claim_operation(self, request_id: str, session_id: str) -> bool:
        try:
            uuid.UUID(request_id)
        except ValueError as exc:
            raise ValueError("request_id non valido") from exc
        with self._connect() as connection:
            try:
                connection.execute(
                    "INSERT INTO operations VALUES (?,?,?,NULL)", (request_id, session_id, _now())
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def finish_operation(self, request_id: str, result: dict) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE operations SET result_json=? WHERE request_id=?",
                (json.dumps(result, separators=(",", ":")), request_id),
            )

    def operation_result(self, request_id: str) -> dict | None:
        with self._connect() as connection:
            row = connection.execute("SELECT result_json FROM operations WHERE request_id=?", (request_id,)).fetchone()
        return json.loads(row["result_json"]) if row and row["result_json"] else None

    def revoke_share(self, share_id: str, *, reason: str, actor_id: str) -> None:
        reason = reason.strip()
        if not 3 <= len(reason) <= 200:
            raise ValueError("Motivazione revoca non valida")
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE shares SET enabled=0,revoked_reason=?,revoked_by=?,revoked_at=? WHERE id=?",
                (reason, actor_id, _now(), share_id),
            )
            connection.execute("UPDATE sessions SET revoked=1 WHERE share_id=?", (share_id,))
            connection.commit()

    def revoke_session(self, session_id: str) -> None:
        with self._connect() as connection:
            connection.execute("UPDATE sessions SET revoked=1 WHERE id=?", (session_id,))
