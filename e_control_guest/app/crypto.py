from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError


_PIN_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class SecretStore:
    def __init__(self, directory: Path):
        self.directory = directory

    def get(self, name: str, size: int = 32) -> bytes:
        if not name.replace("-", "").isalnum():
            raise ValueError("invalid secret name")
        path = self.directory / f"{name}.key"
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            value = path.read_bytes()
        except FileNotFoundError:
            value = secrets.token_bytes(size)
            temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
            with temporary.open("xb") as file:
                os.chmod(temporary, 0o600)
                file.write(value)
                file.flush()
                os.fsync(file.fileno())
            try:
                temporary.replace(path)
            finally:
                temporary.unlink(missing_ok=True)
        if len(value) < size:
            raise RuntimeError(f"secret {name} is invalid")
        return value


def new_share_token() -> str:
    return b64url(secrets.token_bytes(32))


def recoverable_share_token(key: bytes, share_id: str) -> str:
    """Derive an unguessable token that can be reconstructed only with the local secret."""
    return b64url(hmac.new(key, f"share-token-v1:{share_id}".encode("utf-8"), hashlib.sha256).digest())


def token_digest(key: bytes, token: str) -> str:
    return hmac.new(key, token.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_pin(pin: str | None) -> str | None:
    if pin is None or pin == "":
        return None
    if not pin.isdigit() or not 4 <= len(pin) <= 12:
        raise ValueError("Il PIN deve contenere da 4 a 12 cifre")
    return _PIN_HASHER.hash(pin)


def verify_pin(pin_hash: str | None, pin: str | None) -> bool:
    if pin_hash is None:
        return pin in {None, ""}
    if pin is None:
        return False
    try:
        return _PIN_HASHER.verify(pin_hash, pin)
    except (VerifyMismatchError, InvalidHashError):
        return False


class SessionSigner:
    def __init__(self, key: bytes):
        self.key = key

    def issue(self, *, session_id: str, share_id: str, profile_id: str, revision: int,
              lifetime_seconds: int) -> str:
        now = int(time.time())
        payload = {
            "v": 1,
            "sid": session_id,
            "sh": share_id,
            "pr": profile_id,
            "rev": int(revision),
            "iat": now,
            "exp": now + lifetime_seconds,
            "nonce": b64url(secrets.token_bytes(12)),
        }
        encoded = b64url(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        signature = b64url(hmac.new(self.key, encoded.encode("ascii"), hashlib.sha256).digest())
        return f"{encoded}.{signature}"

    def verify(self, token: str, *, now: int | None = None) -> dict:
        try:
            encoded, signature = token.split(".", 1)
            expected = b64url(hmac.new(self.key, encoded.encode("ascii"), hashlib.sha256).digest())
            if not secrets.compare_digest(signature, expected):
                raise ValueError("invalid session signature")
            payload = json.loads(unb64url(encoded))
        except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("invalid session") from exc
        required = {"v", "sid", "sh", "pr", "rev", "iat", "exp", "nonce"}
        if set(payload) != required or payload["v"] != 1:
            raise ValueError("invalid session")
        current = int(time.time()) if now is None else int(now)
        if not isinstance(payload["exp"], int) or payload["exp"] <= current:
            raise ValueError("expired session")
        return payload
