from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    admin_port: int = 8099
    guest_port: int = 8100
    session_minutes: int = 30
    polling_seconds: int = 60
    audit_retention_days: int = 365
    guest_base_url: str = ""
    allow_insecure_local_http: bool = False
    trusted_proxy_cidrs: tuple[str, ...] = ()
    supervisor_url: str = "http://supervisor"
    supervisor_token: str = ""
    development_admin: bool = False

    @classmethod
    def load(cls) -> "Settings":
        data_dir = Path(os.environ.get("ECONTROL_GUEST_DATA_DIR", "/data"))
        options_path = Path(os.environ.get("ECONTROL_GUEST_OPTIONS", "/data/options.json"))
        try:
            options = json.loads(options_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            options = {}

        def bounded(name: str, default: int, low: int, high: int) -> int:
            try:
                value = int(options.get(name, default))
            except (TypeError, ValueError):
                value = default
            return max(low, min(high, value))

        return cls(
            data_dir=data_dir,
            guest_port=bounded("guest_port", 8100, 1024, 65535),
            session_minutes=bounded("session_minutes", 30, 5, 240),
            polling_seconds=bounded("polling_seconds", 60, 15, 3600),
            audit_retention_days=bounded("audit_retention_days", 365, 30, 3650),
            guest_base_url=str(options.get("guest_base_url", "")).strip().rstrip("/"),
            allow_insecure_local_http=options.get("allow_insecure_local_http") is True,
            trusted_proxy_cidrs=tuple(
                str(item).strip() for item in options.get("trusted_proxy_cidrs", [])
                if isinstance(item, str) and item.strip()
            ),
            supervisor_url=os.environ.get("SUPERVISOR_URL", "http://supervisor").rstrip("/"),
            supervisor_token=os.environ.get("SUPERVISOR_TOKEN", ""),
            development_admin=os.environ.get("ECONTROL_GUEST_DEV_ADMIN") == "1",
        )
