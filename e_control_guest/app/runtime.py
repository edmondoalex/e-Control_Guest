from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from fastapi import Request

from .adapters import HassioAdapter
from .audit import AuditLog
from .crypto import SecretStore, SessionSigner
from .dashboard_client import HomeAssistantDashboardClient
from .rate_limit import SlidingWindowLimiter
from .settings import Settings
from .origin import request_origin
from .storage import GuestStore


@dataclass
class Runtime:
    settings: Settings
    audit: AuditLog
    store: GuestStore
    signer: SessionSigner
    adapter: object
    dashboard_client: HomeAssistantDashboardClient
    limiter: SlidingWindowLimiter
    admin_csrf: str
    identity_key: bytes

    def request_origin(self, request: Request) -> dict:
        return request_origin(request, self.settings)

    def network_id(self, request: Request) -> str:
        client = self.request_origin(request)["client_ip"] or "unknown"
        return hmac.new(self.identity_key, client.encode("utf-8"), hashlib.sha256).hexdigest()[:24]

    def user_agent_id(self, request: Request) -> str:
        value = request.headers.get("user-agent", "")[:500]
        return hmac.new(self.identity_key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:24]


def build_runtime(settings: Settings | None = None, *, adapter: object | None = None) -> Runtime:
    settings = settings or Settings.load()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    secrets_store = SecretStore(settings.data_dir / "secrets")
    token_key = secrets_store.get("token-digest")
    return Runtime(
        settings=settings,
        audit=AuditLog(settings.data_dir / "audit.db", secrets_store.get("audit-chain"),
                       retention_days=settings.audit_retention_days,
                       max_events=settings.audit_max_events),
        store=GuestStore(settings.data_dir / "guest.db", token_key,
                         idle_seconds=settings.session_idle_minutes * 60),
        signer=SessionSigner(secrets_store.get("session-signing")),
        adapter=adapter or HassioAdapter(settings.supervisor_url, settings.supervisor_token),
        dashboard_client=HomeAssistantDashboardClient(settings.supervisor_url, settings.supervisor_token),
        limiter=SlidingWindowLimiter(),
        admin_csrf=secrets.token_urlsafe(32),
        identity_key=secrets_store.get("identity-hmac"),
    )
