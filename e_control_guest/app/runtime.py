from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
from dataclasses import dataclass

from fastapi import Request

from .adapters import HassioAdapter
from .audit import AuditLog
from .crypto import SecretStore, SessionSigner
from .dashboard_client import HomeAssistantDashboardClient
from .rate_limit import SlidingWindowLimiter
from .settings import Settings
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

    def network_id(self, request: Request) -> str:
        address = request.client.host if request.client else "unknown"
        try:
            peer = ipaddress.ip_address(address)
            trusted = any(peer in ipaddress.ip_network(cidr, strict=False)
                          for cidr in self.settings.trusted_proxy_cidrs)
        except ValueError:
            trusted = False
        if trusted:
            forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
            try:
                address = str(ipaddress.ip_address(forwarded))
            except ValueError:
                pass
        return hmac.new(self.identity_key, address.encode("utf-8"), hashlib.sha256).hexdigest()[:24]

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
        store=GuestStore(settings.data_dir / "guest.db", token_key),
        signer=SessionSigner(secrets_store.get("session-signing")),
        adapter=adapter or HassioAdapter(settings.supervisor_url, settings.supervisor_token),
        dashboard_client=HomeAssistantDashboardClient(settings.supervisor_url, settings.supervisor_token),
        limiter=SlidingWindowLimiter(),
        admin_csrf=secrets.token_urlsafe(32),
        identity_key=secrets_store.get("identity-hmac"),
    )
