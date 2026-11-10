from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .dashboard_client import DashboardUnavailable
from .importer import inspect_dashboard, snapshot
from .policy import ACTION_CATALOG, PolicyDenied, authorize
from .runtime import Runtime
from .web import install_http_guards

STATIC = Path(__file__).with_name("static")


class ProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class ProfileStatus(BaseModel):
    active: bool


class InspectDashboard(BaseModel):
    dashboard: str = Field(default="manual", max_length=100)
    config: dict[str, Any]


class ImportCard(BaseModel):
    dashboard: str = Field(default="manual", max_length=100)
    source_ref: str = Field(max_length=300)
    config: dict[str, Any] | None = None


class PermissionUpdate(BaseModel):
    permissions: dict[str, dict]


class ShareCreate(BaseModel):
    pin: str | None = Field(default=None, min_length=4, max_length=12)
    valid_minutes: int = Field(default=60, ge=5, le=43200)
    max_sessions: int = Field(default=1, ge=1, le=20)


def create_admin_app(runtime: Runtime) -> FastAPI:
    app = FastAPI(title="e-Control Guest Admin", docs_url=None, redoc_url=None)
    install_http_guards(app, runtime, surface="admin")
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    async def require_ingress(request: Request) -> None:
        if runtime.settings.development_admin:
            return
        peer = request.client.host if request.client else ""
        if peer != "172.30.32.2" or not request.headers.get("x-ingress-path"):
            runtime.audit.append(actor_type="admin", action="admin_access", outcome="denied",
                                 metadata={"network_id": runtime.network_id(request)})
            raise HTTPException(403, "Amministrazione disponibile soltanto tramite Ingress")

    async def require_csrf(request: Request, token: str | None = Header(None, alias="X-eControl-CSRF")) -> None:
        await require_ingress(request)
        if token != runtime.admin_csrf:
            runtime.audit.append(actor_type="admin", action="csrf_check", outcome="denied",
                                 metadata={"network_id": runtime.network_id(request)})
            raise HTTPException(403, "Controllo CSRF non valido")

    @app.get("/health")
    async def health(request: Request):
        peer = request.client.host if request.client else ""
        if not runtime.settings.development_admin and peer not in {"127.0.0.1", "::1", "172.30.32.2"}:
            raise HTTPException(403, "Health check locale")
        valid, broken_at = runtime.audit.verify()
        return {"status": "ok" if valid else "degraded", "audit_valid": valid, "broken_at": broken_at}

    @app.get("/", dependencies=[Depends(require_ingress)])
    async def index():
        return FileResponse(STATIC / "admin.html")

    @app.get("/api/admin/bootstrap", dependencies=[Depends(require_ingress)])
    async def bootstrap():
        return {"csrf": runtime.admin_csrf, "action_catalog": ACTION_CATALOG,
                "guest_base_url": runtime.settings.guest_base_url}

    @app.get("/api/admin/profiles", dependencies=[Depends(require_ingress)])
    async def profiles():
        return {"profiles": runtime.store.list_profiles()}

    @app.post("/api/admin/profiles", dependencies=[Depends(require_csrf)])
    async def create_profile(payload: ProfileCreate, request: Request):
        profile = runtime.store.create_profile(payload.name)
        runtime.audit.append(actor_type="admin", actor_id=request.headers.get("x-hass-user-id", "ingress"),
                             action="profile_create", resource=profile["id"], outcome="allowed",
                             metadata={"name": profile["name"], "revision": profile["revision"]})
        return profile

    @app.get("/api/admin/profiles/{profile_id}", dependencies=[Depends(require_ingress)])
    async def profile(profile_id: str):
        try:
            return {"dashboard": runtime.store.dashboard(profile_id),
                    "shares": runtime.store.list_shares(profile_id)}
        except KeyError as exc:
            raise HTTPException(404, "Profilo non trovato") from exc

    @app.put("/api/admin/profiles/{profile_id}/status", dependencies=[Depends(require_csrf)])
    async def profile_status(profile_id: str, payload: ProfileStatus, request: Request):
        try:
            profile = runtime.store.set_profile_active(profile_id, payload.active)
        except KeyError as exc:
            raise HTTPException(404, "Profilo non trovato") from exc
        runtime.audit.append(actor_type="admin", actor_id=request.headers.get("x-hass-user-id", "ingress"),
                             action="profile_status", resource=profile_id, outcome="allowed",
                             metadata={"active": payload.active, "revision": profile["revision"]})
        return profile

    @app.get("/api/admin/import/dashboards", dependencies=[Depends(require_ingress)])
    async def dashboards():
        try:
            values = await runtime.dashboard_client.dashboards()
            if not any((item.get("url_path") or "lovelace") == "lovelace" for item in values):
                values.insert(0, {"url_path": "lovelace", "title": "Panoramica"})
            return {"dashboards": values, "mode": "automatic"}
        except DashboardUnavailable as exc:
            return {"dashboards": [{"url_path": "lovelace", "title": "Panoramica"}],
                    "mode": "manual", "detail": str(exc)}

    @app.get("/api/admin/import/dashboards/{url_path}/cards", dependencies=[Depends(require_ingress)])
    async def dashboard_cards(url_path: str):
        try:
            config = await runtime.dashboard_client.config(None if url_path == "lovelace" else url_path)
            cards = [item.public() for item in inspect_dashboard(config, url_path)]
        except DashboardUnavailable as exc:
            raise HTTPException(503, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"cards": cards}

    @app.post("/api/admin/import/inspect", dependencies=[Depends(require_csrf)])
    async def inspect_manual(payload: InspectDashboard):
        try:
            return {"cards": [x.public() for x in inspect_dashboard(payload.config, payload.dashboard)]}
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/admin/profiles/{profile_id}/cards/import", dependencies=[Depends(require_csrf)])
    async def import_card(profile_id: str, payload: ImportCard, request: Request):
        try:
            config = payload.config or await runtime.dashboard_client.config(
                None if payload.dashboard == "lovelace" else payload.dashboard)
            candidates = {x.source_ref: x for x in inspect_dashboard(config, payload.dashboard)}
        except (DashboardUnavailable, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc
        candidate = candidates.get(payload.source_ref)
        if candidate is None:
            raise HTTPException(404, "Scheda non trovata")
        if not candidate.safe:
            runtime.audit.append(actor_type="admin", action="card_import", resource=payload.source_ref,
                                 outcome="denied", metadata={"reason": candidate.reason})
            raise HTTPException(400, candidate.reason)
        try:
            card = runtime.store.add_card(profile_id, snapshot(candidate))
        except KeyError as exc:
            raise HTTPException(404, "Profilo non trovato o disattivato") from exc
        runtime.audit.append(actor_type="admin", actor_id=request.headers.get("x-hass-user-id", "ingress"),
                             action="card_import", resource=card["id"], outcome="allowed",
                             metadata={"source_ref": candidate.source_ref,
                                       "source_hash": candidate.source_hash,
                                       "entities": [x["entity_id"] for x in candidate.entities]})
        return card

    @app.delete("/api/admin/cards/{card_id}", dependencies=[Depends(require_csrf)])
    async def delete_card(card_id: str, request: Request):
        try:
            profile_id = runtime.store.delete_card(card_id)
        except KeyError as exc:
            raise HTTPException(404, "Scheda non trovata") from exc
        runtime.audit.append(actor_type="admin", actor_id=request.headers.get("x-hass-user-id", "ingress"),
                             action="card_delete", resource=card_id, outcome="allowed",
                             metadata={"profile_id": profile_id})
        return {"deleted": True}

    @app.put("/api/admin/cards/{card_id}/permissions", dependencies=[Depends(require_csrf)])
    async def permissions(card_id: str, payload: PermissionUpdate, request: Request):
        try:
            card = runtime.store.get_card(card_id)
        except KeyError as exc:
            raise HTTPException(404, "Scheda non trovata") from exc
        entities = {x["entity_id"] for x in card["config"]["entities"]}
        if set(payload.permissions) != entities:
            raise HTTPException(400, "I permessi devono coprire esattamente le entita importate")
        probes = {"set_temperature": 20, "set_brightness": 1, "set_position": 1,
                  "set_hvac_mode": "off"}
        for entity_id, policy in payload.permissions.items():
            if not isinstance(policy, dict) or not isinstance(policy.get("actions"), list):
                raise HTTPException(400, "Permessi non validi")
            for action in policy["actions"]:
                try:
                    authorize({entity_id: policy}, entity_id, action, probes.get(action))
                except PolicyDenied as exc:
                    raise HTTPException(400, str(exc)) from exc
        updated = runtime.store.update_card_permissions(card_id, payload.permissions)
        runtime.audit.append(actor_type="admin", actor_id=request.headers.get("x-hass-user-id", "ingress"),
                             action="permissions_update", resource=card_id, outcome="allowed",
                             metadata={"entities": sorted(payload.permissions)})
        return updated

    @app.post("/api/admin/profiles/{profile_id}/shares", dependencies=[Depends(require_csrf)])
    async def create_share(profile_id: str, payload: ShareCreate, request: Request):
        try:
            share, token = runtime.store.create_share(
                profile_id, pin=payload.pin, expires_at=time.time() + payload.valid_minutes * 60,
                max_sessions=payload.max_sessions)
        except (KeyError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc
        runtime.audit.append(actor_type="admin", actor_id=request.headers.get("x-hass-user-id", "ingress"),
                             action="share_create", resource=share["id"], outcome="allowed",
                             metadata={"profile_id": profile_id, "expires_at": share["expires_at"],
                                       "max_sessions": share["max_sessions"],
                                       "pin_required": bool(payload.pin)})
        return {"share": share,
                "fragment_url": f"{runtime.settings.guest_base_url}/share#token={token}"}

    @app.delete("/api/admin/shares/{share_id}", dependencies=[Depends(require_csrf)])
    async def revoke_share(share_id: str, request: Request):
        runtime.store.revoke_share(share_id)
        runtime.audit.append(actor_type="admin", actor_id=request.headers.get("x-hass-user-id", "ingress"),
                             action="share_revoke", resource=share_id, outcome="allowed")
        return {"revoked": True}

    @app.get("/api/admin/audit", dependencies=[Depends(require_ingress)])
    async def audit(limit: int = 200):
        valid, broken_at = runtime.audit.verify()
        return {"valid": valid, "broken_at": broken_at, "events": runtime.audit.recent(limit)}

    return app
