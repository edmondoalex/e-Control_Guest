from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .dashboard_client import DashboardUnavailable
from .importer import SAFE_CARD_TYPES, inspect_dashboard, snapshot
from .policy import ACTION_CATALOG, PolicyDenied, authorize
from .runtime import Runtime
from .storage import StoreError
from .web import install_http_guards

STATIC = Path(__file__).with_name("static")
PERMANENT_EXPIRES_AT = 253402300799.0


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


class ProfilePermissionUpdate(BaseModel):
    cards: dict[str, dict[str, dict]]


class ProfileContentImport(BaseModel):
    schema_version: int
    cards: list[dict[str, Any]] = Field(max_length=500)


class ShareCreate(BaseModel):
    label: str = Field(min_length=1, max_length=100)
    pin: str | None = Field(default=None, min_length=4, max_length=12)
    valid_minutes: int | None = Field(default=60, ge=5, le=43200)
    max_sessions: int = Field(default=1, ge=1, le=20)


class ShareRevoke(BaseModel):
    reason: str = Field(min_length=3, max_length=200)


class ShareUpdate(BaseModel):
    valid_minutes: int | None = Field(default=None, ge=5, le=43200)
    max_sessions: int = Field(ge=1, le=20)


def create_admin_app(runtime: Runtime) -> FastAPI:
    app = FastAPI(title="e-Control Guest Admin", docs_url=None, redoc_url=None)
    install_http_guards(app, runtime, surface="admin")
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    def validate_permissions(card: dict, permissions: dict[str, dict]) -> None:
        entities = {x["entity_id"] for x in card["config"]["entities"]}
        if set(permissions) != entities:
            raise HTTPException(400, "I permessi devono coprire esattamente le entita importate")
        probes = {"set_temperature": 20, "set_brightness": 1, "set_position": 1,
                  "set_hvac_mode": "off"}
        for entity_id, policy in permissions.items():
            if not isinstance(policy, dict) or set(policy) != {"read", "actions", "limits"} \
                    or not isinstance(policy.get("read"), bool) \
                    or not isinstance(policy.get("actions"), list) \
                    or not isinstance(policy.get("limits"), dict):
                raise HTTPException(400, "Permessi non validi")
            for action in policy["actions"]:
                try:
                    authorize({entity_id: policy}, entity_id, action, probes.get(action))
                except PolicyDenied as exc:
                    raise HTTPException(400, str(exc)) from exc

    def imported_snapshots(payload: ProfileContentImport) -> list[dict]:
        if payload.schema_version != 1:
            raise HTTPException(400, "Versione JSON non supportata")
        snapshots = []
        for index, item in enumerate(payload.cards):
            if not isinstance(item, dict) or set(item) != {"title", "config", "permissions"}:
                raise HTTPException(400, f"Scheda JSON {index + 1} non valida")
            config, permissions = item["config"], item["permissions"]
            if not isinstance(config, dict) or set(config) != {"type", "appearance", "entities"}:
                raise HTTPException(400, f"Configurazione scheda {index + 1} non valida")
            if config["type"] not in SAFE_CARD_TYPES:
                raise HTTPException(400, f"Tipo scheda non consentito: {config['type']}")
            if not isinstance(config["appearance"], dict) or not isinstance(config["entities"], list):
                raise HTTPException(400, f"Contenuto scheda {index + 1} non valido")
            if len(config["entities"]) > 500:
                raise HTTPException(400, "Troppe entita in una scheda")
            entity_ids = []
            for entity in config["entities"]:
                if not isinstance(entity, dict) or set(entity) != {"entity_id", "name", "icon"}:
                    raise HTTPException(400, f"Entita scheda {index + 1} non valida")
                entity_id = entity["entity_id"]
                if not isinstance(entity_id, str) or "." not in entity_id or len(entity_id) > 255:
                    raise HTTPException(400, "ID entita non valido")
                entity_ids.append(entity_id)
            if len(entity_ids) != len(set(entity_ids)):
                raise HTTPException(400, "Entita duplicate nella scheda")
            validate_permissions({"config": config}, permissions)
            canonical = json.dumps(config, ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":")).encode("utf-8")
            snapshots.append({
                "source_ref": f"json-import[{index}]",
                "source_hash": hashlib.sha256(canonical).hexdigest(),
                "title": str(item["title"])[:100],
                "type": config["type"], "appearance": config["appearance"],
                "entities": config["entities"], "permissions": permissions,
            })
        return snapshots

    async def enrich_entity_names(dashboard: dict) -> dict:
        entities = [
            entity for card in dashboard.get("cards", [])
            for entity in card.get("config", {}).get("entities", [])
            if not entity.get("name")
        ]
        entity_ids = {str(entity.get("entity_id", "")) for entity in entities}
        entity_ids.discard("")
        try:
            if hasattr(runtime.adapter, "states"):
                states = await runtime.adapter.states(entity_ids)
            else:
                values = await asyncio.gather(
                    *(runtime.adapter.state(entity_id) for entity_id in entity_ids),
                    return_exceptions=True,
                )
                states = {
                    str(value.get("entity_id")): value for value in values
                    if isinstance(value, dict) and value.get("entity_id")
                }
        except Exception:
            return dashboard
        for entity in entities:
            state = states.get(entity.get("entity_id"), {})
            friendly_name = state.get("attributes", {}).get("friendly_name")
            if friendly_name:
                entity["name"] = str(friendly_name)[:100]
        return dashboard

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

    @app.get("/favicon.ico", include_in_schema=False, dependencies=[Depends(require_ingress)])
    async def favicon():
        return FileResponse(STATIC / "icon.png", media_type="image/png")

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
            dashboard = await enrich_entity_names(runtime.store.dashboard(profile_id))
            return {"dashboard": dashboard,
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
        validate_permissions(card, payload.permissions)
        updated = runtime.store.update_card_permissions(card_id, payload.permissions)
        runtime.audit.append(actor_type="admin", actor_id=request.headers.get("x-hass-user-id", "ingress"),
                             action="permissions_update", resource=card_id, outcome="allowed",
                             metadata={"entities": sorted(payload.permissions)})
        return updated

    @app.put("/api/admin/profiles/{profile_id}/permissions", dependencies=[Depends(require_csrf)])
    async def profile_permissions(profile_id: str, payload: ProfilePermissionUpdate, request: Request):
        try:
            dashboard = runtime.store.dashboard(profile_id)
        except KeyError as exc:
            raise HTTPException(404, "Profilo non trovato") from exc
        cards = {card["id"]: card for card in dashboard["cards"]}
        if set(payload.cards) != set(cards):
            raise HTTPException(400, "I permessi devono coprire esattamente tutte le schede del profilo")
        for card_id, permissions in payload.cards.items():
            validate_permissions(cards[card_id], permissions)
        try:
            updated = runtime.store.update_profile_permissions(profile_id, payload.cards)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        runtime.audit.append(
            actor_type="admin", actor_id=request.headers.get("x-hass-user-id", "ingress"),
            action="permissions_update_all", resource=profile_id, outcome="allowed",
            metadata={"card_count": len(payload.cards),
                      "entity_count": sum(len(value) for value in payload.cards.values())},
        )
        return updated

    @app.get("/api/admin/profiles/{profile_id}/content-export", dependencies=[Depends(require_ingress)])
    async def content_export(profile_id: str, request: Request):
        try:
            dashboard = runtime.store.dashboard(profile_id)
        except KeyError as exc:
            raise HTTPException(404, "Profilo non trovato") from exc
        cards = [{"title": card["title"], "config": card["config"],
                  "permissions": card["permissions"]} for card in dashboard["cards"]]
        runtime.audit.append(
            actor_type="admin", actor_id=request.headers.get("x-hass-user-id", "ingress"),
            action="content_export", resource=profile_id, outcome="allowed",
            metadata={"card_count": len(cards)},
        )
        return {"schema_version": 1, "product": "e-Control Guest",
                "profile_name": dashboard["profile"]["name"], "cards": cards}

    @app.post("/api/admin/profiles/{profile_id}/content-import", dependencies=[Depends(require_csrf)])
    async def content_import(profile_id: str, payload: ProfileContentImport, request: Request):
        snapshots = imported_snapshots(payload)
        try:
            dashboard = runtime.store.replace_profile_cards(profile_id, snapshots)
        except KeyError as exc:
            raise HTTPException(404, "Profilo non trovato o disattivato") from exc
        runtime.audit.append(
            actor_type="admin", actor_id=request.headers.get("x-hass-user-id", "ingress"),
            action="content_import", resource=profile_id, outcome="allowed",
            metadata={"card_count": len(snapshots),
                      "entity_count": sum(len(card["entities"]) for card in snapshots)},
        )
        return dashboard

    @app.post("/api/admin/profiles/{profile_id}/shares", dependencies=[Depends(require_csrf)])
    async def create_share(profile_id: str, payload: ShareCreate, request: Request):
        if payload.valid_minutes is None and not payload.pin:
            raise HTTPException(400, "Il PIN è obbligatorio per i link senza scadenza")
        expires_at = (PERMANENT_EXPIRES_AT if payload.valid_minutes is None
                      else time.time() + payload.valid_minutes * 60)
        try:
            share, token = runtime.store.create_share(
                profile_id, label=payload.label, pin=payload.pin, expires_at=expires_at,
                max_sessions=payload.max_sessions)
        except (KeyError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc
        runtime.audit.append(actor_type="admin", actor_id=request.headers.get("x-hass-user-id", "ingress"),
                             action="share_create", resource=share["id"], outcome="allowed",
                             metadata={"profile_id": profile_id, "label": payload.label,
                                       "expires_at": share["expires_at"],
                                       "max_sessions": share["max_sessions"],
                                       "pin_required": bool(payload.pin)})
        return {"share": share,
                "fragment_url": f"{runtime.settings.guest_base_url}/guest-access#token={token}"}

    @app.put("/api/admin/shares/{share_id}", dependencies=[Depends(require_csrf)])
    async def update_share(share_id: str, payload: ShareUpdate, request: Request):
        expires_at = (PERMANENT_EXPIRES_AT if payload.valid_minutes is None
                      else time.time() + payload.valid_minutes * 60)
        try:
            result = runtime.store.update_share_limits(
                share_id, expires_at=expires_at, max_sessions=payload.max_sessions,
            )
        except KeyError as exc:
            raise HTTPException(404, "Link non trovato") from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        runtime.audit.append(
            actor_type="admin", actor_id=request.headers.get("x-hass-user-id", "ingress"),
            action="share_update", resource=share_id, outcome="allowed",
            metadata={"label": result["share"].get("label", ""),
                      "expires_at": result["share"]["expires_at"],
                      "max_sessions": result["share"]["max_sessions"],
                      "sessions_revoked": result["sessions_revoked"]},
        )
        return result

    @app.delete("/api/admin/shares/{share_id}", dependencies=[Depends(require_csrf)])
    async def revoke_share(share_id: str, payload: ShareRevoke, request: Request):
        actor_id = request.headers.get("x-hass-user-id", "ingress")
        try:
            share = runtime.store.get_share(share_id)
            runtime.store.revoke_share(share_id, reason=payload.reason, actor_id=actor_id)
        except (KeyError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc
        runtime.audit.append(actor_type="admin", actor_id=actor_id,
                             action="share_revoke", resource=share_id, outcome="allowed",
                             metadata={"label": share.get("label", ""), "reason": payload.reason})
        return {"revoked": True}

    @app.get("/api/admin/shares/{share_id}/link", dependencies=[Depends(require_ingress)])
    async def share_link(share_id: str):
        try:
            share = runtime.store.get_share(share_id)
            token = runtime.store.recover_share_token(share_id)
        except KeyError as exc:
            raise HTTPException(404, "Link non trovato") from exc
        except StoreError as exc:
            raise HTTPException(409, "Questo link precedente non e recuperabile") from exc
        return {"share_id": share_id, "label": share.get("label", ""),
                "fragment_url": f"{runtime.settings.guest_base_url}/guest-access#token={token}"}

    @app.get("/api/admin/audit", dependencies=[Depends(require_ingress)])
    async def audit(limit: int = 200):
        valid, broken_at = runtime.audit.verify()
        events = runtime.audit.recent(limit)
        for event in events:
            if event["actor_type"] != "guest" or event["metadata"].get("label"):
                continue
            label = runtime.store.share_label_for_session(event.get("session_id", ""))
            if label:
                event["metadata"]["label"] = label
        return {"valid": valid, "broken_at": broken_at, "events": events,
                "stats": runtime.audit.stats()}

    return app
