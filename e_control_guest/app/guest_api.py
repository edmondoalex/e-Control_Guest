from __future__ import annotations

import asyncio
import secrets
import uuid
from pathlib import Path
from typing import Any

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .crypto import b64url
from .policy import PolicyDenied, authorize, public_state
from .rate_limit import RateLimitExceeded
from .runtime import Runtime
from .storage import StoreError
from .web import install_http_guards

STATIC = Path(__file__).with_name("static")


class Login(BaseModel):
    token: str = Field(min_length=30, max_length=100)
    pin: str | None = Field(default=None, max_length=12)


class Action(BaseModel):
    request_id: str
    card_id: str
    entity_id: str = Field(max_length=255)
    action: str = Field(max_length=50)
    value: Any = None


def create_guest_app(runtime: Runtime) -> FastAPI:
    app = FastAPI(title="e-Control Guest", docs_url=None, redoc_url=None)
    install_http_guards(app, runtime, surface="guest")
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    def audit_denied(request: Request, action: str, reason: str, *, resource: str = "") -> None:
        runtime.audit.append(
            actor_type="guest", action=action, resource=resource, outcome="denied",
            metadata={"reason": reason, "network_id": runtime.network_id(request),
                      "user_agent_id": runtime.user_agent_id(request)},
        )

    async def session(
        request: Request,
        ecg_session: str | None = Cookie(default=None),
        ecg_device: str | None = Cookie(default=None),
    ) -> dict:
        if not ecg_session or not ecg_device:
            audit_denied(request, "session_check", "missing_session")
            raise HTTPException(401, "Sessione mancante")
        try:
            payload = runtime.signer.verify(ecg_session)
            row = runtime.store.validate_session(
                payload["sid"], payload["sh"], payload["pr"], payload["rev"],
                device_token=ecg_device,
            )
        except (ValueError, StoreError) as exc:
            audit_denied(request, "session_check", str(exc))
            raise HTTPException(401, "Sessione non valida") from exc
        return {**payload, "row": row}

    async def write_session(
        request: Request,
        current: dict = Depends(session),
        csrf: str | None = Header(default=None, alias="X-eControl-CSRF"),
    ) -> dict:
        try:
            runtime.store.validate_session(
                current["sid"], current["sh"], current["pr"], current["rev"], csrf_token=csrf,
            )
        except StoreError as exc:
            audit_denied(request, "csrf_check", str(exc))
            raise HTTPException(403, "Controllo CSRF non valido") from exc
        return current

    @app.get("/health")
    async def health():
        valid, broken_at = runtime.audit.verify()
        return {"status": "ok" if valid else "degraded", "audit_valid": valid,
                "broken_at": broken_at}

    @app.get("/")
    @app.get("/share")
    async def share_page():
        return FileResponse(STATIC / "guest.html")

    @app.post("/api/guest/login")
    async def login(payload: Login, request: Request, response: Response):
        network_id = runtime.network_id(request)
        try:
            runtime.limiter.check("login", network_id, limit=8, seconds=300)
        except RateLimitExceeded as exc:
            audit_denied(request, "login", "rate_limited")
            raise HTTPException(429, "Troppi tentativi. Riprova piu tardi") from exc
        csrf_token = b64url(secrets.token_bytes(32))
        device_token = b64url(secrets.token_bytes(32))
        try:
            row = runtime.store.authenticate_share(
                payload.token, payload.pin, csrf_token=csrf_token, device_token=device_token,
                lifetime_seconds=runtime.settings.session_minutes * 60,
            )
        except StoreError as exc:
            audit_denied(request, "login", str(exc))
            raise HTTPException(401, "Link, PIN o disponibilita non validi") from exc
        lifetime = max(1, int(row["expires_at"]) - int(__import__("time").time()))
        signed = runtime.signer.issue(
            session_id=row["id"], share_id=row["share_id"], profile_id=row["profile_id"],
            revision=row["profile_revision"], lifetime_seconds=lifetime,
        )
        secure = not runtime.settings.allow_insecure_local_http
        response.set_cookie("ecg_session", signed, max_age=lifetime, httponly=True,
                            secure=secure, samesite="strict", path="/")
        response.set_cookie("ecg_device", device_token, max_age=lifetime, httponly=True,
                            secure=secure, samesite="strict", path="/")
        runtime.audit.append(
            actor_type="guest", actor_id=runtime.user_agent_id(request), session_id=row["id"],
            action="login", resource=row["profile_id"], outcome="allowed",
            metadata={"network_id": network_id, "expires_at": row["expires_at"]},
        )
        return {"csrf": csrf_token, "expires_at": row["expires_at"]}

    @app.get("/api/guest/dashboard")
    async def dashboard(request: Request, current: dict = Depends(session)):
        try:
            value = runtime.store.dashboard(current["pr"])
        except KeyError as exc:
            raise HTTPException(404, "Profilo non disponibile") from exc
        output = []
        for card in value["cards"]:
            states = []
            for entity in card["config"]["entities"]:
                entity_id = entity["entity_id"]
                policy = card["permissions"].get(entity_id, {})
                if not policy.get("read", False):
                    continue
                try:
                    state = public_state(await runtime.adapter.state(entity_id))
                    states.append({**state, "name": entity.get("name") or "",
                                   "icon": entity.get("icon") or "",
                                   "actions": policy.get("actions", []),
                                   "limits": policy.get("limits", {})})
                    outcome = "allowed"
                except Exception:
                    states.append({"entity_id": entity_id, "state": "unavailable", "attributes": {},
                                   "name": entity.get("name") or "", "icon": entity.get("icon") or "",
                                   "actions": [], "limits": {}})
                    outcome = "error"
                runtime.audit.append(
                    actor_type="guest", actor_id=runtime.user_agent_id(request),
                    session_id=current["sid"], action="state_read", resource=entity_id,
                    outcome=outcome,
                )
            output.append({"id": card["id"], "title": card["title"],
                           "type": card["config"]["type"], "states": states})
        runtime.audit.append(
            actor_type="guest", actor_id=runtime.user_agent_id(request),
            session_id=current["sid"], action="dashboard_view", resource=current["pr"],
            outcome="allowed", metadata={"cards": len(output)},
        )
        return {"profile": {"name": value["profile"]["name"]}, "cards": output}

    @app.post("/api/guest/action")
    async def action(payload: Action, request: Request, current: dict = Depends(write_session)):
        try:
            uuid.UUID(payload.request_id)
        except ValueError as exc:
            raise HTTPException(400, "request_id non valido") from exc
        try:
            card = runtime.store.get_card(payload.card_id)
        except KeyError as exc:
            audit_denied(request, "command", "card_not_found", resource=payload.entity_id)
            raise HTTPException(404, "Scheda non trovata") from exc
        if card["profile_id"] != current["pr"]:
            audit_denied(request, "command", "cross_profile", resource=payload.entity_id)
            raise HTTPException(403, "Azione non consentita")
        try:
            runtime.limiter.check("command", current["sid"], limit=30, seconds=60)
            command = authorize(card["permissions"], payload.entity_id, payload.action, payload.value)
        except RateLimitExceeded as exc:
            audit_denied(request, "command", "rate_limited", resource=payload.entity_id)
            raise HTTPException(429, "Troppe azioni") from exc
        except PolicyDenied as exc:
            audit_denied(request, "command", str(exc), resource=payload.entity_id)
            raise HTTPException(403, "Azione non consentita") from exc
        if not runtime.store.claim_operation(payload.request_id, current["sid"]):
            previous = runtime.store.operation_result(payload.request_id)
            if previous is not None:
                return previous
            raise HTTPException(409, "Azione gia in corso")
        runtime.audit.append(
            actor_type="guest", actor_id=runtime.user_agent_id(request), session_id=current["sid"],
            action="command_request", resource=payload.entity_id, request_id=payload.request_id,
            outcome="allowed", metadata={"action": payload.action, "value": payload.value},
        )
        try:
            readback = public_state(await runtime.adapter.execute(command))
            result = {"ok": True, "request_id": payload.request_id, "readback": readback}
            runtime.audit.append(
                actor_type="guest", actor_id=runtime.user_agent_id(request), session_id=current["sid"],
                action="command_readback", resource=payload.entity_id,
                request_id=payload.request_id, outcome="allowed",
                metadata={"state": readback.get("state")},
            )
        except Exception as exc:
            result = {"ok": False, "request_id": payload.request_id, "error": "command_failed"}
            runtime.audit.append(
                actor_type="guest", actor_id=runtime.user_agent_id(request), session_id=current["sid"],
                action="command_readback", resource=payload.entity_id,
                request_id=payload.request_id, outcome="error",
                metadata={"error_type": type(exc).__name__},
            )
        runtime.store.finish_operation(payload.request_id, result)
        if not result["ok"]:
            raise HTTPException(502, "Comando non confermato")
        return result

    @app.post("/api/guest/logout")
    async def logout(response: Response, current: dict = Depends(write_session)):
        runtime.store.revoke_session(current["sid"])
        response.delete_cookie("ecg_session", path="/")
        response.delete_cookie("ecg_device", path="/")
        runtime.audit.append(actor_type="guest", session_id=current["sid"], action="logout",
                             resource=current["pr"], outcome="allowed")
        return {"ok": True}

    return app
