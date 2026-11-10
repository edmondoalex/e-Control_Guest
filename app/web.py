from __future__ import annotations

import secrets

from fastapi import FastAPI, Request


def install_http_guards(app: FastAPI, runtime, *, surface: str) -> None:
    @app.middleware("http")
    async def security_and_audit(request: Request, call_next):
        request_id = request.headers.get("x-request-id", "")
        if not request_id or len(request_id) > 100:
            request_id = secrets.token_hex(12)
        try:
            response = await call_next(request)
            status = response.status_code
        except Exception:
            runtime.audit.append(
                actor_type=surface, action="http_request", resource=request.url.path,
                request_id=request_id, outcome="error",
                metadata={"method": request.method, "network_id": runtime.network_id(request)},
            )
            raise
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN" if surface == "admin" else "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'self'" if surface == "admin" else
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'"
        )
        response.headers["X-Request-ID"] = request_id
        if not request.url.path.startswith("/static/") and request.url.path != "/health":
            runtime.audit.append(
                actor_type=surface, action="http_request", resource=request.url.path,
                request_id=request_id, outcome="allowed" if status < 400 else "denied",
                metadata={"method": request.method, "status": status,
                          "network_id": runtime.network_id(request)},
            )
        return response
