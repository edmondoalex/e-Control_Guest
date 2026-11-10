from __future__ import annotations

import asyncio
import json
from urllib.parse import urlsplit, urlunsplit

import websockets


class DashboardUnavailable(RuntimeError):
    pass


class HomeAssistantDashboardClient:
    """Best-effort Lovelace reader with a manual-import fallback in the UI."""

    def __init__(self, supervisor_url: str, token: str, timeout: float = 10.0):
        parts = urlsplit(supervisor_url)
        scheme = "wss" if parts.scheme == "https" else "ws"
        self.url = urlunsplit((scheme, parts.netloc, "/core/websocket", "", ""))
        self.token = token
        self.timeout = timeout

    async def command(self, command_type: str, **fields) -> object:
        if not self.token:
            raise DashboardUnavailable("Supervisor token non disponibile")
        try:
            async with asyncio.timeout(self.timeout):
                async with websockets.connect(self.url, max_size=4 * 1024 * 1024) as socket:
                    hello = json.loads(await socket.recv())
                    if hello.get("type") != "auth_required":
                        raise DashboardUnavailable("Handshake WebSocket inatteso")
                    await socket.send(json.dumps({"type": "auth", "access_token": self.token}))
                    authenticated = json.loads(await socket.recv())
                    if authenticated.get("type") != "auth_ok":
                        raise DashboardUnavailable("Autenticazione dashboard rifiutata")
                    request = {"id": 1, "type": command_type, **fields}
                    await socket.send(json.dumps(request))
                    while True:
                        response = json.loads(await socket.recv())
                        if response.get("id") == 1:
                            if not response.get("success"):
                                raise DashboardUnavailable(str(response.get("error", {}).get("message") or "Comando dashboard non supportato"))
                            return response.get("result")
        except (OSError, TimeoutError, websockets.WebSocketException, json.JSONDecodeError) as exc:
            raise DashboardUnavailable("Dashboard non raggiungibile") from exc

    async def dashboards(self) -> list[dict]:
        result = await self.command("lovelace/dashboards/list")
        if not isinstance(result, list):
            raise DashboardUnavailable("Elenco dashboard non valido")
        return [item for item in result if isinstance(item, dict)]

    async def config(self, url_path: str | None = None) -> dict:
        fields = {"url_path": url_path} if url_path else {}
        result = await self.command("lovelace/config", **fields)
        if not isinstance(result, dict):
            raise DashboardUnavailable("Configurazione dashboard non valida")
        return result
