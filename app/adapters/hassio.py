from __future__ import annotations

from typing import Any

import httpx

from ..policy import Command


class HassioAdapter:
    """Narrow broker for typed commands; no generic service endpoint is exposed."""

    def __init__(self, base_url: str, token: str, *, timeout: float = 8.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        if not self.token:
            raise RuntimeError("Supervisor token non disponibile")
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    async def state(self, entity_id: str) -> dict:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(
                f"{self.base_url}/core/api/states/{entity_id}", headers=self._headers()
            )
        response.raise_for_status()
        data = response.json()
        return {"entity_id": data.get("entity_id"), "state": data.get("state"), "attributes": data.get("attributes", {})}

    async def execute(self, command: Command) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/core/api/services/{command.domain}/{command.service}",
                headers=self._headers(), json=command.data,
            )
        response.raise_for_status()
        return await self.state(command.entity_id)
