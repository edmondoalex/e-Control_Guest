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

    async def states(self, entity_ids: set[str]) -> dict[str, dict]:
        if not entity_ids:
            return {}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(
                f"{self.base_url}/core/api/states", headers=self._headers()
            )
        response.raise_for_status()
        values = response.json()
        if not isinstance(values, list):
            raise RuntimeError("Elenco stati Home Assistant non valido")
        return {
            str(item["entity_id"]): {
                "entity_id": item["entity_id"], "state": item.get("state"),
                "attributes": item.get("attributes", {}),
            }
            for item in values
            if isinstance(item, dict) and item.get("entity_id") in entity_ids
        }

    async def execute(self, command: Command) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/core/api/services/{command.domain}/{command.service}",
                headers=self._headers(), json=command.data,
            )
        response.raise_for_status()
        return await self.state(command.entity_id)
