from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

from app.admin_api import create_admin_app
from app.audit import AuditLog
from app.guest_api import create_guest_app
from app.importer import inspect_dashboard
from app.policy import PolicyDenied, authorize
from app.policy import public_state
from app.runtime import build_runtime
from app.settings import Settings


class FakeAdapter:
    def __init__(self):
        self.values = {"light.tasting": {"entity_id": "light.tasting", "state": "off",
                                        "attributes": {"friendly_name": "Tasting Room", "brightness": 0}}}
        self.commands = []

    async def state(self, entity_id: str) -> dict:
        return self.values[entity_id]

    async def execute(self, command) -> dict:
        self.commands.append(command)
        state = "on" if command.service == "turn_on" else "off"
        self.values[command.entity_id] = {"entity_id": command.entity_id, "state": state,
                                          "attributes": {"friendly_name": "Tasting Room"}}
        return self.values[command.entity_id]


@pytest.fixture()
def runtime(tmp_path: Path):
    settings = Settings(data_dir=tmp_path, development_admin=True, session_minutes=30,
                        allow_insecure_local_http=True)
    return build_runtime(settings, adapter=FakeAdapter())


def dashboard_config() -> dict:
    return {"views": [{"title": "Interrato", "cards": [
        {"type": "heading", "heading": "INTERRATO"},
        {"type": "entities", "title": "TASTING ROOM",
         "entities": [{"entity": "light.tasting", "name": "Tasting Room"}]},
        {"type": "custom:unsafe-card", "entity": "switch.secret"},
    ]}]}


def test_importer_flattens_only_safe_builtin_cards():
    cards = inspect_dashboard(dashboard_config())
    assert cards[0].safe is True
    assert cards[0].card_type == "heading"
    assert cards[0].title == "INTERRATO"
    assert cards[0].entities == []
    assert cards[1].entities[0]["entity_id"] == "light.tasting"
    assert cards[2].safe is False
    assert cards[2].reason == "custom_card_not_executable"


def test_generated_dashboard_returns_readable_error():
    with pytest.raises(ValueError, match="generata automaticamente"):
        inspect_dashboard({"strategy": {"type": "map"}}, "map")


def test_policy_is_fail_closed_and_checks_limits():
    permissions = {"light.tasting": {"actions": ["set_brightness"],
                                      "limits": {"brightness": [10, 100]}}}
    command = authorize(permissions, "light.tasting", "set_brightness", 80)
    assert command.data == {"entity_id": "light.tasting", "brightness": 80}
    with pytest.raises(PolicyDenied):
        authorize(permissions, "light.tasting", "set_brightness", 200)
    with pytest.raises(PolicyDenied):
        authorize(permissions, "light.tasting", "turn_on")
    with pytest.raises(PolicyDenied):
        authorize(permissions, "switch.not_shared", "turn_on")


def test_state_attributes_are_allowlisted():
    value = public_state({"entity_id": "light.tasting", "state": "on",
                          "attributes": {"friendly_name": "Tasting", "brightness": 120,
                                         "access_token": "must-not-leak", "private": {"x": 1}}})
    assert value["attributes"] == {"friendly_name": "Tasting", "brightness": 120}


def test_audit_redacts_secrets_and_detects_tampering(tmp_path: Path):
    audit = AuditLog(tmp_path / "audit.db", b"a" * 32)
    audit.append(actor_type="test", action="login", outcome="allowed",
                 metadata={"token": "never-store-me", "nested": {"pin": "1234"}})
    event = audit.recent(1)[0]
    assert event["metadata"] == {"nested": {"pin": "[REDACTED]"}, "token": "[REDACTED]"}
    assert audit.verify() == (True, None)
    with sqlite3.connect(tmp_path / "audit.db") as connection:
        connection.execute("UPDATE audit_events SET outcome='changed' WHERE seq=1")
    assert audit.verify() == (False, 1)


def test_end_to_end_share_login_read_command_and_revoke(runtime):
    admin = TestClient(create_admin_app(runtime))
    guest = TestClient(create_guest_app(runtime))
    headers = {"x-hass-user-id": "admin-1"}
    boot = admin.get("/api/admin/bootstrap", headers=headers).json()
    write = {**headers, "X-eControl-CSRF": boot["csrf"]}

    profile = admin.post("/api/admin/profiles", headers=write, json={"name": "Ospiti"}).json()
    inspected = admin.post("/api/admin/import/inspect", headers=write,
                           json={"dashboard": "manual", "config": dashboard_config()}).json()
    safe = next(item for item in inspected["cards"] if item["card_type"] == "entities")
    card = admin.post(f"/api/admin/profiles/{profile['id']}/cards/import", headers=write,
                      json={"dashboard": "manual", "source_ref": safe["source_ref"],
                            "config": dashboard_config()}).json()
    profile_view = admin.get(f"/api/admin/profiles/{profile['id']}", headers=headers).json()
    assert profile_view["dashboard"]["cards"][0]["config"]["entities"][0]["name"] == "Tasting Room"
    permissions = {"light.tasting": {"read": True, "actions": ["turn_on", "turn_off"],
                                      "limits": {}}}
    assert admin.put(f"/api/admin/cards/{card['id']}/permissions", headers=write,
                     json={"permissions": permissions}).status_code == 200
    revision = admin.get(
        f"/api/admin/profiles/{profile['id']}", headers=headers
    ).json()["dashboard"]["profile"]["revision"]
    saved_all = admin.put(f"/api/admin/profiles/{profile['id']}/permissions", headers=write,
                          json={"cards": {card["id"]: permissions}})
    assert saved_all.status_code == 200
    assert saved_all.json()["profile"]["revision"] == revision + 1
    assert saved_all.json()["cards"][0]["permissions"] == permissions
    assert admin.post(f"/api/admin/profiles/{profile['id']}/shares", headers=write,
                      json={"label": "Senza PIN", "pin": None, "valid_minutes": None,
                            "max_sessions": 1}).status_code == 400
    permanent = admin.post(f"/api/admin/profiles/{profile['id']}/shares", headers=write,
                           json={"label": "Ospite permanente", "pin": "1357", "valid_minutes": None,
                                 "max_sessions": 1})
    assert permanent.status_code == 200
    assert permanent.json()["share"]["expires_at"] > 250_000_000_000
    shared = admin.post(f"/api/admin/profiles/{profile['id']}/shares", headers=write,
                        json={"label": "Ospite temporaneo", "pin": "2468", "valid_minutes": 60,
                              "max_sessions": 1}).json()
    assert urlsplit(shared["fragment_url"]).path == "/guest-access"
    raw_token = shared["fragment_url"].split("#token=", 1)[1]
    database_text = (runtime.settings.data_dir / "guest.db").read_bytes()
    assert raw_token.encode() not in database_text
    assert b"2468" not in database_text

    assert guest.post("/api/guest/login", json={"token": raw_token, "pin": "0000"}).status_code == 401
    login = guest.post("/api/guest/login", json={"token": raw_token, "pin": "2468"})
    assert login.status_code == 200
    csrf = login.json()["csrf"]
    view = guest.get("/api/guest/dashboard")
    assert view.status_code == 200
    assert view.json()["cards"][0]["states"][0]["state"] == "off"
    audit_events = admin.get("/api/admin/audit", headers=headers).json()["events"]
    guest_views = [event for event in audit_events if event["action"] == "dashboard_view"]
    assert guest_views[0]["metadata"]["label"] == "Ospite temporaneo"
    assert guest_views[0]["metadata"]["entities"] == 1

    request_id = "b3b55223-6632-4135-9314-a1765fc0a25d"
    action = {"request_id": request_id, "card_id": card["id"],
              "entity_id": "light.tasting", "action": "turn_on", "value": None}
    result = guest.post("/api/guest/action", headers={"X-eControl-CSRF": csrf}, json=action)
    assert result.status_code == 200
    assert result.json()["readback"]["state"] == "on"
    duplicate = guest.post("/api/guest/action", headers={"X-eControl-CSRF": csrf}, json=action)
    assert duplicate.status_code == 200
    assert len(runtime.adapter.commands) == 1

    denied = {**action, "request_id": "c2ac9d38-4b9e-4482-8792-a56ada9ea1cf",
              "entity_id": "switch.not_shared"}
    assert guest.post("/api/guest/action", headers={"X-eControl-CSRF": csrf}, json=denied).status_code == 403
    assert runtime.audit.verify() == (True, None)
    command_events = [x for x in runtime.audit.recent(200) if x["action"] == "command_readback"]
    assert command_events[0]["metadata"]["entity_name"] == "Tasting Room"

    share_id = shared["share"]["id"]
    assert admin.request("DELETE", f"/api/admin/shares/{share_id}", headers=write,
                         json={"reason": "Fine soggiorno"}).status_code == 200
    revoked = next(item for item in admin.get(
        f"/api/admin/profiles/{profile['id']}", headers=headers).json()["shares"]
                   if item["id"] == share_id)
    assert revoked["label"] == "Ospite temporaneo"
    assert revoked["revoked_reason"] == "Fine soggiorno"
    assert revoked["revoked_by"] == "admin-1"
    assert guest.get("/api/guest/dashboard").status_code == 401


def test_guest_entry_uses_dedicated_non_share_path(runtime):
    guest = TestClient(create_guest_app(runtime))
    assert guest.get("/guest-access").status_code == 200
    assert guest.get("/share").status_code == 404


def test_admin_requires_ingress(runtime):
    client = TestClient(create_admin_app(runtime))
    runtime.settings = Settings(data_dir=runtime.settings.data_dir, development_admin=False)
    assert client.get("/").status_code == 403
    assert client.get("/health").status_code == 403
    runtime.settings = Settings(data_dir=runtime.settings.data_dir, development_admin=True)
    assert client.get("/health").status_code == 200
