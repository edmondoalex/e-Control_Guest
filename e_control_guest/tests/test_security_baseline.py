from __future__ import annotations

import sqlite3
import time
import uuid

from fastapi.testclient import TestClient

from app.audit import AuditLog
from app.crypto import hash_pin, verify_pin
from app.guest_api import create_guest_app
from app.importer import inspect_dashboard, snapshot
from app.policy import PolicyDenied, authorize
from app.runtime import build_runtime
from app.settings import Settings


class FakeAdapter:
    def __init__(self):
        self.commands = []
        self.state_calls = []
        self.states_calls = []

    async def state(self, entity_id):
        self.state_calls.append(entity_id)
        return {"entity_id": entity_id, "state": "on", "attributes": {}}

    async def states(self, entity_ids):
        self.states_calls.append(set(entity_ids))
        return {
            entity_id: {"entity_id": entity_id, "state": "on", "attributes": {}}
            for entity_id in entity_ids
        }

    async def execute(self, command):
        self.commands.append(command)
        return {"entity_id": command.entity_id, "state": "on", "attributes": {}}


def make_runtime(tmp_path):
    adapter = FakeAdapter()
    settings = Settings(data_dir=tmp_path, development_admin=True, session_minutes=30,
                        allow_insecure_local_http=True)
    return build_runtime(settings, adapter=adapter), adapter


def provision(runtime, *, pin="1234"):
    profile = runtime.store.create_profile("Ospiti")
    config = {"views": [{"title": "Casa", "cards": [{"type": "entity", "entity": "light.sala"}]}]}
    card = runtime.store.add_card(profile["id"], snapshot(inspect_dashboard(config)[0]))
    runtime.store.update_card_permissions(card["id"], {
        "light.sala": {"read": True, "actions": ["turn_on", "set_brightness"],
                       "limits": {"brightness": [10, 100]}}
    })
    profile = runtime.store.get_profile(profile["id"])
    share, token = runtime.store.create_share(profile["id"], label="Ospite test", pin=pin,
                                               expires_at=time.time() + 3600, max_sessions=2)
    return share, token, card


def login(client, token, pin="1234"):
    response = client.post("/api/guest/login", json={"token": token, "pin": pin})
    assert response.status_code == 200
    body = response.json()
    return {"X-eControl-CSRF": body["csrf"]}


def test_pin_uses_argon2id_and_rejects_wrong_value():
    digest = hash_pin("1234")
    assert digest.startswith("$argon2id$")
    assert verify_pin(digest, "1234")
    assert not verify_pin(digest, "9999")


def test_importer_rejects_custom_card_and_freezes_safe_snapshot():
    config = {"views": [{"cards": [
        {"type": "custom:unsafe", "entity": "light.bad"},
        {"type": "entity", "entity": "light.good", "tap_action": {"action": "call-service"}},
    ]}]}
    bad, good = inspect_dashboard(config)
    assert not bad.safe
    frozen = snapshot(good)
    assert frozen["entities"][0]["entity_id"] == "light.good"
    assert "tap_action" not in frozen
    assert frozen["permissions"]["light.good"]["actions"] == []


def test_heading_snapshot_is_display_only_and_preserves_title():
    config = {"views": [{"cards": [{"type": "heading", "heading": "INTERRATO"}]}]}
    frozen = snapshot(inspect_dashboard(config)[0])
    assert frozen["title"] == "INTERRATO"
    assert frozen["type"] == "heading"
    assert frozen["entities"] == []
    assert frozen["permissions"] == {}


def test_policy_is_fail_closed_and_enforces_ranges():
    permissions = {"light.sala": {"actions": ["set_brightness"],
                                   "limits": {"brightness": [10, 100]}}}
    assert authorize(permissions, "light.sala", "set_brightness", 80).data["brightness"] == 80
    for entity, action, value in [
        ("light.sala", "turn_off", None), ("light.altro", "set_brightness", 80),
        ("light.sala", "set_brightness", 200),
    ]:
        try:
            authorize(permissions, entity, action, value)
        except PolicyDenied:
            pass
        else:
            raise AssertionError("policy unexpectedly allowed command")


def test_guest_flow_revocation_idempotency_and_audit(tmp_path):
    runtime, adapter = make_runtime(tmp_path)
    share, token, card = provision(runtime)
    with TestClient(create_guest_app(runtime), base_url="http://guest.test") as client:
        headers = login(client, token)
        dashboard = client.get("/api/guest/dashboard", headers=headers)
        assert dashboard.status_code == 200
        request_id = str(uuid.uuid4())
        command = {"request_id": request_id, "card_id": card["id"], "entity_id": "light.sala",
                   "action": "set_brightness", "value": 50}
        first = client.post("/api/guest/action", headers=headers, json=command)
        second = client.post("/api/guest/action", headers=headers, json=command)
        assert first.status_code == second.status_code == 200
        assert first.json() == second.json()
        assert len(adapter.commands) == 1
        runtime.store.revoke_share(share["id"], reason="Fine test", actor_id="test-admin")
        assert client.get("/api/guest/dashboard", headers=headers).status_code == 401
    valid, broken_at = runtime.audit.verify()
    assert valid and broken_at is None
    actions = [event["action"] for event in runtime.audit.recent()]
    assert "command_request" in actions and "command_readback" in actions and "session_check" in actions


def test_dashboard_reads_all_entities_with_one_bulk_request(tmp_path):
    runtime, adapter = make_runtime(tmp_path)
    _, token, _ = provision(runtime)
    with TestClient(create_guest_app(runtime), base_url="http://guest.test") as client:
        login(client, token)
        response = client.get("/api/guest/dashboard")
    assert response.status_code == 200
    assert response.json()["polling_seconds"] == 60
    assert adapter.states_calls == [{"light.sala"}]
    assert adapter.state_calls == []
    actions = [event["action"] for event in runtime.audit.recent()]
    assert actions.count("dashboard_view") == 1
    assert "state_read" not in actions


def test_link_and_active_session_survive_profile_changes_until_manual_revoke(tmp_path):
    runtime, _ = make_runtime(tmp_path)
    share, token, card = provision(runtime)
    runtime.store.update_card_permissions(card["id"], {
        "light.sala": {"read": True, "actions": ["turn_on"], "limits": {}}
    })
    assert runtime.store.list_shares()[0]["revision_valid"] == 1
    with TestClient(create_guest_app(runtime), base_url="http://guest.test") as client:
        login(client, token)
        runtime.store.update_card_permissions(card["id"], {
            "light.sala": {"read": True, "actions": [], "limits": {}}
        })
        assert client.get("/api/guest/dashboard").status_code == 200
        runtime.store.delete_card(card["id"])
        dashboard = client.get("/api/guest/dashboard")
        assert dashboard.status_code == 200
        assert dashboard.json()["cards"] == []
        runtime.store.revoke_share(share["id"], reason="Fine accesso", actor_id="admin")
        assert client.get("/api/guest/dashboard").status_code == 401


def test_token_and_pin_are_not_persisted_or_logged(tmp_path):
    runtime, _ = make_runtime(tmp_path)
    _, token, _ = provision(runtime, pin="6789")
    with TestClient(create_guest_app(runtime), base_url="http://guest.test") as client:
        login(client, token, "6789")
    database_bytes = (tmp_path / "guest.db").read_bytes()
    audit_bytes = (tmp_path / "audit.db").read_bytes()
    assert token.encode() not in database_bytes + audit_bytes
    assert b"6789" not in database_bytes + audit_bytes


def test_audit_chain_detects_tampering(tmp_path):
    database = tmp_path / "audit.db"
    audit = AuditLog(database, b"k" * 32)
    audit.append(actor_type="guest", action="read", outcome="allowed")
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE audit_events SET outcome='denied' WHERE seq=1")
    assert audit.verify() == (False, 1)
