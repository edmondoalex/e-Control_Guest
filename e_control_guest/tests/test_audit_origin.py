"""Synthetic origin and pagination checks; never contact an installation."""
from pathlib import Path
import asyncio
import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from starlette.requests import Request

from app.audit import AuditLog
from app.runtime import build_runtime
from app.settings import Settings
from app.admin_api import create_admin_app
from app.guest_api import create_guest_app
from test_security_baseline import FakeAdapter, provision


def request(peer, headers=()):
    return Request({"type": "http", "method": "GET", "path": "/", "headers":
                    [(key.encode(), value.encode()) for key, value in headers],
                    "client": (peer, 1234), "server": ("origin.test", 8100), "scheme": "https"})


def test_direct_origin_ignores_forged_forwarded_and_country_headers(tmp_path):
    runtime = build_runtime(Settings(data_dir=tmp_path))
    origin = runtime.request_origin(request("8.8.8.8", [("x-forwarded-for", "1.1.1.1"),
                                ("cf-connecting-ip", "1.1.1.1"), ("cf-ipcountry", "IT")]))
    assert origin["client_ip"] == "8.8.8.8" and origin["country_code"] == ""
    assert origin["ip_source"] == "peer"


@pytest.mark.parametrize('proof', ['', 'bad', 's'*32])
def test_shared_gateway_requires_secret_proof_before_original_ip_and_city(tmp_path, proof):
    settings=Settings(data_dir=tmp_path,cloudflare_proxy_cidrs=('172.30.32.1/32',),
                      trusted_proxy_cidrs=('172.30.32.1/32',),cloudflare_proxy_secret='s'*32)
    runtime=build_runtime(settings)
    headers=[('cf-connecting-ip','1.1.1.1'),('cf-ipcountry','IT'),('cf-ipcity','Città sintetica'),
             ('x-forwarded-for','8.8.8.8'),('x-econtrol-proxy-secret',proof)]
    origin=runtime.request_origin(request('172.30.32.1',headers))
    if proof=='s'*32:
        assert origin['client_ip']=='1.1.1.1' and origin['city']=='Città sintetica'
        assert origin['city_source']=='cloudflare' and origin['country_code']=='IT'
    else:
        assert origin['client_ip']=='172.30.32.1' and not origin['city'] and not origin['country_code']
        assert origin['ip_source']=='proxy_unresolved'
    assert 's'*32 not in json.dumps(origin) and 's'*32 not in repr(settings)


def test_shared_gateway_without_configured_secret_cannot_supply_identity(tmp_path):
    runtime=build_runtime(Settings(data_dir=tmp_path,cloudflare_proxy_cidrs=('172.30.32.1/32',)))
    result=runtime.request_origin(request('172.30.32.1',[('cf-connecting-ip','1.1.1.1'),('cf-ipcountry','IT')]))
    assert result['client_ip']=='172.30.32.1' and result['ip_source']=='proxy_unresolved'


def test_city_headers_are_trusted_bounded_unique_and_never_from_worker_or_direct(tmp_path):
    from app.origin import request_origin
    settings=Settings(data_dir=tmp_path,cloudflare_proxy_cidrs=('172.30.33.3/32',))
    base=[('cf-connecting-ip','1.1.1.1'),('cf-ipcountry','IT')]
    for city in ['<script>','a'*101,'fake\x00city']:
        assert request_origin(request('172.30.33.3',base+[('cf-ipcity',city)]),settings)['city']==''
    for more in [[('cf-ipcity','A'),('cf-ipcity','B')],[('cf-ipcity','A'),('cf-worker','example.test')]]:
        assert request_origin(request('172.30.33.3',base+more),settings)['city']==''
    assert request_origin(request('8.8.8.8',base+[('cf-ipcity','A')]),settings)['city']==''
    assert request_origin(request('172.30.33.3',base+[('cf-ipcity','A')]),settings)['city']=='A'


def test_duplicate_proxy_secret_cannot_pass_and_secret_never_enters_signed_audit(tmp_path):
    runtime=build_runtime(Settings(data_dir=tmp_path,cloudflare_proxy_cidrs=('172.30.32.1/32',),cloudflare_proxy_secret='s'*32))
    headers=[('cf-connecting-ip','1.1.1.1'),('x-econtrol-proxy-secret','s'*32)]
    result=runtime.request_origin(request('172.30.32.1',headers+headers[-1:]))
    assert result['client_ip']=='172.30.32.1'
    with runtime.audit.request_context(runtime.request_origin(request('172.30.32.1',headers))):
        runtime.audit.append(actor_type='guest',action='login',outcome='allowed')
    assert 's'*32 not in json.dumps(runtime.audit.page())


def test_pages_cover_retained_history_and_snapshot_does_not_shift_on_append(tmp_path):
    audit = AuditLog(tmp_path / "audit.db", b"s" * 32)
    for number in range(205):
        audit.append(actor_type="guest", action="login", outcome="allowed", metadata={"number": number})
    first = audit.page()
    assert len(first["events"]) == 100 and first["total"] == 205 and first["pages"] == 3
    audit.append(actor_type="guest", action="new", outcome="allowed")
    second = audit.page(page=2, snapshot_seq=first["snapshot_seq"])
    last = audit.page(page=3, snapshot_seq=first["snapshot_seq"])
    seqs = [event["seq"] for group in (first, second, last) for event in group["events"]]
    assert seqs == list(range(205, 0, -1))
    assert audit.verify() == (True, None)


@pytest.mark.parametrize("headers,expected", [
    ([("x-forwarded-for", "9.9.9.9, 1.1.1.1")], "1.1.1.1"),
    ([("x-forwarded-for", "1.1.1.1, 172.30.33.4")], "1.1.1.1"),
    ([("x-forwarded-for", "2001:4860:4860::8888")], "2001:4860:4860::8888"),
    ([("x-forwarded-for", "invalid, 1.1.1.1")], "172.30.33.3"),
    ([("x-forwarded-for", "1.1.1.1"), ("x-forwarded-for", "8.8.8.8")], "172.30.33.3"),
    ([("x-forwarded-for", "1.1.1.1," * 30 + "8.8.8.8")], "172.30.33.3"),
    ([("x-forwarded-for", "x" * 2050)], "172.30.33.3"),
    ([("x-forwarded-for", "172.30.33.4")], "172.30.33.3"),
])
def test_forwarded_chain_stops_at_first_untrusted_hop_and_rejects_malformed_input(tmp_path, headers, expected):
    runtime = build_runtime(Settings(data_dir=tmp_path, trusted_proxy_cidrs=("172.30.33.0/24", "invalid")))
    origin = runtime.request_origin(request("172.30.33.3", headers + [("cf-ipcountry", "IT")]))
    assert origin["client_ip"] == expected and origin["country_code"] == ""
    assert origin["ip_source"] == ("forwarded" if expected != "172.30.33.3" else "proxy_unresolved")


@pytest.mark.parametrize("code,expected", [("IT", "IT"), ("us", "US"), ("XX", ""),
                                            ("T1", "T1"), ("ZZ", ""), ("<script>", "")])
def test_country_only_from_explicit_cloudflare_connector(tmp_path, code, expected):
    headers = [("cf-connecting-ip", "1.1.1.1"), ("cf-ipcountry", code)]
    generic = build_runtime(Settings(data_dir=tmp_path / "generic", trusted_proxy_cidrs=("172.30.33.3/32",)))
    assert generic.request_origin(request("172.30.33.3", headers))["country_code"] == ""
    cloud = build_runtime(Settings(data_dir=tmp_path / "cloud", cloudflare_proxy_cidrs=("172.30.33.3/32",)))
    result = cloud.request_origin(request("172.30.33.3", headers))
    assert result["client_ip"] == "1.1.1.1" and result["country_code"] == expected
    assert result["country_source"] == ("cloudflare" if expected else "")


def test_cloudflare_special_ipv6_duplicates_local_and_worker_are_not_invented(tmp_path):
    runtime = build_runtime(Settings(data_dir=tmp_path, cloudflare_proxy_cidrs=("172.30.33.3/32",)))
    base = [("cf-connecting-ip", "1.1.1.1"), ("cf-ipcountry", "IT")]
    assert runtime.request_origin(request("172.30.33.3", base + [("cf-ipcountry", "US")]))["country_code"] == ""
    assert runtime.request_origin(request("172.30.33.3", base + [("cf-worker", "example.test")]))["country_code"] == ""
    pseudo = [("cf-connecting-ip", "240.1.2.3"), ("cf-connecting-ipv6", "2001:4860:4860::8888"), ("cf-ipcountry", "US")]
    assert runtime.request_origin(request("172.30.33.3", pseudo))["client_ip"] == "2001:4860:4860::8888"
    assert runtime.request_origin(request("172.30.33.3", base + [("cf-connecting-ipv6", "2001:4860:4860::8888")]))["client_ip"] == "1.1.1.1"
    assert runtime.request_origin(request("172.30.33.3", [("cf-connecting-ip", "192.168.1.4"), ("cf-ipcountry", "IT")]))["country_code"] == ""
    assert runtime.request_origin(request("::ffff:172.30.33.3", base))["client_ip"] == "1.1.1.1"


def test_origin_context_is_request_local_and_legacy_chain_is_unchanged(tmp_path):
    audit = AuditLog(tmp_path / "audit.db", b"r" * 32)
    old = audit.append(actor_type="guest", action="old", outcome="allowed")
    async def record(ip):
        with audit.request_context({"client_ip": ip, "country_code": "IT"}):
            await asyncio.sleep(0)
            audit.append(actor_type="guest", action=ip, outcome="allowed", metadata={"origin": {"client_ip": "forged"}})
    async def run():
        await asyncio.gather(record("1.1.1.1"), record("8.8.8.8"))
    asyncio.run(run())
    audit.append(actor_type="system", action="after", outcome="allowed")
    events = audit.page()["events"]
    assert "origin" not in events[0]["metadata"]
    for row in events[1:3]: assert row["action"] == row["metadata"]["origin"]["client_ip"]
    assert events[-1]["event_hash"] == old["event_hash"] and "origin" not in events[-1]["metadata"]
    assert audit.verify() == (True, None)


def test_login_success_denied_and_http_events_capture_origin_without_credentials(tmp_path):
    runtime = build_runtime(Settings(data_dir=tmp_path, development_admin=True, allow_insecure_local_http=True,
                                    cloudflare_proxy_cidrs=("172.30.33.3/32",)), adapter=FakeAdapter())
    _, token, _ = provision(runtime, pin="456789")
    async def run():
        transport = httpx.ASGITransport(app=create_guest_app(runtime), client=("172.30.33.3", 1234))
        async with httpx.AsyncClient(transport=transport, base_url="http://guest.test",
                                   headers={"CF-Connecting-IP": "1.1.1.1", "CF-IPCountry": "IT"}) as client:
            assert (await client.post("/api/guest/login", json={"token": token, "pin": "000000"})).status_code == 401
            assert (await client.post("/api/guest/login", json={"token": token, "pin": "456789"})).status_code == 200
            assert (await client.get("/api/admin/audit")).status_code == 404
    asyncio.run(run())
    events = runtime.audit.page()["events"]
    logins = [e for e in events if e["action"] == "login"]
    assert {e["outcome"] for e in logins} == {"allowed", "denied"}
    assert all(e["metadata"]["origin"]["client_ip"] == "1.1.1.1" for e in events)
    assert all(e["metadata"]["origin"]["country_code"] == "IT" for e in logins)
    serialized = json.dumps([event["metadata"] for event in events])
    assert token not in json.dumps(events)
    assert '"456789"' not in serialized and '"000000"' not in serialized
    assert not runtime.adapter.commands and runtime.audit.verify() == (True, None)


def test_global_search_history_beyond1000_labels_limit_and_validation(tmp_path):
    runtime = build_runtime(Settings(data_dir=tmp_path, development_admin=True), adapter=FakeAdapter())
    share, _, _ = provision(runtime)
    session = runtime.store.authenticate_share(runtime.store.recover_share_token(share["id"]), "1234",
                                               csrf_token="synthetic-csrf", device_token="synthetic-device", lifetime_seconds=300)
    old = runtime.audit.append(actor_type="guest", session_id=session["id"], action="login", outcome="allowed")
    for _ in range(1005): runtime.audit.append(actor_type="guest", action="http_request", outcome="allowed")
    client = TestClient(create_admin_app(runtime))
    first = client.get("/api/admin/audit?limit=1000").json()
    assert len(first["events"]) == 100 and first["total"] == 1006 and first["pages"] == 11
    last = client.get(f"/api/admin/audit?page=11&snapshot_seq={first['snapshot_seq']}").json()
    assert last["events"][-1]["seq"] == old["seq"]
    found = client.get("/api/admin/audit", params={"q": "Ospite test"}).json()
    assert len(found["events"]) == 1 and found["events"][0]["metadata"]["label"] == "Ospite test"
    assert client.get("/api/admin/audit", params={"q": "effettuato l’accesso"}).json()["total"] == 1
    assert client.get("/api/admin/audit", params={"q": "' OR 1=1 --"}).json()["total"] == 0
    for params in ({"page": 0}, {"page": 10001}, {"q": "x"*201}, {"snapshot_seq": -1}, {"snapshot_seq": 2**63}):
        assert client.get("/api/admin/audit", params=params).status_code == 422
    assert runtime.audit.verify() == (True, None)


def test_audit_remains_ingress_only_and_uvicorn_does_not_rewrite_peer(tmp_path):
    runtime = build_runtime(Settings(data_dir=tmp_path), adapter=FakeAdapter())
    client = TestClient(create_admin_app(runtime))
    assert client.get("/api/admin/audit", headers={"X-Ingress-Path": "/test", "X-Forwarded-For": "172.30.32.2"}).status_code == 403
    source = (Path(__file__).parents[1] / "app" / "__main__.py").read_text(encoding="utf-8")
    assert source.count("proxy_headers=False") == 2


def test_real_ingress_peer_still_works_and_country_trust_defaults_to_empty(tmp_path):
    runtime = build_runtime(Settings(data_dir=tmp_path), adapter=FakeAdapter())
    assert runtime.settings.cloudflare_proxy_cidrs == ()
    async def run():
        transport = httpx.ASGITransport(app=create_admin_app(runtime), client=("172.30.32.2", 1234))
        async with httpx.AsyncClient(transport=transport, base_url="http://admin.test") as client:
            response = await client.get("/api/admin/audit", headers={"X-Ingress-Path": "/synthetic"})
            assert response.status_code == 200 and response.json()["page_size"] == 100
    asyncio.run(run())
    assert runtime.request_origin(request("8.8.8.8", [("cf-ipcountry", "IT")]))["country_code"] == ""


def test_retention_clamps_last_page_and_tampering_is_still_reported(tmp_path):
    audit = AuditLog(tmp_path / "retained.db", b"r" * 32, retention_days=30)
    audit.append(actor_type="guest", action="old", outcome="allowed", occurred_at="2000-01-01T00:00:00+00:00")
    for _ in range(100): audit.append(actor_type="guest", action="login", outcome="allowed")
    first = audit.page()
    assert first["pages"] == 2
    assert audit.prune()["deleted"] == 1
    page = audit.page(page=2, snapshot_seq=first["snapshot_seq"])
    assert page["page"] == page["pages"] == 1 and len(page["events"]) == 100
    assert audit.verify() == (True, None)
    import sqlite3
    with sqlite3.connect(audit.database) as connection:
        connection.execute("UPDATE audit_events SET outcome='denied' WHERE seq=2")
    assert audit.verify() == (False, 2)
    assert audit.page()["valid"] is False and audit.page()["broken_at"] == 2


def test_forwarding_does_not_trust_all_internet_or_change_rate_bucket_with_forged_prefix(tmp_path):
    runtime = build_runtime(Settings(data_dir=tmp_path, trusted_proxy_cidrs=("172.30.33.3/32",)))
    left = request("172.30.33.3", [("x-forwarded-for", "9.9.9.9, 1.1.1.1")])
    right = request("172.30.33.3", [("x-forwarded-for", "8.8.8.8, 1.1.1.1")])
    assert runtime.network_id(left) == runtime.network_id(right)
    all_trusted = build_runtime(Settings(data_dir=tmp_path / "all", cloudflare_proxy_cidrs=("0.0.0.0/0", "::/0")))
    assert all_trusted.request_origin(request("8.8.8.8", [("cf-connecting-ip", "1.1.1.1"), ("cf-ipcountry", "IT")]))["country_code"] == ""
