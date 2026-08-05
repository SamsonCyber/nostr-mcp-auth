"""HTTP MCP entry: allow path + negatives never run tools."""
from __future__ import annotations

import json

import httpx
import pytest

from nostr_mcp_auth.config import AuthConfig, load_config
from nostr_mcp_auth.crypto import generate_private_key_hex, npub_encode, xonly_pubkey_hex
from nostr_mcp_auth.nip98 import build_auth_event, encode_authorization_header
from nostr_mcp_auth.server import TOOL_INVOCATIONS, create_app, reset_tool_invocations


@pytest.fixture
def identity():
    sk = generate_private_key_hex()
    pk = xonly_pubkey_hex(sk)
    return sk, pk, npub_encode(pk)


@pytest.fixture
def app(identity):
    sk, pk, npub = identity
    cfg = load_config(
        raw={
            "auth": {
                "open": False,
                "allow_npubs": [npub],
                "roles": {npub: ["tools:admin"]},
                "max_skew_seconds": 60,
                "replay_ttl_seconds": 120,
            },
            "tools": {"admin_ping": {"roles": ["tools:admin"]}},
        }
    )
    reset_tool_invocations()
    return create_app(cfg), sk, pk


async def _signed_post(app, sk, rpc: dict):
    body = json.dumps(rpc, separators=(",", ":")).encode("utf-8")
    url = "http://test/mcp"
    event = build_auth_event(sk, url=url, method="POST", body=body)
    headers = {
        "Content-Type": "application/json",
        "Authorization": encode_authorization_header(event),
        "Host": "test",
    }
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/mcp", content=body, headers=headers)


@pytest.mark.asyncio
async def test_health_no_auth(app):
    application, sk, pk = app
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_missing_auth_no_tool_side_effect(app):
    application, sk, pk = app
    reset_tool_invocations()
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "protected_echo", "arguments": {"text": "x"}},
        }
    ).encode()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/mcp", content=body, headers={"Content-Type": "application/json"})
    assert r.status_code == 401
    assert r.json()["code"] == "unauthorized"
    assert "reason" not in r.json()
    assert TOOL_INVOCATIONS == []


@pytest.mark.asyncio
async def test_allowlisted_whoami_success(app):
    application, sk, pk = app
    reset_tool_invocations()
    r = await _signed_post(
        application,
        sk,
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "whoami", "arguments": {}},
        },
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert "result" in data
    text = data["result"]["content"][0]["text"]
    payload = json.loads(text)
    assert payload["ok"] is True
    assert payload["pubkey"] == pk
    assert any(i["tool"] == "whoami" for i in TOOL_INVOCATIONS)


@pytest.mark.asyncio
async def test_not_allowlisted_no_tool(identity):
    sk, pk, npub = identity
    other_sk = generate_private_key_hex()
    cfg = load_config(raw={"auth": {"open": False, "allow_npubs": [npub]}})
    application = create_app(cfg)
    reset_tool_invocations()
    r = await _signed_post(
        application,
        other_sk,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "whoami", "arguments": {}},
        },
    )
    assert r.status_code == 401
    assert r.json()["code"] == "unauthorized"
    assert TOOL_INVOCATIONS == []


@pytest.mark.asyncio
async def test_empty_allowlist_denies_all(identity):
    sk, pk, npub = identity
    cfg = AuthConfig(open=False, allow_pubkeys=set())
    application = create_app(cfg)
    reset_tool_invocations()
    r = await _signed_post(
        application,
        sk,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "whoami", "arguments": {}},
        },
    )
    assert r.status_code == 401
    assert r.json()["code"] == "unauthorized"
    assert TOOL_INVOCATIONS == []


@pytest.mark.asyncio
async def test_admin_role_required(app):
    application, sk, pk = app
    reset_tool_invocations()
    r = await _signed_post(
        application,
        sk,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "admin_ping", "arguments": {}},
        },
    )
    assert r.status_code == 200
    assert any(i["tool"] == "admin_ping" for i in TOOL_INVOCATIONS)


@pytest.mark.asyncio
async def test_admin_role_denied_without_role(identity):
    sk, pk, npub = identity
    cfg = load_config(
        raw={
            "auth": {"allow_npubs": [npub], "roles": {}},
            "tools": {"admin_ping": {"roles": ["tools:admin"]}},
        }
    )
    application = create_app(cfg)
    reset_tool_invocations()
    r = await _signed_post(
        application,
        sk,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "admin_ping", "arguments": {}},
        },
    )
    assert r.status_code == 403
    assert TOOL_INVOCATIONS == []
