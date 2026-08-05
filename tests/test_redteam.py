"""Adversarial mutations against the shipped gate."""
from __future__ import annotations

import json
import time

import httpx
import pytest

from nostr_mcp_auth.config import load_config
from nostr_mcp_auth.crypto import generate_private_key_hex, npub_encode, xonly_pubkey_hex
from nostr_mcp_auth.gate import AuthGate
from nostr_mcp_auth.nip98 import AuthError, build_auth_event, encode_authorization_header
from nostr_mcp_auth.replay import ReplayCache
from nostr_mcp_auth.server import TOOL_INVOCATIONS, create_app, reset_tool_invocations


@pytest.fixture
def setup():
    sk = generate_private_key_hex()
    pk = xonly_pubkey_hex(sk)
    npub = npub_encode(pk)
    cfg = load_config(
        raw={
            "auth": {
                "allow_npubs": [npub],
                "max_skew_seconds": 60,
                "replay_ttl_seconds": 120,
            }
        }
    )
    app = create_app(cfg)
    reset_tool_invocations()
    return app, sk, pk, cfg


async def _call(app, sk, rpc, *, mutate_event=None):
    body = json.dumps(rpc, separators=(",", ":")).encode()
    url = "http://test/mcp"
    event = build_auth_event(sk, url=url, method="POST", body=body)
    if mutate_event:
        event = mutate_event(event)
    headers = {
        "Content-Type": "application/json",
        "Authorization": encode_authorization_header(event),
        "Host": "test",
    }
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/mcp", content=body, headers=headers)


def test_replay_rejected(setup):
    app, sk, pk, cfg = setup
    gate = AuthGate(cfg, replay=ReplayCache(ttl_seconds=120))
    url = "http://test/mcp"
    body = b"{}"
    event = build_auth_event(sk, url=url, method="POST", body=body)
    header = encode_authorization_header(event)
    gate.authenticate(authorization=header, url=url, method="POST", body=body)
    with pytest.raises(AuthError) as ei:
        gate.authenticate(authorization=header, url=url, method="POST", body=body)
    assert ei.value.reason == "replay"


@pytest.mark.asyncio
async def test_http_replay_second_request(setup):
    app, sk, pk, cfg = setup
    rpc = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "whoami", "arguments": {}},
    }
    body = json.dumps(rpc, separators=(",", ":")).encode()
    event = build_auth_event(sk, url="http://test/mcp", method="POST", body=body)
    headers = {
        "Content-Type": "application/json",
        "Authorization": encode_authorization_header(event),
        "Host": "test",
    }
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r1 = await client.post("/mcp", content=body, headers=headers)
        r2 = await client.post("/mcp", content=body, headers=headers)
    assert r1.status_code == 200, r1.text
    assert r2.status_code == 401
    assert r2.json()["reason"] == "replay"
    assert sum(1 for i in TOOL_INVOCATIONS if i["tool"] == "whoami") == 1


@pytest.mark.asyncio
async def test_mutate_pubkey_fails(setup):
    app, sk, pk, cfg = setup
    other = xonly_pubkey_hex(generate_private_key_hex())

    def mut(ev):
        ev = dict(ev)
        ev["pubkey"] = other
        return ev

    before = len(TOOL_INVOCATIONS)
    r = await _call(
        app,
        sk,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "whoami", "arguments": {}},
        },
        mutate_event=mut,
    )
    assert r.status_code == 401
    assert len(TOOL_INVOCATIONS) == before


@pytest.mark.asyncio
async def test_swap_method_in_event(setup):
    app, sk, pk, cfg = setup

    def mut(ev):
        tags = []
        for t in ev["tags"]:
            if t[0] == "method":
                tags.append(["method", "GET"])
            else:
                tags.append(t)
        ev = dict(ev)
        ev["tags"] = tags
        return ev

    before = len(TOOL_INVOCATIONS)
    r = await _call(
        app,
        sk,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "whoami", "arguments": {}},
        },
        mutate_event=mut,
    )
    assert r.status_code == 401
    assert len(TOOL_INVOCATIONS) == before


@pytest.mark.asyncio
async def test_expired_event(setup):
    app, sk, pk, cfg = setup
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "whoami", "arguments": {}},
        },
        separators=(",", ":"),
    ).encode()
    event = build_auth_event(
        sk,
        url="http://test/mcp",
        method="POST",
        body=body,
        created_at=int(time.time()) - 10_000,
    )
    headers = {
        "Content-Type": "application/json",
        "Authorization": encode_authorization_header(event),
        "Host": "test",
    }
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/mcp", content=body, headers=headers)
    assert r.status_code == 401
    assert r.json()["reason"] == "expired"
    assert not any(i["tool"] == "whoami" for i in TOOL_INVOCATIONS)


@pytest.mark.asyncio
async def test_strip_payload_tag(setup):
    app, sk, pk, cfg = setup
    body = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
    event = build_auth_event(sk, url="http://test/mcp", method="POST", body=body)
    event = dict(event)
    event["tags"] = [t for t in event["tags"] if t[0] != "payload"]
    headers = {
        "Content-Type": "application/json",
        "Authorization": encode_authorization_header(event),
        "Host": "test",
    }
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/mcp", content=body, headers=headers)
    assert r.status_code == 401
