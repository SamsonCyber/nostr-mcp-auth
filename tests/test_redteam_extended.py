"""Full red-team matrix against shipped verifier + HTTP gate."""
from __future__ import annotations

import base64
import json
import time

import httpx
import pytest

from nostr_mcp_auth.config import load_config
from nostr_mcp_auth.crypto import (
    generate_private_key_hex,
    npub_encode,
    sign_event,
    xonly_pubkey_hex,
)
from nostr_mcp_auth.nip98 import (
    AuthError,
    build_auth_event,
    encode_authorization_header,
    verify_authorization_header,
    verify_nip98_event,
)
from nostr_mcp_auth.server import TOOL_INVOCATIONS, create_app, reset_tool_invocations


@pytest.fixture
def keys():
    sk = generate_private_key_hex()
    pk = xonly_pubkey_hex(sk)
    return sk, pk, npub_encode(pk)


@pytest.fixture
def app_cfg(keys):
    sk, pk, npub = keys
    cfg = load_config(
        raw={
            "auth": {
                "allow_npubs": [npub],
                "deny_npubs": [],
                "roles": {npub: ["tools:admin"]},
                "max_skew_seconds": 60,
                "replay_ttl_seconds": 120,
            },
            "tools": {"admin_ping": {"roles": ["tools:admin"]}},
        }
    )
    reset_tool_invocations()
    return create_app(cfg), sk, pk, npub, cfg


async def signed_post(app, sk, rpc: dict):
    body = json.dumps(rpc, separators=(",", ":")).encode()
    url = "http://test/mcp"
    headers = {
        "Content-Type": "application/json",
        "Authorization": encode_authorization_header(
            build_auth_event(sk, url=url, method="POST", body=body)
        ),
        "Host": "test",
    }
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/mcp", content=body, headers=headers)


# --- pure verifier attacks ---


def test_kind_list_is_auth_error_not_500(keys):
    sk, pk, npub = keys
    url = "http://x/mcp"
    body = b"{}"
    ev = build_auth_event(sk, url=url, method="POST", body=body)
    ev = dict(ev)
    ev["kind"] = [27235]
    with pytest.raises(AuthError) as ei:
        verify_nip98_event(ev, url=url, method="POST", body=body)
    assert ei.value.reason == "wrong_kind"


def test_kind_bool_rejected(keys):
    sk, pk, npub = keys
    url = "http://x/mcp"
    body = b"{}"
    ev = build_auth_event(sk, url=url, method="POST", body=body)
    ev = dict(ev)
    ev["kind"] = True
    with pytest.raises(AuthError):
        verify_nip98_event(ev, url=url, method="POST", body=body)


def test_scheme_must_be_exact_Nostr(keys):
    sk, pk, npub = keys
    url = "http://x/mcp"
    body = b"{}"
    tok = encode_authorization_header(build_auth_event(sk, url=url, method="POST", body=body)).split(
        " ", 1
    )[1]
    for bad in ("nostr " + tok, "NOSTR " + tok, "Bearer " + tok, "Nostr" + tok):
        with pytest.raises(AuthError) as ei:
            verify_authorization_header(bad, url=url, method="POST", body=body)
        assert ei.value.reason in ("invalid_scheme", "missing_authorization", "invalid_token_encoding")


def test_base64_internal_whitespace_rejected(keys):
    sk, pk, npub = keys
    url = "http://x/mcp"
    body = b"{}"
    ev = build_auth_event(sk, url=url, method="POST", body=body)
    raw = json.dumps(ev, separators=(",", ":")).encode()
    tok = base64.b64encode(raw).decode()
    messy = tok[:15] + "\n" + tok[15:]
    with pytest.raises(AuthError) as ei:
        verify_authorization_header(f"Nostr {messy}", url=url, method="POST", body=body)
    assert ei.value.reason == "invalid_token_encoding"


def test_nonempty_content_rejected(keys):
    sk, pk, npub = keys
    url = "http://x/mcp"
    body = b"hi"
    tags = [["u", url], ["method", "POST"], ["payload", __import__("hashlib").sha256(body).hexdigest()]]
    ev = sign_event(sk, {"created_at": int(time.time()), "kind": 27235, "tags": tags, "content": "x"})
    with pytest.raises(AuthError) as ei:
        verify_nip98_event(ev, url=url, method="POST", body=body)
    assert ei.value.reason == "invalid_content"


def test_ambiguous_u_tags_rejected(keys):
    sk, pk, npub = keys
    url = "http://x/mcp"
    body = b"{}"
    tags = [["u", url], ["u", "http://evil/mcp"], ["method", "POST"]]
    ev = sign_event(sk, {"created_at": int(time.time()), "kind": 27235, "tags": tags, "content": ""})
    with pytest.raises(AuthError) as ei:
        verify_nip98_event(ev, url=url, method="POST", body=body)
    assert ei.value.reason == "ambiguous_u"


def test_payload_without_body_rejected(keys):
    sk, pk, npub = keys
    url = "http://x/mcp"
    body = b"data"
    ev = build_auth_event(sk, url=url, method="POST", body=body)
    # send empty body while event has payload
    with pytest.raises(AuthError) as ei:
        verify_nip98_event(ev, url=url, method="POST", body=b"")
    assert ei.value.reason == "payload_without_body"


def test_deny_list_blocks_even_if_allowlisted(keys):
    sk, pk, npub = keys
    cfg = load_config(raw={"auth": {"allow_npubs": [npub], "deny_npubs": [npub]}})
    from nostr_mcp_auth.gate import AuthGate

    gate = AuthGate(cfg)
    url = "http://x/mcp"
    body = b"{}"
    h = encode_authorization_header(build_auth_event(sk, url=url, method="POST", body=body))
    with pytest.raises(AuthError) as ei:
        gate.authenticate(authorization=h, url=url, method="POST", body=body)
    assert ei.value.reason == "denied_npub"


# --- HTTP attacks ---


@pytest.mark.asyncio
async def test_http_kind_list_returns_401_not_500(app_cfg):
    app, sk, pk, npub, cfg = app_cfg
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "whoami", "arguments": {}},
        },
        separators=(",", ":"),
    ).encode()
    ev = build_auth_event(sk, url="http://test/mcp", method="POST", body=body)
    ev = dict(ev)
    ev["kind"] = [27235]
    headers = {
        "Content-Type": "application/json",
        "Authorization": encode_authorization_header(ev),
        "Host": "test",
    }
    reset_tool_invocations()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/mcp", content=body, headers=headers)
    assert r.status_code == 401
    assert TOOL_INVOCATIONS == []


@pytest.mark.asyncio
async def test_http_bearer_rejected(app_cfg):
    app, sk, pk, npub, cfg = app_cfg
    body = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/mcp",
            content=body,
            headers={"Content-Type": "application/json", "Authorization": "Bearer secret"},
        )
    assert r.status_code == 401
    assert TOOL_INVOCATIONS == []


@pytest.mark.asyncio
async def test_http_wrong_host_binding(app_cfg):
    """Sign for evil host; request hits real server → url_mismatch."""
    app, sk, pk, npub, cfg = app_cfg
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "whoami", "arguments": {}},
        },
        separators=(",", ":"),
    ).encode()
    # sign as if destined for attacker host
    ev = build_auth_event(sk, url="http://evil.example/mcp", method="POST", body=body)
    headers = {
        "Content-Type": "application/json",
        "Authorization": encode_authorization_header(ev),
        "Host": "test",
    }
    reset_tool_invocations()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/mcp", content=body, headers=headers)
    assert r.status_code == 401
    assert r.json()["code"] == "unauthorized"
    assert TOOL_INVOCATIONS == []


@pytest.mark.asyncio
async def test_http_get_mcp_no_tool_dispatch(app_cfg):
    app, sk, pk, npub, cfg = app_cfg
    reset_tool_invocations()
    # unauthenticated GET
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/mcp")
    assert r.status_code == 401
    assert TOOL_INVOCATIONS == []


@pytest.mark.asyncio
async def test_http_allow_still_works(app_cfg):
    app, sk, pk, npub, cfg = app_cfg
    reset_tool_invocations()
    r = await signed_post(
        app,
        sk,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "whoami", "arguments": {}},
        },
    )
    assert r.status_code == 200
    payload = json.loads(r.json()["result"]["content"][0]["text"])
    assert payload["pubkey"] == pk
    assert any(i["tool"] == "whoami" for i in TOOL_INVOCATIONS)


@pytest.mark.asyncio
async def test_http_body_swap_after_sign(app_cfg):
    app, sk, pk, npub, cfg = app_cfg
    rpc_a = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "whoami", "arguments": {}},
    }
    rpc_b = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "protected_echo", "arguments": {"text": "pwn"}},
    }
    body_a = json.dumps(rpc_a, separators=(",", ":")).encode()
    body_b = json.dumps(rpc_b, separators=(",", ":")).encode()
    headers = {
        "Content-Type": "application/json",
        "Authorization": encode_authorization_header(
            build_auth_event(sk, url="http://test/mcp", method="POST", body=body_a)
        ),
        "Host": "test",
    }
    reset_tool_invocations()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/mcp", content=body_b, headers=headers)
    assert r.status_code == 401
    assert r.json()["code"] == "unauthorized"
    assert TOOL_INVOCATIONS == []
