"""Document and lock residual risk behaviors on the shipped gate.

These are not "bugs to open the world by default"; they are known limits operators
must understand. Tests assert shipped behavior so regressions are caught.
"""
from __future__ import annotations

import json

import httpx
import pytest

from nostr_mcp_auth.config import AuthConfig, load_config
from nostr_mcp_auth.crypto import (
    generate_private_key_hex,
    npub_encode,
    xonly_pubkey_hex,
)
from nostr_mcp_auth.gate import AuthGate
from nostr_mcp_auth.nip98 import (
    AuthError,
    build_auth_event,
    encode_authorization_header,
)
from nostr_mcp_auth.replay import ReplayCache
from nostr_mcp_auth.server import TOOL_INVOCATIONS, create_app, reset_tool_invocations


def _whoami_body() -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "whoami", "arguments": {}},
        },
        separators=(",", ":"),
    ).encode()


async def _asgi_post(app, headers: dict, body: bytes):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/mcp", content=body, headers=headers)


@pytest.fixture
def identity():
    sk = generate_private_key_hex()
    pk = xonly_pubkey_hex(sk)
    return sk, pk, npub_encode(pk)


# ---------------------------------------------------------------------------
# 1) Process-local replay
# ---------------------------------------------------------------------------


def test_replay_is_process_local_across_gate_instances():
    """Two AuthGate instances do not share replay state (documented residual)."""
    sk = generate_private_key_hex()
    pk = xonly_pubkey_hex(sk)
    npub = npub_encode(pk)
    cfg = load_config(raw={"auth": {"allow_npubs": [npub], "replay_ttl_seconds": 120}})
    body = b'{"x":1}'
    url = "http://test/mcp"
    header = encode_authorization_header(
        build_auth_event(sk, url=url, method="POST", body=body)
    )

    g1 = AuthGate(cfg, replay=ReplayCache(120))
    g2 = AuthGate(cfg, replay=ReplayCache(120))

    g1.authenticate(authorization=header, url=url, method="POST", body=body)
    # same process, different cache instance: second gate still accepts (residual)
    ctx2 = g2.authenticate(authorization=header, url=url, method="POST", body=body)
    assert ctx2.pubkey == pk

    # same gate: second use is replay
    with pytest.raises(AuthError) as ei:
        g1.authenticate(authorization=header, url=url, method="POST", body=body)
    assert ei.value.reason == "replay"


def test_same_gate_rejects_replay():
    sk = generate_private_key_hex()
    npub = npub_encode(xonly_pubkey_hex(sk))
    cfg = load_config(raw={"auth": {"allow_npubs": [npub]}})
    gate = AuthGate(cfg)
    body = b"{}"
    url = "http://x/mcp"
    h = encode_authorization_header(build_auth_event(sk, url=url, method="POST", body=body))
    gate.authenticate(authorization=h, url=url, method="POST", body=body)
    with pytest.raises(AuthError) as ei:
        gate.authenticate(authorization=h, url=url, method="POST", body=body)
    assert ei.value.reason == "replay"


# ---------------------------------------------------------------------------
# 2) Operator open / trust_proxy
# ---------------------------------------------------------------------------


def test_open_mode_allows_any_valid_signature_not_on_allowlist():
    """auth.open=true is an explicit operator footgun: any valid NIP-98 identity works."""
    sk = generate_private_key_hex()
    pk = xonly_pubkey_hex(sk)
    # empty allowlist but open
    cfg = AuthConfig(open=True, allow_pubkeys=set())
    assert cfg.is_authorized(pk) == (True, "open")

    gate = AuthGate(cfg)
    body = b"{}"
    url = "http://test/mcp"
    h = encode_authorization_header(build_auth_event(sk, url=url, method="POST", body=body))
    ctx = gate.authenticate(authorization=h, url=url, method="POST", body=body)
    assert ctx.pubkey == pk


def test_open_false_empty_allowlist_still_denies():
    sk = generate_private_key_hex()
    cfg = AuthConfig(open=False, allow_pubkeys=set())
    ok, reason = cfg.is_authorized(xonly_pubkey_hex(sk))
    assert ok is False
    assert reason == "empty_allowlist"


@pytest.mark.asyncio
async def test_trust_proxy_true_uses_forwarded_host_for_u_binding():
    """When trust_proxy is on, client must sign the forwarded URL (operator responsibility)."""
    sk = generate_private_key_hex()
    pk = xonly_pubkey_hex(sk)
    npub = npub_encode(pk)
    cfg = load_config(
        raw={
            "auth": {
                "allow_npubs": [npub],
                "trust_proxy": True,
            }
        }
    )
    app = create_app(cfg)
    reset_tool_invocations()
    body = _whoami_body()
    # Server will reconstruct https://edge.example/mcp from forwarded headers
    signed_url = "https://edge.example/mcp"
    headers = {
        "Content-Type": "application/json",
        "Authorization": encode_authorization_header(
            build_auth_event(sk, url=signed_url, method="POST", body=body)
        ),
        "Host": "test",
        "X-Forwarded-Host": "edge.example",
        "X-Forwarded-Proto": "https",
    }
    r = await _asgi_post(app, headers, body)
    assert r.status_code == 200, r.text
    payload = json.loads(r.json()["result"]["content"][0]["text"])
    assert payload["pubkey"] == pk


@pytest.mark.asyncio
async def test_trust_proxy_false_ignores_forwarded_even_if_signed_for_it():
    sk = generate_private_key_hex()
    npub = npub_encode(xonly_pubkey_hex(sk))
    cfg = load_config(
        raw={"auth": {"allow_npubs": [npub], "trust_proxy": False}}
    )
    app = create_app(cfg)
    reset_tool_invocations()
    body = _whoami_body()
    headers = {
        "Content-Type": "application/json",
        "Authorization": encode_authorization_header(
            build_auth_event(sk, url="https://edge.example/mcp", method="POST", body=body)
        ),
        "Host": "test",
        "X-Forwarded-Host": "edge.example",
        "X-Forwarded-Proto": "https",
    }
    r = await _asgi_post(app, headers, body)
    assert r.status_code == 401
    assert r.json()["reason"] == "url_mismatch"
    assert TOOL_INVOCATIONS == []


# ---------------------------------------------------------------------------
# 3) Stolen nsec
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stolen_allowlisted_nsec_grants_access():
    """If the attacker holds an allowlisted nsec, crypto auth cannot stop them.

    This is identity theft, not a gate bug. Test locks the security model:
    possession of the key == possession of the identity.
    """
    victim_sk = generate_private_key_hex()
    victim_pk = xonly_pubkey_hex(victim_sk)
    victim_npub = npub_encode(victim_pk)
    cfg = load_config(raw={"auth": {"allow_npubs": [victim_npub]}})
    app = create_app(cfg)
    reset_tool_invocations()

    # Attacker uses stolen key material (same bytes as victim)
    stolen_sk = victim_sk
    body = _whoami_body()
    headers = {
        "Content-Type": "application/json",
        "Authorization": encode_authorization_header(
            build_auth_event(stolen_sk, url="http://test/mcp", method="POST", body=body)
        ),
        "Host": "test",
    }
    r = await _asgi_post(app, headers, body)
    assert r.status_code == 200
    payload = json.loads(r.json()["result"]["content"][0]["text"])
    assert payload["pubkey"] == victim_pk
    assert any(i["tool"] == "whoami" for i in TOOL_INVOCATIONS)


@pytest.mark.asyncio
async def test_stolen_non_allowlisted_nsec_still_denied():
    """Stolen key for an identity not on the allowlist does not open tools."""
    random_sk = generate_private_key_hex()
    allowed_sk = generate_private_key_hex()
    allowed_npub = npub_encode(xonly_pubkey_hex(allowed_sk))
    cfg = load_config(raw={"auth": {"allow_npubs": [allowed_npub]}})
    app = create_app(cfg)
    reset_tool_invocations()
    body = _whoami_body()
    headers = {
        "Content-Type": "application/json",
        "Authorization": encode_authorization_header(
            build_auth_event(random_sk, url="http://test/mcp", method="POST", body=body)
        ),
        "Host": "test",
    }
    r = await _asgi_post(app, headers, body)
    assert r.status_code == 401
    assert r.json()["reason"] == "not_allowlisted"
    assert TOOL_INVOCATIONS == []


# ---------------------------------------------------------------------------
# 4) Clients without NIP-98 signing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_without_nip98_cannot_call_tools(identity):
    """MCP-style JSON-RPC without Authorization is rejected (Claude-like bare HTTP)."""
    sk, pk, npub = identity
    cfg = load_config(raw={"auth": {"allow_npubs": [npub]}})
    app = create_app(cfg)
    reset_tool_invocations()
    body = _whoami_body()
    # no Authorization header at all
    r = await _asgi_post(app, {"Content-Type": "application/json", "Host": "test"}, body)
    assert r.status_code == 401
    assert r.json()["reason"] == "missing_authorization"
    assert TOOL_INVOCATIONS == []


@pytest.mark.asyncio
async def test_client_with_bearer_api_key_style_rejected(identity):
    """Common corporate mistake: send Bearer API key instead of Nostr header."""
    sk, pk, npub = identity
    cfg = load_config(raw={"auth": {"allow_npubs": [npub]}})
    app = create_app(cfg)
    reset_tool_invocations()
    body = _whoami_body()
    r = await _asgi_post(
        app,
        {
            "Content-Type": "application/json",
            "Host": "test",
            "Authorization": "Bearer sk-corp-api-key-not-nostr",
        },
        body,
    )
    assert r.status_code == 401
    assert r.json()["reason"] == "invalid_scheme"
    assert TOOL_INVOCATIONS == []


@pytest.mark.asyncio
async def test_unsigned_tools_list_denied(identity):
    sk, pk, npub = identity
    cfg = load_config(raw={"auth": {"allow_npubs": [npub]}})
    app = create_app(cfg)
    reset_tool_invocations()
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        separators=(",", ":"),
    ).encode()
    r = await _asgi_post(app, {"Content-Type": "application/json", "Host": "test"}, body)
    assert r.status_code == 401
    assert TOOL_INVOCATIONS == []
