"""Second red-team wave: residual hot-path options after hardening."""
from __future__ import annotations

import json
import threading
import time

import httpx
import pytest

from nostr_mcp_auth.config import load_config
from nostr_mcp_auth.crypto import (
    generate_private_key_hex,
    npub_encode,
    sha256_hex,
    sign_event,
    xonly_pubkey_hex,
)
from nostr_mcp_auth.gate import AuthGate
from nostr_mcp_auth.nip98 import (
    AuthError,
    _MAX_TOKEN_BYTES,
    build_auth_event,
    encode_authorization_header,
    verify_authorization_header,
    verify_nip98_event,
)
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
                "allow_npubs": [npub],
                "roles": {npub: ["tools:admin"]},
                "trust_proxy": False,
                "replay_ttl_seconds": 120,
            },
            "tools": {"admin_ping": {"roles": ["tools:admin"]}},
        }
    )
    reset_tool_invocations()
    return create_app(cfg), sk, pk, npub


async def _post(app, sk, rpc, *, url="http://test/mcp", extra_headers=None):
    body = json.dumps(rpc, separators=(",", ":")).encode()
    headers = {
        "Content-Type": "application/json",
        "Authorization": encode_authorization_header(
            build_auth_event(sk, url=url, method="POST", body=body)
        ),
        "Host": "test",
    }
    if extra_headers:
        headers.update(extra_headers)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/mcp", content=body, headers=headers)


def test_oversized_token_rejected(identity):
    sk, pk, npub = identity
    huge = "A" * (_MAX_TOKEN_BYTES * 3)
    with pytest.raises(AuthError) as ei:
        verify_authorization_header(
            f"Nostr {huge}", url="http://test/mcp", method="POST", body=b"{}"
        )
    assert ei.value.reason == "token_too_large"


def test_query_string_must_match_exactly(identity):
    sk, pk, npub = identity
    body = b'{"x":1}'
    ev = build_auth_event(sk, url="http://test/mcp?admin=1", method="POST", body=body)
    with pytest.raises(AuthError) as ei:
        verify_nip98_event(ev, url="http://test/mcp", method="POST", body=body)
    assert ei.value.reason == "url_mismatch"


def test_path_case_sensitive(identity):
    sk, pk, npub = identity
    body = b"{}"
    ev = build_auth_event(sk, url="http://test/MCP", method="POST", body=body)
    with pytest.raises(AuthError) as ei:
        verify_nip98_event(ev, url="http://test/mcp", method="POST", body=body)
    assert ei.value.reason == "url_mismatch"


def test_concurrent_same_event_at_most_one_ok(identity):
    sk, pk, npub = identity
    cfg = load_config(raw={"auth": {"allow_npubs": [npub], "replay_ttl_seconds": 120}})
    gate = AuthGate(cfg)
    body = b'{"race":true}'
    url = "http://test/mcp"
    header = encode_authorization_header(
        build_auth_event(sk, url=url, method="POST", body=body)
    )
    results: list[str] = []
    barrier = threading.Barrier(12)

    def worker():
        barrier.wait()
        try:
            gate.authenticate(authorization=header, url=url, method="POST", body=body)
            results.append("ok")
        except AuthError as e:
            results.append(e.reason)

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("ok") == 1
    assert results.count("replay") == 11


def test_padded_method_tag_rejected(identity):
    sk, pk, npub = identity
    url = "http://test/mcp"
    body = b"{}"
    tags = [["u", url], ["method", " POST "], ["payload", sha256_hex(body)]]
    ev = sign_event(
        sk, {"created_at": int(time.time()), "kind": 27235, "tags": tags, "content": ""}
    )
    with pytest.raises(AuthError) as ei:
        verify_nip98_event(ev, url=url, method="POST", body=body)
    assert ei.value.reason == "method_mismatch"


def test_null_byte_in_u_rejected(identity):
    sk, pk, npub = identity
    url = "http://test/mcp"
    tags = [["u", url + "\x00.evil"], ["method", "POST"]]
    ev = sign_event(
        sk, {"created_at": int(time.time()), "kind": 27235, "tags": tags, "content": ""}
    )
    with pytest.raises(AuthError) as ei:
        verify_nip98_event(ev, url=url, method="POST", body=b"")
    assert ei.value.reason == "url_mismatch"


def test_empty_token_after_scheme(identity):
    with pytest.raises(AuthError):
        verify_authorization_header("Nostr    ", url="http://t/mcp", method="POST", body=b"{}")


@pytest.mark.asyncio
async def test_trust_proxy_false_ignores_forwarded_host(app):
    application, sk, pk, npub = app
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "whoami", "arguments": {}},
        },
        separators=(",", ":"),
    ).encode()
    # signed for evil; X-Forwarded-Host should not change reconstruct when trust_proxy false
    headers = {
        "Content-Type": "application/json",
        "Authorization": encode_authorization_header(
            build_auth_event(sk, url="http://evil/mcp", method="POST", body=body)
        ),
        "Host": "test",
        "X-Forwarded-Host": "evil",
        "X-Forwarded-Proto": "https",
    }
    reset_tool_invocations()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/mcp", content=body, headers=headers)
    assert r.status_code == 401
    assert r.json()["code"] == "unauthorized"
    assert TOOL_INVOCATIONS == []


@pytest.mark.asyncio
async def test_role_path_confusion_no_tool_run(identity):
    sk, pk, npub = identity
    cfg = load_config(
        raw={
            "auth": {"allow_npubs": [npub], "roles": {}},
            "tools": {"admin_ping": {"roles": ["tools:admin"]}},
        }
    )
    application = create_app(cfg)
    reset_tool_invocations()
    r = await _post(
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


@pytest.mark.asyncio
async def test_wave2_allow_path_still_works(app):
    application, sk, pk, npub = app
    reset_tool_invocations()
    r = await _post(
        application,
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
    assert any(i["tool"] == "whoami" and i["pubkey"] == pk for i in TOOL_INVOCATIONS)
