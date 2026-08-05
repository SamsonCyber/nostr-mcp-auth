"""Harden: snoop scrub, constrained external oracle, cache headers, classical gaps."""
from __future__ import annotations

import json
import logging

import httpx
import pytest

from nostr_mcp_auth.config import load_config
from nostr_mcp_auth.crypto import (
    generate_private_key_hex,
    nsec_encode,
    npub_encode,
    xonly_pubkey_hex,
)
from nostr_mcp_auth.gate import AuthGate
from nostr_mcp_auth.http_safe import NO_STORE_HEADERS, EXTERNAL_UNAUTHORIZED
from nostr_mcp_auth.nip98 import (
    AuthError,
    build_auth_event,
    encode_authorization_header,
)
from nostr_mcp_auth.server import TOOL_INVOCATIONS, create_app, reset_tool_invocations
from nostr_mcp_auth.snoop import looks_like_secret_material, scrub_secrets


def _whoami_rpc() -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "whoami", "arguments": {}},
    }


def _body() -> bytes:
    return json.dumps(_whoami_rpc(), separators=(",", ":")).encode()


@pytest.fixture
def identity():
    sk = generate_private_key_hex()
    pk = xonly_pubkey_hex(sk)
    return sk, pk, npub_encode(pk), nsec_encode(sk)


@pytest.fixture
def app(identity):
    sk, pk, npub, nsec = identity
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
    return create_app(cfg), sk, pk, npub, nsec


class _LogCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.records.append(self.format(record))
        except Exception:
            self.records.append(record.getMessage())

    def joined(self) -> str:
        return "\n".join(self.records)


def _attach_auth_loggers(handler: logging.Handler) -> list[logging.Logger]:
    names = (
        "nostr_mcp_auth.gate",
        "nostr_mcp_auth.server",
        "nostr_mcp_auth",
    )
    loggers: list[logging.Logger] = []
    for name in names:
        lg = logging.getLogger(name)
        lg.setLevel(logging.DEBUG)
        lg.addHandler(handler)
        loggers.append(lg)
    return loggers


def _detach(loggers: list[logging.Handler], handler: logging.Handler) -> None:
    for lg in loggers:
        lg.removeHandler(handler)


# ---------------------------------------------------------------------------
# Snoop scrub unit + gate log capture
# ---------------------------------------------------------------------------


def test_scrub_secrets_redacts_nsec_and_nostr_token(identity):
    sk, pk, npub, nsec = identity
    header = encode_authorization_header(
        build_auth_event(sk, url="http://t/mcp", method="POST", body=b"{}")
    )
    messy = f"got {nsec} and Authorization: {header} sk={sk}"
    cleaned = scrub_secrets(messy)
    assert nsec not in cleaned
    assert sk not in cleaned
    assert "Nostr " in cleaned or "[REDACTED]" in cleaned
    token = header.split(None, 1)[1]
    assert token not in cleaned
    assert looks_like_secret_material(messy, private_key_hex=sk, authorization=header, nsec=nsec)
    assert not looks_like_secret_material(
        cleaned, private_key_hex=sk, authorization=header, nsec=nsec
    )


@pytest.mark.asyncio
async def test_deny_path_logs_and_body_have_no_secrets(app):
    application, sk, pk, npub, nsec = app
    body = _body()
    auth = encode_authorization_header(
        build_auth_event(sk, url="http://evil/mcp", method="POST", body=body)
    )
    cap = _LogCapture()
    cap.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s"))
    loggers = _attach_auth_loggers(cap)
    reset_tool_invocations()
    try:
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.post(
                "/mcp",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": auth,
                    "Host": "test",
                },
            )
    finally:
        _detach(loggers, cap)

    assert r.status_code == 401
    text_body = r.text
    log_text = cap.joined()
    assert not looks_like_secret_material(
        text_body, private_key_hex=sk, authorization=auth, nsec=nsec
    )
    assert not looks_like_secret_material(
        log_text, private_key_hex=sk, authorization=auth, nsec=nsec
    )
    token = auth.split(None, 1)[1]
    assert token not in text_body
    assert token not in log_text
    assert sk not in text_body
    assert sk not in log_text
    assert nsec not in text_body
    assert nsec not in log_text
    assert TOOL_INVOCATIONS == []


@pytest.mark.asyncio
async def test_allow_path_logs_and_body_have_no_secrets(app):
    application, sk, pk, npub, nsec = app
    body = _body()
    auth = encode_authorization_header(
        build_auth_event(sk, url="http://test/mcp", method="POST", body=body)
    )
    cap = _LogCapture()
    cap.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s"))
    loggers = _attach_auth_loggers(cap)
    reset_tool_invocations()
    try:
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.post(
                "/mcp",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": auth,
                    "Host": "test",
                },
            )
    finally:
        _detach(loggers, cap)

    assert r.status_code == 200, r.text
    text_body = r.text
    log_text = cap.joined()
    token = auth.split(None, 1)[1]
    assert token not in text_body
    assert token not in log_text
    assert sk not in text_body
    assert sk not in log_text
    assert nsec not in text_body
    assert nsec not in log_text
    assert "Nostr " not in log_text
    assert not looks_like_secret_material(
        log_text, private_key_hex=sk, authorization=auth, nsec=nsec
    )


# ---------------------------------------------------------------------------
# Constrained external oracle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auth_failures_share_same_external_body(app, identity):
    """Different internal failures must not teach attackers distinct reasons on the wire."""
    application, sk, pk, npub, nsec = app
    other_sk = generate_private_key_hex()
    body = _body()
    cases = []

    # missing auth
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r_miss = await client.post(
            "/mcp",
            content=body,
            headers={"Content-Type": "application/json", "Host": "test"},
        )
        cases.append(r_miss)

        # bad scheme
        r_bearer = await client.post(
            "/mcp",
            content=body,
            headers={
                "Content-Type": "application/json",
                "Host": "test",
                "Authorization": "Bearer nope",
            },
        )
        cases.append(r_bearer)

        # wrong host binding
        r_url = await client.post(
            "/mcp",
            content=body,
            headers={
                "Content-Type": "application/json",
                "Host": "test",
                "Authorization": encode_authorization_header(
                    build_auth_event(sk, url="http://evil/mcp", method="POST", body=body)
                ),
            },
        )
        cases.append(r_url)

        # not allowlisted
        r_na = await client.post(
            "/mcp",
            content=body,
            headers={
                "Content-Type": "application/json",
                "Host": "test",
                "Authorization": encode_authorization_header(
                    build_auth_event(other_sk, url="http://test/mcp", method="POST", body=body)
                ),
            },
        )
        cases.append(r_na)

        # body swap
        body_b = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "protected_echo", "arguments": {"text": "x"}},
            },
            separators=(",", ":"),
        ).encode()
        r_swap = await client.post(
            "/mcp",
            content=body_b,
            headers={
                "Content-Type": "application/json",
                "Host": "test",
                "Authorization": encode_authorization_header(
                    build_auth_event(sk, url="http://test/mcp", method="POST", body=body)
                ),
            },
        )
        cases.append(r_swap)

    shapes = []
    for r in cases:
        assert r.status_code == 401
        data = r.json()
        assert data.get("code") == EXTERNAL_UNAUTHORIZED
        assert data.get("error") == EXTERNAL_UNAUTHORIZED
        assert "reason" not in data
        shapes.append(json.dumps(data, sort_keys=True))
    assert len(set(shapes)) == 1
    assert TOOL_INVOCATIONS == []


@pytest.mark.asyncio
async def test_role_denied_is_forbidden_not_tool_output(app):
    application, sk, pk, npub, nsec = app
    # drop admin role
    cfg = load_config(
        raw={
            "auth": {"allow_npubs": [npub], "roles": {}},
            "tools": {"admin_ping": {"roles": ["tools:admin"]}},
        }
    )
    application = create_app(cfg)
    reset_tool_invocations()
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "admin_ping", "arguments": {}},
        },
        separators=(",", ":"),
    ).encode()
    auth = encode_authorization_header(
        build_auth_event(sk, url="http://test/mcp", method="POST", body=body)
    )
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/mcp",
            content=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": auth,
                "Host": "test",
            },
        )
    assert r.status_code == 403
    data = r.json()
    assert data["error"]["message"] == "forbidden"
    assert "insufficient_role" not in r.text
    assert TOOL_INVOCATIONS == []


# ---------------------------------------------------------------------------
# Cache-disabling headers
# ---------------------------------------------------------------------------


def _assert_no_store(headers: httpx.Headers) -> None:
    cc = headers.get("cache-control", "").lower()
    assert "no-store" in cc
    assert "private" in cc or "no-cache" in cc
    assert headers.get("pragma", "").lower() == "no-cache"
    assert headers.get("expires") == "0"


@pytest.mark.asyncio
async def test_mcp_success_and_failure_are_non_cacheable(app):
    application, sk, pk, npub, nsec = app
    body = _body()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r_fail = await client.post(
            "/mcp",
            content=body,
            headers={"Content-Type": "application/json", "Host": "test"},
        )
        auth = encode_authorization_header(
            build_auth_event(sk, url="http://test/mcp", method="POST", body=body)
        )
        r_ok = await client.post(
            "/mcp",
            content=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": auth,
                "Host": "test",
            },
        )
    assert r_fail.status_code == 401
    assert r_ok.status_code == 200
    _assert_no_store(r_fail.headers)
    _assert_no_store(r_ok.headers)
    # shipped constant present
    for k, v in NO_STORE_HEADERS.items():
        assert r_ok.headers.get(k.lower()) == v or r_ok.headers.get(k) == v


# ---------------------------------------------------------------------------
# Classical gaps: method-override ignored; host confusion; deny list HTTP
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_method_override_header_ignored(app):
    """X-HTTP-Method-Override must not change NIP-98 method binding (POST stays POST)."""
    application, sk, pk, npub, nsec = app
    body = _body()
    # Sign as POST (real method). If server honored override as GET, binding would break.
    auth = encode_authorization_header(
        build_auth_event(sk, url="http://test/mcp", method="POST", body=body)
    )
    reset_tool_invocations()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/mcp",
            content=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": auth,
                "Host": "test",
                "X-HTTP-Method-Override": "GET",
                "X-Method-Override": "DELETE",
            },
        )
    assert r.status_code == 200, r.text
    assert any(i["tool"] == "whoami" for i in TOOL_INVOCATIONS)


@pytest.mark.asyncio
async def test_method_override_cannot_bypass_with_get_signed_post(app):
    """Sign GET then POST: still method_mismatch internally → 401, no tools."""
    application, sk, pk, npub, nsec = app
    body = _body()
    auth = encode_authorization_header(
        build_auth_event(sk, url="http://test/mcp", method="GET", body=body)
    )
    reset_tool_invocations()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/mcp",
            content=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": auth,
                "Host": "test",
                "X-HTTP-Method-Override": "GET",
            },
        )
    assert r.status_code == 401
    assert r.json()["code"] == "unauthorized"
    assert TOOL_INVOCATIONS == []


@pytest.mark.asyncio
async def test_deny_listed_identity_no_tool(identity):
    sk, pk, npub, nsec = identity
    cfg = load_config(raw={"auth": {"allow_npubs": [npub], "deny_npubs": [npub]}})
    application = create_app(cfg)
    reset_tool_invocations()
    body = _body()
    auth = encode_authorization_header(
        build_auth_event(sk, url="http://test/mcp", method="POST", body=body)
    )
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/mcp",
            content=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": auth,
                "Host": "test",
            },
        )
    assert r.status_code == 401
    assert r.json()["code"] == "unauthorized"
    assert TOOL_INVOCATIONS == []


def test_gate_still_exposes_internal_reason_for_operators(identity):
    """Internal AuthError.reason remains for logs/tests; not on HTTP body."""
    sk, pk, npub, nsec = identity
    cfg = load_config(raw={"auth": {"allow_npubs": [npub]}})
    gate = AuthGate(cfg)
    body = b"{}"
    url = "http://t/mcp"
    h = encode_authorization_header(build_auth_event(sk, url=url, method="POST", body=body))
    gate.authenticate(authorization=h, url=url, method="POST", body=body)
    with pytest.raises(AuthError) as ei:
        gate.authenticate(authorization=h, url=url, method="POST", body=body)
    assert ei.value.reason == "replay"
