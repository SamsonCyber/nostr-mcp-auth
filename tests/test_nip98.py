"""Pure NIP-98 verifier tests: allow + full fail-closed matrix."""
from __future__ import annotations

import time

import pytest

from nostr_mcp_auth.crypto import generate_private_key_hex, xonly_pubkey_hex
from nostr_mcp_auth.nip98 import (
    AuthError,
    build_auth_event,
    encode_authorization_header,
    verify_authorization_header,
    verify_nip98_event,
)


@pytest.fixture
def keys():
    sk = generate_private_key_hex()
    return sk, xonly_pubkey_hex(sk)


def test_valid_auth_allows(keys):
    sk, pk = keys
    url = "http://127.0.0.1:8787/mcp"
    body = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
    event = build_auth_event(sk, url=url, method="POST", body=body)
    ctx = verify_nip98_event(event, url=url, method="POST", body=body)
    assert ctx.pubkey == pk
    assert ctx.event_id == event["id"]


def test_missing_auth_header():
    with pytest.raises(AuthError) as ei:
        verify_authorization_header(None, url="http://x/mcp", method="POST", body=b"{}")
    assert ei.value.reason == "missing_authorization"


def test_bad_signature(keys):
    sk, _ = keys
    url = "http://127.0.0.1:8787/mcp"
    body = b"{}"
    event = build_auth_event(sk, url=url, method="POST", body=body)
    # flip one nibble of sig
    sig = event["sig"]
    event["sig"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    with pytest.raises(AuthError) as ei:
        verify_nip98_event(event, url=url, method="POST", body=body)
    assert ei.value.reason == "bad_signature"


def test_wrong_kind(keys):
    sk, _ = keys
    url = "http://x/mcp"
    body = b"{}"
    event = build_auth_event(sk, url=url, method="POST", body=body)
    # re-sign would need rebuild; corrupt kind breaks id bind -> bad_signature or wrong_kind
    event["kind"] = 1
    with pytest.raises(AuthError) as ei:
        verify_nip98_event(event, url=url, method="POST", body=body)
    assert ei.value.reason in ("wrong_kind", "bad_signature")


def test_expired(keys):
    sk, _ = keys
    url = "http://x/mcp"
    body = b"{}"
    now = int(time.time())
    event = build_auth_event(sk, url=url, method="POST", body=body, created_at=now - 3600)
    with pytest.raises(AuthError) as ei:
        verify_nip98_event(event, url=url, method="POST", body=body, now=now, max_skew_seconds=60)
    assert ei.value.reason == "expired"


def test_url_mismatch(keys):
    sk, _ = keys
    body = b"{}"
    event = build_auth_event(sk, url="http://x/mcp", method="POST", body=body)
    with pytest.raises(AuthError) as ei:
        verify_nip98_event(event, url="http://evil/mcp", method="POST", body=body)
    assert ei.value.reason == "url_mismatch"


def test_method_mismatch(keys):
    sk, _ = keys
    body = b"{}"
    event = build_auth_event(sk, url="http://x/mcp", method="POST", body=body)
    with pytest.raises(AuthError) as ei:
        verify_nip98_event(event, url="http://x/mcp", method="GET", body=body)
    assert ei.value.reason == "method_mismatch"


def test_payload_mismatch(keys):
    sk, _ = keys
    url = "http://x/mcp"
    body = b'{"a":1}'
    event = build_auth_event(sk, url=url, method="POST", body=body)
    with pytest.raises(AuthError) as ei:
        verify_nip98_event(event, url=url, method="POST", body=b'{"a":2}')
    assert ei.value.reason == "payload_mismatch"


def test_missing_payload_when_body(keys):
    sk, _ = keys
    url = "http://x/mcp"
    # craft event without payload tag but with body required
    event = build_auth_event(sk, url=url, method="POST", body=None)
    # no payload tag
    assert not any(t[0] == "payload" for t in event["tags"])
    with pytest.raises(AuthError) as ei:
        verify_nip98_event(event, url=url, method="POST", body=b"nonempty")
    assert ei.value.reason == "missing_payload"


def test_header_roundtrip(keys):
    sk, pk = keys
    url = "http://127.0.0.1:9/mcp"
    body = b'{"jsonrpc":"2.0"}'
    event = build_auth_event(sk, url=url, method="POST", body=body)
    header = encode_authorization_header(event)
    ctx = verify_authorization_header(header, url=url, method="POST", body=body)
    assert ctx.pubkey == pk
