"""NIP-98 build + verify (pure, fail-closed)."""
from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass
from typing import Any

from .crypto import (
    sha256_hex,
    sign_event,
    verify_event_id_and_sig,
    xonly_pubkey_hex,
)

NIP98_KIND = 27235
_MAX_TOKEN_BYTES = 8192
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class AuthError(Exception):
    """Fail-closed auth failure with stable reason code."""

    def __init__(self, reason: str, message: str = ""):
        self.reason = reason
        super().__init__(message or reason)


@dataclass
class AuthContext:
    pubkey: str
    npub: str | None
    event_id: str
    created_at: int


def build_auth_event(
    private_key_hex: str,
    *,
    url: str,
    method: str,
    body: bytes | None = None,
    created_at: int | None = None,
) -> dict[str, Any]:
    """Build and sign a NIP-98 event for an HTTP request."""
    method_u = method.upper()
    tags: list[list[str]] = [
        ["u", url],
        ["method", method_u],
    ]
    if body is not None and len(body) > 0:
        tags.append(["payload", sha256_hex(body)])
    draft = {
        "created_at": int(created_at if created_at is not None else time.time()),
        "kind": NIP98_KIND,
        "tags": tags,
        "content": "",
    }
    return sign_event(private_key_hex, draft)


def encode_authorization_header(event: dict[str, Any]) -> str:
    raw = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    token = base64.b64encode(raw).decode("ascii")
    return f"Nostr {token}"


def _safe_int(value: Any, reason: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        # bool is subclass of int — reject True/False explicitly
        if isinstance(value, bool):
            raise AuthError(reason)
        raise AuthError(reason)
    try:
        if isinstance(value, str):
            if not value.strip().lstrip("-").isdigit():
                raise AuthError(reason)
            return int(value)
        return int(value)
    except (TypeError, ValueError) as exc:
        raise AuthError(reason) from exc


def _decode_authorization_header(header: str | None) -> dict[str, Any]:
    if not header or not header.strip():
        raise AuthError("missing_authorization")
    parts = header.strip().split(None, 1)
    if len(parts) != 2 or parts[0] != "Nostr":
        raise AuthError("invalid_scheme")
    token = parts[1].strip()
    # Reject whitespace inside the token (CRLF smuggling / parser ambiguity)
    if any(c.isspace() for c in token):
        raise AuthError("invalid_token_encoding")
    if len(token) > _MAX_TOKEN_BYTES * 2:
        raise AuthError("token_too_large")
    try:
        pad = "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(token + pad, validate=True)
        except Exception:
            raw = base64.urlsafe_b64decode(token + pad)
        if len(raw) > _MAX_TOKEN_BYTES:
            raise AuthError("token_too_large")
        data = json.loads(raw.decode("utf-8"))
    except AuthError:
        raise
    except Exception as exc:
        raise AuthError("invalid_token_encoding") from exc
    if not isinstance(data, dict):
        raise AuthError("invalid_event_json")
    return data


def _tag_values(tags: list, name: str) -> list[str]:
    out: list[str] = []
    for t in tags:
        if isinstance(t, list) and len(t) >= 2 and t[0] == name:
            out.append(str(t[1]))
    return out


def _unique_tag(tags: list, name: str) -> str | None:
    vals = _tag_values(tags, name)
    if not vals:
        return None
    if len(set(vals)) > 1:
        raise AuthError(f"ambiguous_{name}")
    return vals[0]


def verify_nip98_event(
    event: dict[str, Any],
    *,
    url: str,
    method: str,
    body: bytes | None = None,
    now: int | None = None,
    max_skew_seconds: int = 60,
    require_payload_when_body: bool = True,
) -> AuthContext:
    """Verify a NIP-98 event against request binding. Raises AuthError."""
    if not isinstance(event, dict):
        raise AuthError("invalid_event_json")

    kind = _safe_int(event.get("kind", -1), "wrong_kind")
    if kind != NIP98_KIND:
        raise AuthError("wrong_kind")

    # content must be empty per NIP-98
    content = event.get("content", "")
    if content is None:
        content = ""
    if not isinstance(content, str) or content != "":
        raise AuthError("invalid_content")

    if not verify_event_id_and_sig(event):
        raise AuthError("bad_signature")

    created_at = _safe_int(event.get("created_at"), "invalid_created_at")
    ts = int(now if now is not None else time.time())
    if abs(ts - created_at) > int(max_skew_seconds):
        raise AuthError("expired")

    tags = event.get("tags")
    if not isinstance(tags, list):
        raise AuthError("missing_binding_tags")

    try:
        u = _unique_tag(tags, "u")
        m = _unique_tag(tags, "method")
        payload = _unique_tag(tags, "payload")
    except AuthError:
        raise

    if u is None or m is None:
        raise AuthError("missing_binding_tags")

    if u != url:
        raise AuthError("url_mismatch")
    if m.upper() != method.upper():
        raise AuthError("method_mismatch")

    body = body or b""
    if len(body) > 0 and require_payload_when_body:
        if payload is None:
            raise AuthError("missing_payload")
        expected = sha256_hex(body)
        if payload.lower() != expected.lower():
            raise AuthError("payload_mismatch")
    elif len(body) == 0 and payload is not None:
        # Signed for a body but request has none — reject
        raise AuthError("payload_without_body")

    pubkey = str(event.get("pubkey") or "").lower()
    if not _HEX64.match(pubkey):
        raise AuthError("invalid_pubkey")

    event_id = str(event.get("id") or "")
    if not _HEX64.match(event_id):
        raise AuthError("bad_signature")

    npub = None
    try:
        from .crypto import npub_encode

        npub = npub_encode(pubkey)
    except Exception:
        pass

    return AuthContext(
        pubkey=pubkey,
        npub=npub,
        event_id=event_id,
        created_at=created_at,
    )


def verify_authorization_header(
    header: str | None,
    *,
    url: str,
    method: str,
    body: bytes | None = None,
    now: int | None = None,
    max_skew_seconds: int = 60,
) -> AuthContext:
    event = _decode_authorization_header(header)
    return verify_nip98_event(
        event,
        url=url,
        method=method,
        body=body,
        now=now,
        max_skew_seconds=max_skew_seconds,
    )


def identity_from_private_key(private_key_hex: str) -> tuple[str, str]:
    """Return (pubkey_hex, npub)."""
    from .crypto import npub_encode

    pub = xonly_pubkey_hex(private_key_hex)
    return pub, npub_encode(pub)
