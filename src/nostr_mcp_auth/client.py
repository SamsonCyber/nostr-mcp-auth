"""Signed HTTP client helper for NIP-98 MCP calls."""
from __future__ import annotations

import json
from typing import Any

import httpx

from .crypto import load_private_key, npub_encode, xonly_pubkey_hex
from .nip98 import build_auth_event, encode_authorization_header


def sign_headers(
    private_key_hex: str,
    *,
    url: str,
    method: str,
    body: bytes | None = None,
) -> dict[str, str]:
    event = build_auth_event(private_key_hex, url=url, method=method, body=body)
    return {
        "Authorization": encode_authorization_header(event),
        "Content-Type": "application/json",
    }


def call_tool(
    base_url: str,
    private_key_hex: str,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    *,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """POST tools/call with NIP-98 auth. base_url should include path e.g. http://host:port/mcp."""
    key = load_private_key(private_key_hex)
    url = base_url.rstrip("/")
    if not url.endswith("/mcp"):
        # allow bare origin
        if url.endswith("/"):
            url = url + "mcp"
        else:
            url = url + "/mcp"

    rpc = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments or {}},
    }
    body = json.dumps(rpc, separators=(",", ":")).encode("utf-8")
    headers = sign_headers(key, url=url, method="POST", body=body)
    with httpx.Client(timeout=timeout) as client:
        r = client.post(url, content=body, headers=headers)
    return {
        "status_code": r.status_code,
        "body": r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text,
        "pubkey": xonly_pubkey_hex(key),
        "npub": npub_encode(xonly_pubkey_hex(key)),
    }


def list_tools(base_url: str, private_key_hex: str, *, timeout: float = 15.0) -> dict[str, Any]:
    key = load_private_key(private_key_hex)
    url = base_url.rstrip("/")
    if not url.endswith("/mcp"):
        url = url.rstrip("/") + "/mcp"
    rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    body = json.dumps(rpc, separators=(",", ":")).encode("utf-8")
    headers = sign_headers(key, url=url, method="POST", body=body)
    with httpx.Client(timeout=timeout) as client:
        r = client.post(url, content=body, headers=headers)
    return {"status_code": r.status_code, "body": r.json() if r.content else {}}
