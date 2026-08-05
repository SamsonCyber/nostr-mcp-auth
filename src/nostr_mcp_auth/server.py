"""HTTP MCP-style JSON-RPC surface protected by NIP-98."""
from __future__ import annotations

import json
import logging
from typing import Any, Callable
from urllib.parse import urlencode

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .config import AuthConfig
from .gate import AuthGate
from .nip98 import AuthError

logger = logging.getLogger("nostr_mcp_auth.server")

# Side-effect flags for tests (module-level, reset in tests)
TOOL_INVOCATIONS: list[dict[str, Any]] = []


def reset_tool_invocations() -> None:
    TOOL_INVOCATIONS.clear()


def reconstruct_url(request: Request, *, trust_proxy: bool) -> str:
    if trust_proxy:
        proto = request.headers.get("x-forwarded-proto") or request.url.scheme
        host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    else:
        proto = request.url.scheme
        host = request.headers.get("host") or request.url.netloc
    path = request.url.path or "/"
    query = request.url.query
    base = f"{proto}://{host}{path}"
    if query:
        return f"{base}?{query}"
    return base


def create_app(config: AuthConfig, *, gate: AuthGate | None = None) -> Starlette:
    auth_gate = gate or AuthGate(config)

    async def health(_request: Request) -> JSONResponse:
        return JSONResponse({"ok": True, "service": "nostr-mcp-auth"})

    async def ready(_request: Request) -> JSONResponse:
        return JSONResponse({"ready": True})

    async def mcp_endpoint(request: Request) -> Response:
        body = await request.body()
        url = reconstruct_url(request, trust_proxy=config.trust_proxy)
        method = request.method.upper()

        # Auth gate: nothing below runs without success
        try:
            ctx = auth_gate.authenticate(
                authorization=request.headers.get("authorization"),
                url=url,
                method=method,
                body=body,
            )
        except AuthError as exc:
            return JSONResponse(
                {"error": "unauthorized", "reason": exc.reason},
                status_code=401,
            )

        if not body:
            return JSONResponse({"error": "empty_body"}, status_code=400)

        try:
            rpc = json.loads(body.decode("utf-8"))
        except Exception:
            return JSONResponse({"error": "invalid_json"}, status_code=400)

        # Batch not required for v1
        if not isinstance(rpc, dict):
            return JSONResponse({"error": "invalid_rpc"}, status_code=400)

        req_id = rpc.get("id")
        rpc_method = rpc.get("method")

        if rpc_method == "tools/list":
            tools = [
                {
                    "name": "whoami",
                    "description": "Return authenticated Nostr identity",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "protected_echo",
                    "description": "Echo text (auth required; records side effect)",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"text": {"type": "string"}},
                        "required": ["text"],
                    },
                },
                {
                    "name": "admin_ping",
                    "description": "Admin-only ping (requires tools:admin role)",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ]
            return JSONResponse(
                {"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools}}
            )

        if rpc_method == "tools/call":
            params = rpc.get("params") or {}
            tool_name = params.get("name") or ""
            arguments = params.get("arguments") or {}
            try:
                auth_gate.authorize_tool(ctx, tool_name)
            except AuthError as exc:
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32003, "message": exc.reason},
                    },
                    status_code=403,
                )

            result = _dispatch_tool(tool_name, arguments, ctx.pubkey, ctx.npub)
            if result.get("_not_found"):
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32601, "message": "tool not found"},
                    },
                    status_code=404,
                )
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": json.dumps(result, separators=(",", ":"))}
                        ],
                        "isError": False,
                    },
                }
            )

        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"method not found: {rpc_method}"},
            },
            status_code=404,
        )

    async def mcp_get(request: Request) -> Response:
        # Auth still required; no tool dispatch on GET (no body RPC).
        body = await request.body()
        url = reconstruct_url(request, trust_proxy=config.trust_proxy)
        try:
            auth_gate.authenticate(
                authorization=request.headers.get("authorization"),
                url=url,
                method="GET",
                body=body,
            )
        except AuthError as exc:
            return JSONResponse(
                {"error": "unauthorized", "reason": exc.reason},
                status_code=401,
            )
        return JSONResponse(
            {"error": "method_not_allowed", "detail": "use POST /mcp for JSON-RPC"},
            status_code=405,
        )

    routes = [
        Route("/health", health, methods=["GET"]),
        Route("/ready", ready, methods=["GET"]),
        Route("/mcp", mcp_endpoint, methods=["POST"]),
        Route("/mcp", mcp_get, methods=["GET"]),
    ]
    return Starlette(routes=routes)


def _dispatch_tool(
    name: str,
    arguments: dict[str, Any],
    pubkey: str,
    npub: str | None,
) -> dict[str, Any]:
    # Record side effect only after auth+role passed
    TOOL_INVOCATIONS.append({"tool": name, "arguments": dict(arguments), "pubkey": pubkey})

    if name == "whoami":
        return {"pubkey": pubkey, "npub": npub, "ok": True}
    if name == "protected_echo":
        return {"echo": arguments.get("text", ""), "pubkey": pubkey, "ok": True}
    if name == "admin_ping":
        return {"pong": True, "role": "tools:admin", "pubkey": pubkey, "ok": True}
    return {"_not_found": True}
