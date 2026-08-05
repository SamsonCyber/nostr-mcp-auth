"""HTTP MCP-style JSON-RPC surface protected by NIP-98."""
from __future__ import annotations

import json
import logging
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .config import AuthConfig
from .gate import AuthGate
from .http_safe import (
    forbidden_rpc_response,
    json_no_store,
    unauthorized_response,
)
from .nip98 import AuthError
from .snoop import scrub_secrets

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
        # Real HTTP method only; never honor X-HTTP-Method-Override / method spoof headers
        method = request.method.upper()

        try:
            ctx = auth_gate.authenticate(
                authorization=request.headers.get("authorization"),
                url=url,
                method=method,
                body=body,
            )
        except AuthError as exc:
            # Internal reason for operators only; external body is constrained
            logger.info(
                "mcp auth failed internal_reason=%s",
                scrub_secrets(exc.reason),
            )
            return unauthorized_response()

        if not body:
            return json_no_store({"error": "empty_body"}, status_code=400)

        try:
            rpc = json.loads(body.decode("utf-8"))
        except Exception:
            return json_no_store({"error": "invalid_json"}, status_code=400)

        if not isinstance(rpc, dict):
            return json_no_store({"error": "invalid_rpc"}, status_code=400)

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
            return json_no_store(
                {"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools}}
            )

        if rpc_method == "tools/call":
            params = rpc.get("params") or {}
            tool_name = params.get("name") or ""
            arguments = params.get("arguments") or {}
            try:
                auth_gate.authorize_tool(ctx, tool_name)
            except AuthError as exc:
                logger.info(
                    "mcp tool denied internal_reason=%s tool=%s",
                    scrub_secrets(exc.reason),
                    scrub_secrets(str(tool_name)),
                )
                return forbidden_rpc_response(req_id)

            result = _dispatch_tool(tool_name, arguments, ctx.pubkey, ctx.npub)
            if result.get("_not_found"):
                return json_no_store(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32601, "message": "tool not found"},
                    },
                    status_code=404,
                )
            return json_no_store(
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

        return json_no_store(
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
            logger.info(
                "mcp GET auth failed internal_reason=%s",
                scrub_secrets(exc.reason),
            )
            return unauthorized_response()
        return json_no_store(
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
