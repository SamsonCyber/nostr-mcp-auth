"""External HTTP auth surface: constrained codes + no-cache headers."""
from __future__ import annotations

from typing import Any

from starlette.responses import JSONResponse

# External codes only (no fine-grained crypto oracle for remote callers)
EXTERNAL_UNAUTHORIZED = "unauthorized"
EXTERNAL_FORBIDDEN = "forbidden"

# Authenticated MCP traffic must not be stored by shared caches
NO_STORE_HEADERS: dict[str, str] = {
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "Pragma": "no-cache",
    "Expires": "0",
}


def external_auth_body() -> dict[str, str]:
    return {"error": EXTERNAL_UNAUTHORIZED, "code": EXTERNAL_UNAUTHORIZED}


def external_forbidden_body() -> dict[str, str]:
    return {"error": EXTERNAL_FORBIDDEN, "code": EXTERNAL_FORBIDDEN}


def json_no_store(
    content: Any,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    merged = dict(NO_STORE_HEADERS)
    if headers:
        merged.update(headers)
    return JSONResponse(content, status_code=status_code, headers=merged)


def unauthorized_response() -> JSONResponse:
    return json_no_store(external_auth_body(), status_code=401)


def forbidden_rpc_response(req_id: Any) -> JSONResponse:
    return json_no_store(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32003, "message": EXTERNAL_FORBIDDEN},
        },
        status_code=403,
    )
