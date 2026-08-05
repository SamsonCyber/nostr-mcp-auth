"""Request gate: NIP-98 + policy + replay."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from .config import AuthConfig
from .nip98 import AuthContext, AuthError, verify_authorization_header
from .replay import ReplayCache
from .snoop import safe_path_for_log, scrub_secrets

logger = logging.getLogger("nostr_mcp_auth.gate")


@dataclass
class GateResult:
    ok: bool
    reason: str
    ctx: AuthContext | None = None


class AuthGate:
    def __init__(self, config: AuthConfig, replay: ReplayCache | None = None):
        self.config = config
        self.replay = replay or ReplayCache(ttl_seconds=config.replay_ttl_seconds)

    def authenticate(
        self,
        *,
        authorization: str | None,
        url: str,
        method: str,
        body: bytes | None = None,
        now: int | None = None,
    ) -> AuthContext:
        # Never log Authorization or body; path only (scrubbed)
        path_log = safe_path_for_log(url)
        try:
            ctx = verify_authorization_header(
                authorization,
                url=url,
                method=method,
                body=body,
                now=now,
                max_skew_seconds=self.config.max_skew_seconds,
            )
        except AuthError as exc:
            logger.info(
                "auth deny reason=%s method=%s path=%s",
                scrub_secrets(exc.reason),
                scrub_secrets(method),
                path_log,
            )
            raise

        if self.config.replay_ttl_seconds > 0:
            if self.replay.seen_or_add(ctx.event_id):
                logger.info(
                    "auth deny reason=replay event_id_prefix=%s path=%s",
                    ctx.event_id[:16],
                    path_log,
                )
                raise AuthError("replay")

        ok, reason = self.config.is_authorized(ctx.pubkey)
        if not ok:
            logger.info(
                "auth deny reason=%s pubkey_prefix=%s path=%s",
                scrub_secrets(reason),
                ctx.pubkey[:16],
                path_log,
            )
            raise AuthError(reason)

        logger.info(
            "auth ok pubkey_prefix=%s event_id_prefix=%s method=%s path=%s",
            ctx.pubkey[:16],
            ctx.event_id[:16],
            scrub_secrets(method),
            path_log,
        )
        return ctx

    def authorize_tool(self, ctx: AuthContext, tool_name: str) -> None:
        ok, reason = self.config.tool_allowed(ctx.pubkey, tool_name)
        if not ok:
            logger.info(
                "auth deny reason=%s tool=%s pubkey_prefix=%s",
                scrub_secrets(reason),
                scrub_secrets(tool_name),
                ctx.pubkey[:16],
            )
            raise AuthError(reason)
