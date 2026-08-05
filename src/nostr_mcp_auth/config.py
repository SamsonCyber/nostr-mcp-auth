"""Auth and server configuration."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .crypto import CryptoError, normalize_pubkey


@dataclass
class AuthConfig:
    open: bool = False
    max_skew_seconds: int = 60
    replay_ttl_seconds: int = 120
    trust_proxy: bool = False
    allow_pubkeys: set[str] = field(default_factory=set)  # hex
    deny_pubkeys: set[str] = field(default_factory=set)
    roles: dict[str, set[str]] = field(default_factory=dict)  # pubkey hex -> roles
    tool_roles: dict[str, set[str]] = field(default_factory=dict)  # tool -> required roles

    def is_authorized(self, pubkey: str) -> tuple[bool, str]:
        pk = pubkey.lower()
        if pk in self.deny_pubkeys:
            return False, "denied_npub"
        if self.open:
            return True, "open"
        if not self.allow_pubkeys:
            return False, "empty_allowlist"
        if pk not in self.allow_pubkeys:
            return False, "not_allowlisted"
        return True, "ok"

    def roles_for(self, pubkey: str) -> set[str]:
        return set(self.roles.get(pubkey.lower()) or set())

    def tool_allowed(self, pubkey: str, tool_name: str) -> tuple[bool, str]:
        ok, reason = self.is_authorized(pubkey)
        if not ok:
            return False, reason
        required = self.tool_roles.get(tool_name)
        if not required:
            return True, "ok"
        have = self.roles_for(pubkey)
        if required & have:
            return True, "ok"
        return False, "insufficient_role"


def _norm_list(values: list[Any] | None) -> set[str]:
    out: set[str] = set()
    for v in values or []:
        try:
            out.add(normalize_pubkey(str(v)))
        except CryptoError:
            # skip invalid entries but keep parsing
            continue
    return out


def load_config(path: str | Path | None = None, raw: dict | None = None) -> AuthConfig:
    if raw is None:
        if path is None:
            raise ValueError("path or raw required")
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    else:
        data = raw

    auth = data.get("auth") or {}
    tools = data.get("tools") or {}

    allow = _norm_list(list(auth.get("allow_npubs") or auth.get("allow_pubkeys") or []))
    deny = _norm_list(list(auth.get("deny_npubs") or auth.get("deny_pubkeys") or []))

    roles: dict[str, set[str]] = {}
    for k, v in (auth.get("roles") or {}).items():
        try:
            pk = normalize_pubkey(str(k))
        except CryptoError:
            continue
        if isinstance(v, list):
            roles[pk] = {str(x) for x in v}
        elif isinstance(v, str):
            roles[pk] = {v}

    tool_roles: dict[str, set[str]] = {}
    for tool_name, meta in tools.items():
        if isinstance(meta, dict) and meta.get("roles"):
            tool_roles[str(tool_name)] = {str(x) for x in meta["roles"]}

    return AuthConfig(
        open=bool(auth.get("open", False)),
        max_skew_seconds=int(auth.get("max_skew_seconds", 60)),
        replay_ttl_seconds=int(auth.get("replay_ttl_seconds", 120)),
        trust_proxy=bool(auth.get("trust_proxy", False)),
        allow_pubkeys=allow,
        deny_pubkeys=deny,
        roles=roles,
        tool_roles=tool_roles,
    )


def default_config_dict(allow_npub: str | None = None) -> dict:
    return {
        "auth": {
            "open": False,
            "max_skew_seconds": 60,
            "replay_ttl_seconds": 120,
            "trust_proxy": False,
            "allow_npubs": [allow_npub] if allow_npub else [],
            "deny_npubs": [],
            "roles": {},
        },
        "tools": {
            "admin_ping": {"roles": ["tools:admin"]},
        },
        "server": {
            "host": "127.0.0.1",
            "port": 8787,
        },
    }
