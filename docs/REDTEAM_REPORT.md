# Red-team report: nostr-mcp-auth

**Date:** 2026-08-05  
**Target:** `C:\code\nostr-mcp-auth` NIP-98 gate + HTTP MCP entry  
**Bar:** Unauthorized callers must never execute protected tools (fail-closed).

## Attacks executed

| Class | Vehicle | Result |
|-------|---------|--------|
| Missing Authorization | unit + HTTP | 401, no side effect |
| Bad / truncated signature | unit + HTTP | 401 |
| Wrong kind / kind as list/bool | unit + HTTP | AuthError/401 (was TypeError 500) |
| Expired / far-future `created_at` | unit + HTTP | 401 expired |
| `u` / `method` mismatch | unit + HTTP | 401 |
| Body swap after sign | HTTP | 401 payload_mismatch |
| Missing / wrong payload | unit | AuthError |
| Payload tag without body | unit | AuthError payload_without_body |
| Non-allowlisted npub | HTTP | 401 |
| Empty allowlist | HTTP | 401 |
| Deny list over allow | unit | 401 denied_npub |
| Event-id replay | unit + HTTP | 401 replay |
| Role denied | HTTP | 403, no side effect |
| Mutate pubkey / strip tags | HTTP | 401 |
| Bearer instead of Nostr | HTTP | 401 |
| Sign for evil Host, hit real host | HTTP | 401 url_mismatch |
| Base64 with embedded whitespace | unit | 401 invalid_token_encoding |
| Non-empty NIP-98 content | unit | 401 invalid_content |
| Ambiguous duplicate `u` tags | unit | 401 ambiguous_u |
| GET /mcp unauthenticated | HTTP | 401, no tools |
| Scheme case `nostr`/`NOSTR` | unit | rejected |

## Breaks found (pre-fix)

| ID | Severity | Evidence | Fix |
|----|----------|----------|-----|
| RT-1 | **Major** | `kind: [27235]` caused `TypeError` (500 path) instead of AuthError | `_safe_int` + type guards before crypto |
| RT-2 | **Major** | Base64 token with embedded newlines still decoded (`validate=False`) | Reject whitespace in token; `validate=True` |
| RT-3 | **Major** | Non-empty `content` accepted (NIP-98 requires empty) | Require `content == ""` |
| RT-4 | **Major** | Multiple conflicting `u` tags used first only (ambiguous binding) | Reject if distinct values for same tag name |
| RT-5 | **Major** | Event with `payload` accepted on empty body | `payload_without_body` deny |
| RT-6 | Minor | GET shared POST handler semantics | Separate GET → 401/405, never tool dispatch |

## Post-fix proof

- **37** pytest tests green → `{SCRATCH}/redteam-pytest.log`
- Probe log → `{SCRATCH}/redteam-attacks.log` (kind list now AuthError; newlines rejected; content rejected)
- Dual live launch unauth 401 + signed whoami 200 → `{SCRATCH}/redteam-launch.log`
- Grep theater clean → `{SCRATCH}/redteam-grep.log`

Allow path still works: allowlisted signed `whoami` returns matching pubkey and records `TOOL_INVOCATIONS`.

## Residual risks (no unauthorized tool execution)

| Risk | Blocker |
|------|---------|
| Process-local replay cache | Shared store for multi-instance deploys |
| `auth.open: true` intentionally opens world | Operator config; default false |
| `trust_proxy: true` trusts X-Forwarded-* | Default false; TLS terminator must be trusted |
| Client clock skew beyond `max_skew_seconds` | Tune config; not an auth bypass |

## Open Critical / Major allowing unauthorized tools

**Zero.**
