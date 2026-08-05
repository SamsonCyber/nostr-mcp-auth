# Scrutiny / oligarchy report: nostr-mcp-auth

**Date:** 2026-08-05  
**Surface:** NIP-98 HTTP MCP auth gate (`docs/SPEC.md` + `src/nostr_mcp_auth`)  
**Verdict:** Ship-grade v1 for corporate plug-and-play with documented limits. Zero open Critical/Major on the auth hot path.

## Scorecard (auth critical path)

| Axis | Score | Notes |
|------|------:|-------|
| Fail-closed default | 9 | Empty allowlist denies all; `open` defaults false |
| Crypto correctness | 9 | BIP-340 + NIP-01 id bind via coincurve |
| Binding (u/method/payload) | 9 | Tested mismatch + missing payload |
| Replay | 8 | Process-local TTL cache; multi-instance needs shared store (deferred) |
| Role ACL | 8 | Per-tool roles after identity |
| Tool side-effect isolation | 10 | `TOOL_INVOCATIONS` only after auth |
| Corporate plug path | 8 | CLI init/gen-key/serve/call documented |
| Client ecosystem | 6 | Dumb hosts need sidecar (SPEC §7.3); OAuth dual-mode non-goal |

## Findings

### Critical
None open.

### Major
None open.

### Major fixed during build
| ID | Finding | Fix |
|----|---------|-----|
| M1 | Empty allowlist must not open the world | `is_authorized` returns `empty_allowlist` when allow set empty and `open` false |
| M2 | Tools must not run on 401 | Handlers only after `authenticate`; tests assert empty `TOOL_INVOCATIONS` |
| M3 | Replay within skew window | `ReplayCache` on event id |

### Minor / deferred
| ID | Finding | Blocker |
|----|---------|---------|
| m1 | Replay cache is process-local | Shared Redis/DB store for multi-instance |
| m2 | No native Claude Desktop NIP-98 | Sidecar / signing proxy (SPEC) |
| m3 | `trust_proxy` host injection if enabled carelessly | Default false; operators must terminate TLS correctly |

## Red-team matrix (shipped tests)

| Attack | Test | Result |
|--------|------|--------|
| Missing auth | `test_missing_auth_no_tool_side_effect` | 401, no side effect |
| Bad sig | `test_bad_signature` | AuthError |
| Expired | `test_expired` / `test_expired_event` | 401 expired |
| URL mismatch | `test_url_mismatch` | AuthError |
| Method mismatch | `test_method_mismatch` / swap tag | 401 |
| Payload mismatch | `test_payload_mismatch` | AuthError |
| Strip payload | `test_strip_payload_tag` | 401 |
| Not allowlisted | `test_not_allowlisted_no_tool` | 401 |
| Empty allowlist | `test_empty_allowlist_denies_all` | 401 |
| Replay | `test_replay_rejected` / HTTP second post | 401 |
| Role missing | `test_admin_role_denied_without_role` | 403, no side effect |
| Mutate pubkey | `test_mutate_pubkey_fails` | 401 |

## Evidence captures

- `{SCRATCH}/nostr-mcp-auth-pytest.log` — 23 passed  
- `{SCRATCH}/nostr-mcp-auth-launch.log` — serve ×2, signed whoami + tools/list  
- `{SCRATCH}/nostr-mcp-auth-agent.log` — signed HTTP JSON-RPC agent path  
- `{SCRATCH}/nostr-mcp-auth-redteam.log` — copy of pytest (includes redteam)  

## Grep theater

No `return True` auth bypass, no empty-allowlist-open, no TODO on verify path in `nip98.py` / `gate.py`.

## Residual Critical/Major

**Zero.**
