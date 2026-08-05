# Second red-team / exhaustiveness report: nostr-mcp-auth

**Date:** 2026-08-05  
**Baseline:** Prior hardening (RT-1..RT-6 in `docs/REDTEAM_REPORT.md`)  
**Goal:** Re-attack residual hot-path options; prove no new unauthorized tool execution.

## Wave-2 attacks tried

| Attack | Result |
|--------|--------|
| Oversized Authorization token | 401 `token_too_large` |
| Query-string strip (`?x=1` signed vs bare `/mcp`) | 401 `url_mismatch` |
| Path case fold (`/MCP` vs `/mcp`) | 401 `url_mismatch` |
| Concurrent 12-thread same-event race | **1 ok + 11 replay** (lock holds) |
| Padded method tag `" POST "` | 401 `method_mismatch` |
| Null byte in `u` tag | 401 `url_mismatch` |
| Empty token after `Nostr` | AuthError |
| `trust_proxy: false` + `X-Forwarded-Host: evil` | 401; forward headers ignored |
| Allowlisted but missing tool role | 403; **no** `TOOL_INVOCATIONS` |
| Malformed tags shape | AuthError (not 500) |
| Prior matrix (sig/kind/replay/deny/payload/body) | Still green (47 tests) |

## New unauthorized-tool breaks this pass

**Zero.**

No production code change required beyond adding permanent wave-2 tests (`tests/test_redteam_wave2.py`). Hardening from the first red-team held.

## Proof artifacts

| File | Content |
|------|---------|
| `{SCRATCH}/rt2-pytest.log` | Full suite **47 passed** |
| `{SCRATCH}/rt2-launch.log` | Serve ×2: unauth 401, signed whoami 200 |
| `{SCRATCH}/rt2-probes.log` | Ad-hoc residual probes (0 BREAK) |
| `{SCRATCH}/rt2-grep.log` | No always-true / TODO-bypass on auth modules |
| `docs/REDTEAM_WAVE2_REPORT.md` | This exhaustiveness note |

## Residual risks (exhausted for v1 hot path)

| Residual | Why not a wave-2 code fix |
|----------|---------------------------|
| Multi-instance replay | Process-local `ReplayCache`; needs shared store product |
| Operator sets `auth.open: true` | Explicit open mode; default false |
| Operator sets `trust_proxy: true` with untrusted edge | Default false; documented footgun |
| BIP-340 cryptanalysis / stolen nsec | Out of scope; identity proof assumes key secrecy |
| Clients without NIP-98 signing | Sidecar path in SPEC; not an open gate |

## Closed hot-path matrix (cumulative)

Missing/malformed auth · bad sig · wrong/typed kind · clock skew · u/method binding · payload/body · allow/deny/empty allow · replay (incl. concurrent) · roles · encoding/whitespace · ambiguous tags · empty content · oversized token · query/path case · forwarded-host when trust_proxy false · GET without tools.

## Open Critical / Major (unauthorized tools)

**Zero.**
