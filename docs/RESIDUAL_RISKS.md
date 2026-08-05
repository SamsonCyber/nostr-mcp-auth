# Residual risks (tested behavior)

These limits are intentional or out-of-scope for a single-process NIP-98 gate.
Tests in `tests/test_residual_risks.py` and `tests/test_harden_snoop.py` lock the behavior.

| Risk | Shipped behavior | Test |
|------|------------------|------|
| Process-local replay | Each AuthGate/ReplayCache tracks event ids only in-process. Two caches accept the same event once each. Same cache rejects the second use. **Not solved by shared Redis/DB.** | test_replay_is_process_local_across_gate_instances, test_same_gate_rejects_replay |
| Operator auth.open true | Runtime still accepts any valid NIP-98 identity when open is true. **serve hard-fails** unless `--force-open`. | test_open_mode_*, test_serve_policy.py |
| Operator trust_proxy true | Runtime still builds u from X-Forwarded-* when trust_proxy is true. **serve hard-fails** unless `--force-trust-proxy`. | test_trust_proxy_*, test_serve_policy.py |
| Stolen allowlisted nsec | Possession of the key is possession of the identity. **Not fixed by this gate.** | test_stolen_allowlisted_nsec_grants_access, test_stolen_non_allowlisted_nsec_still_denied |
| Clients without NIP-98 | Missing or non-Nostr Authorization never reaches tools (401). | test_client_without_nip98_cannot_call_tools, test_client_with_bearer_api_key_style_rejected, test_unsigned_tools_list_denied |

## Hardened (not residual)

| Control | Shipped behavior |
|---------|------------------|
| Snoop surface | Auth logs and HTTP bodies never emit nsec, private-key hex, full Authorization, or full base64 event tokens. |
| External oracle | Auth failures return a single external shape: `{"error":"unauthorized","code":"unauthorized"}`. Role denials use `forbidden` only. Internal reason codes stay in logs (scrubbed). |
| Cache | MCP responses set `Cache-Control: no-store, no-cache, must-revalidate, private` plus Pragma/Expires. |
| Method override | Real HTTP method only; override headers are ignored. |
| Serve footguns | `nostr-mcp-auth serve` refuses `auth.open=true` and `auth.trust_proxy=true` unless `--force-open` / `--force-trust-proxy`. `create_app` is unchanged for tests/ASGI embedders. |

## Ops mitigations

1. Multi-instance: shared replay store or single auth terminator (still residual; not Redis product).
2. Prefer open=false; only use `--force-open` for disposable labs.
3. trust_proxy only behind a proxy that strips client Forwarded headers, plus `--force-trust-proxy`.
4. Protect nsec like any service credential; rotate with allowlist updates.
5. Agents that cannot sign: local signing sidecar (SPEC section 7.3).
