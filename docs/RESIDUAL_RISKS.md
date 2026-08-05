# Residual risks (tested behavior)

These limits are intentional or out-of-scope for a single-process NIP-98 gate.
Tests in `tests/test_residual_risks.py` lock the behavior.

| Risk | Shipped behavior | Test |
|------|------------------|------|
| Process-local replay | Each AuthGate/ReplayCache tracks event ids only in-process. Two caches accept the same event once each. Same cache rejects the second use. | test_replay_is_process_local_across_gate_instances, test_same_gate_rejects_replay |
| Operator auth.open true | Any cryptographically valid NIP-98 identity is accepted (allowlist ignored). Default is false. | test_open_mode_allows_any_valid_signature_not_on_allowlist, test_open_false_empty_allowlist_still_denies |
| Operator trust_proxy true | u is built from X-Forwarded-Proto / X-Forwarded-Host. Default false ignores forwarded headers. | test_trust_proxy_true_uses_forwarded_host_for_u_binding, test_trust_proxy_false_ignores_forwarded_even_if_signed_for_it |
| Stolen allowlisted nsec | Possession of the key is possession of the identity. | test_stolen_allowlisted_nsec_grants_access, test_stolen_non_allowlisted_nsec_still_denied |
| Clients without NIP-98 | Missing or non-Nostr Authorization never reaches tools (401). | test_client_without_nip98_cannot_call_tools, test_client_with_bearer_api_key_style_rejected, test_unsigned_tools_list_denied |

## Ops mitigations

1. Multi-instance: shared replay store or single auth terminator.
2. Never set open true in production.
3. trust_proxy only behind a proxy that strips client Forwarded headers.
4. Protect nsec like any service credential; rotate with allowlist updates.
5. Agents that cannot sign: local signing sidecar (SPEC section 7.3).
