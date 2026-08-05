# Spec: Nostr-authenticated MCP (NIP-98 HTTP gate)

**Product:** `nostr-mcp-auth`  
**Version:** 1.0  
**Status:** implementable / corporate plug-and-play  

## 1. Problem

Networked MCP servers need identity before tools run. OAuth 2.1 is the MCP ecosystem default. Many operator and agent fleets already hold Nostr keys. This product adds a **fail-closed crypto identity rail**: callers prove control of an allowlisted `npub` via **NIP-98** on every HTTP MCP request.

Offline verification only. No live relay required for the auth hot path.

## 2. Non-goals

- Replacing OAuth as the only enterprise IdP  
- Silent honeypot / agent-canary tripwires  
- Multi-tenant SaaS, billing, hosted relays  
- Full NIP-46 remote-signer product (local nsec or sidecar is enough for v1)  
- Infinite adversary proofs beyond the listed attack classes  

## 3. Trust model

| Party | Holds | Trust |
|-------|--------|--------|
| Operator | Server process, allowlist config, optional policy | Configures who may call tools |
| Caller (agent / sidecar) | `nsec` for an allowlisted `npub` | Proves key possession per request |
| Adversary | Network, replay of captured headers within limits | Must not reach protected tool logic |

Empty allowlist = **deny all** (not open). Open mode requires explicit `auth.open: true` (forbidden in production profiles).

## 4. Protocol (NIP-98)

### 4.1 Event

- `kind`: **27235**  
- `created_at`: unix seconds; server accepts if `|now - created_at| <= max_skew_seconds` (default **60**)  
- `pubkey`: 64-char hex x-only  
- `tags` (required):  
  - `["u", "<absolute request URL>"]`  
  - `["method", "<HTTP method uppercase>"]`  
- `tags` (required when body present and non-empty):  
  - `["payload", "<sha256 hex of raw body bytes>"]`  
- `content`: empty string  
- `id` / `sig`: NIP-01 event id and BIP-340 Schnorr over id  

### 4.2 HTTP header

```http
Authorization: Nostr <base64url or standard base64 of UTF-8 JSON event>
```

Scheme is case-sensitive **`Nostr`**. Payload is the full signed event JSON object (not only the sig).

### 4.3 Server verification order (fail closed)

1. Parse `Authorization`; reject missing / wrong scheme / bad base64 / bad JSON  
2. Verify `kind == 27235`  
3. Verify event `id` binds to serialized event (NIP-01)  
4. Verify BIP-340 signature for `pubkey`  
5. Check timestamp window  
6. Normalize and compare `u` to reconstructed absolute request URL  
7. Compare `method` to request method (ASCII upper)  
8. If body length > 0: require `payload` tag equals SHA-256 hex of raw body  
9. Check allowlist / denylist on `pubkey`  
10. Optional: reject replayed event `id` within TTL (in-memory set, default on)  

On any failure: **HTTP 401**, JSON body `{"error":"unauthorized","reason":"<stable_code>"}`. **No tool handler side effects.**

### 4.4 URL binding (`u`)

Server builds absolute URL as:

```
{scheme}://{host}{path}{?query}
```

- Prefer `X-Forwarded-Proto` / `X-Forwarded-Host` only when `trust_proxy: true`  
- Default: use ASGI scheme/host from the connection  
- Trailing slash: compare after RFC3986 path normalization (no double-decode tricks)  
- Client must sign the **same** URL string the server reconstructs  

### 4.5 Anti-replay

Default: remember event `id` for `replay_ttl_seconds` (default **120**). Second use → 401 `replay`. Process-local only in v1 (document multi-instance need for shared store).

## 5. Authorization policy

Config file (YAML/JSON) or env:

```yaml
auth:
  open: false                 # MUST be false for production
  max_skew_seconds: 60
  replay_ttl_seconds: 120
  trust_proxy: false
  allow_npubs:                # bech32 npub1… or 64-hex
    - npub1...
  deny_npubs: []
  # optional: map pubkey -> roles
  roles:
    npub1...: [tools:read, tools:admin]
tools:
  # optional per-tool role requirement; default = any allowlisted identity
  admin_ping:
    roles: [tools:admin]
```

Deny list wins over allow list. Unknown role required → 403 after successful auth.

## 6. MCP surface

- Transport: **HTTP Streamable and/or SSE** on Starlette/uvicorn (v1 ships Streamable-friendly Starlette app + JSON-RPC tools/call demo).  
- Protected paths: all MCP JSON-RPC endpoints and tool invocations behind the gate.  
- Public paths: `/health` (no auth), `/ready` (no auth).  

Demo tools (prove side-effect flag):

- `whoami` → returns authenticated `pubkey` / `npub`  
- `protected_echo` → echoes text **only** if auth passed (test spy)  
- `admin_ping` → requires role `tools:admin`  

## 7. Corporate plug-and-play

### 7.1 Operator

```bash
pip install -e .
nostr-mcp-auth init --out ./mcp-auth.yaml
nostr-mcp-auth gen-key --write-nsec ./caller.nsec
# add printed npub to allow_npubs
nostr-mcp-auth serve --config ./mcp-auth.yaml --host 0.0.0.0 --port 8787
```

### 7.2 Agent / CI client

```bash
nostr-mcp-auth call \
  --url http://127.0.0.1:8787/mcp \
  --nsec ./caller.nsec \
  --tool whoami
```

Or Python:

```python
from nostr_mcp_auth.client import signed_request, load_nsec
```

### 7.3 Sidecar (dumb MCP hosts)

Hosts that cannot sign NIP-98 use a local sidecar that holds `nsec`, signs outbound HTTP to the remote MCP, and speaks stdio MCP to the host. v1 ships the signing client; stdio sidecar is optional follow-on if time permits (document interface).

## 8. Audit

Each decision logs (structured): `ts`, `result` (ok|deny), `reason`, `pubkey` (if known), `method`, `path`, `event_id` (if known). No private keys in logs.

## 9. Threats in scope (must fail closed)

| Attack | Expected |
|--------|----------|
| Missing Authorization | 401, no tool run |
| Bad / truncated signature | 401 |
| Wrong kind | 401 |
| Expired / future `created_at` outside skew | 401 |
| `u` or `method` mismatch | 401 |
| Body present without matching `payload` | 401 |
| Non-allowlisted npub | 401 |
| Deny-listed npub | 401 |
| Replay of same event id within TTL | 401 |
| Empty allowlist with `open: false` | 401 for all |

## 10. Acceptance

1. Spec matches implementation.  
2. Unit tests cover pure verifier fail matrix.  
3. Integration tests: ASGI app + signed client → tool runs; negatives never set tool side-effect.  
4. CLI `serve` + `call` works twice with real keys.  
5. Scrutiny report: zero open Critical/Major on auth gate.
