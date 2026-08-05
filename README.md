# nostr-mcp-auth

# Lock MCP tools to a Nostr key

**No proof, no tools.** Agents sign every HTTP call with a Nostr secret. The server checks the signature offline. Wrong key, bad sig, stale event, or body swap: **401**. Tool code never runs.

```bash
pip install -e .
nostr-mcp-auth quickstart
nostr-mcp-auth serve
# other terminal:
nostr-mcp-auth call --tool whoami
```

Crypto identity for agent tool access. No OAuth dance required for the lab or fleet path.

---

## What is Nostr?

**Nostr** is a simple open protocol for signed messages. Each user (or agent) has:

| Piece | What it is |
|-------|------------|
| **nsec** | Private key. Signs. Keep offline / in a vault. |
| **npub** | Public key. Identity. Safe to put on an allowlist. |

Messages (events) are JSON objects with a **BIP-340 Schnorr signature**. Anyone can verify who signed without a central account server.

Common uses: social apps, relays, Lightning wallet connect. The part we care about for MCP is pure **crypto identity**: prove key possession.

You do **not** need Damus, a public relay, or a social profile for this package. Verification is local.

### NIP-98 (HTTP auth)

[NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) defines how to authorize an HTTP request with a short-lived signed event:

- Kind **27235**
- Tags bind the request: URL (`u`), method (`method`), optional body hash (`payload`)
- Header: `Authorization: Nostr <base64-encoded event>`

That is the protocol. This repo turns it into a **gate in front of MCP tools**.

---

## How we use Nostr for MCP

[MCP](https://modelcontextprotocol.io/) (Model Context Protocol) is how agents call tools over stdio or HTTP. Network MCP needs auth. We put NIP-98 on **`POST /mcp`**.

| Step | What happens |
|------|----------------|
| 1 | Agent (or sidecar) builds a NIP-98 event for this exact URL, method, and body. |
| 2 | Signs with **nsec**. |
| 3 | Sends JSON-RPC (`tools/list` / `tools/call`) plus `Authorization: Nostr …`. |
| 4 | Server verifies: kind, signature, time window, URL/method match, body hash, allowlist, optional roles, replay. |
| 5 | Only then does the tool run. |

```
Agent / sidecar                         MCP server (this package)
     |                                          |
     |  POST /mcp                               |
     |  Authorization: Nostr <signed event>     |
     |  tools/call { name, arguments }          |
     |----------------------------------------->|
     |                                          |  verify NIP-98 (offline)
     |                                          |  allowlist + roles
     |                                          |  run tool  OR  401/403
     |<-----------------------------------------|
```

**What we take from Nostr**

- Keypair identity (`npub` / `nsec`)
- Event shape + Schnorr signatures
- NIP-98 request binding

**What we do not need**

- Public relays for auth
- Social graph, follows, or notes
- Publishing the auth event anywhere

**What we add**

- Fail-closed HTTP MCP surface (`tools/list`, `tools/call`)
- Allow / deny lists and optional tool roles
- Process-local replay defense
- Operator CLI: `quickstart`, `serve`, `call`, `doctor`
- Red-team tested gate (see `docs/`)

---

## Plug in

### Install

```bash
git clone https://github.com/SamsonCyber/nostr-mcp-auth.git
cd nostr-mcp-auth
pip install -e .
```

### Bootstrap

```bash
nostr-mcp-auth quickstart
```

| File | Purpose |
|------|---------|
| `caller.nsec` | Agent secret (never commit) |
| `caller.npub` | Public identity |
| `mcp-auth.yaml` | Server config; npub already allowlisted |

### Serve

```bash
nostr-mcp-auth serve
# http://127.0.0.1:8787/mcp
# http://127.0.0.1:8787/health   (public)
```

`serve` refuses `auth.open=true` and `auth.trust_proxy=true` unless you pass
`--force-open` or `--force-trust-proxy` (lab / reverse-proxy only).

### Call

```bash
nostr-mcp-auth call --tool whoami
nostr-mcp-auth call --tool protected_echo --arg text=hello
nostr-mcp-auth list-tools
nostr-mcp-auth doctor
```

### Python

```python
from nostr_mcp_auth.client import call_tool

print(call_tool("http://127.0.0.1:8787/mcp", "caller.nsec", "whoami"))
```

See `examples/python_agent.py`.

### Agent UIs that cannot sign (Claude Desktop, etc.)

Most hosts do not implement NIP-98. Options:

1. Local **signing sidecar** that holds `nsec` and forwards signed HTTP.
2. Keep high-risk tools on this HTTP gate; use stdio only where local trust is enough.

Unsigned or plain `Bearer` clients get **401**. That is the gate doing its job.

---

## Endpoints and demo tools

| Path | Auth |
|------|------|
| `GET /health` | Public |
| `GET /ready` | Public |
| `POST /mcp` | Required |

| Tool | Access |
|------|--------|
| `whoami` | Allowlisted identity |
| `protected_echo` | Allowlisted identity |
| `admin_ping` | Role `tools:admin` |

Wire real tools behind the same pattern, or terminate network MCP at this process.

---

## Fail-closed checks

| Check | Result |
|-------|--------|
| Missing / wrong auth | 401, no tool side effects |
| Bad signature / wrong kind | 401 |
| Clock skew outside window | 401 |
| URL or method mismatch | 401 |
| Body hash mismatch | 401 |
| Empty allowlist | 401 for everyone |
| Deny list | Wins over allow |
| Replay (same event id) | 401 (process-local) |
| Missing tool role | 403 |
| Auth failure body | Generic `unauthorized` (no fine reason oracle) |
| MCP responses | `Cache-Control: no-store` (not shared-cacheable) |

Defaults: `open: false`, `trust_proxy: false`. Auth logs never print `nsec` or full
`Authorization` tokens. Multi-instance shared replay and stolen allowlisted `nsec`
remain residual (see residual risks).

More: [SPEC](docs/SPEC.md) · [residual risks](docs/RESIDUAL_RISKS.md) · [red-team](docs/REDTEAM_REPORT.md) · [wave 2](docs/REDTEAM_WAVE2_REPORT.md)

---

## Config

```yaml
auth:
  open: false
  allow_npubs:
    - npub1...
  roles:
    npub1...: [tools:admin]
tools:
  admin_ping:
    roles: [tools:admin]
server:
  host: 127.0.0.1
  port: 8787
```

Add agents by generating keys and appending npubs. Example: `examples/mcp-auth.example.yaml`.

## CLI

| Command | Job |
|---------|-----|
| `quickstart` | Identity + config |
| `serve` | Authenticated MCP HTTP (`--force-open` / `--force-trust-proxy` if needed) |
| `call` / `list-tools` | Signed client |
| `doctor` | Config + nsec + allowlist check |
| `gen-key` / `init` | Manual pieces |

## Dev

```bash
pip install -e ".[dev]"
pytest -q
```

Python 3.10+. Uses `coincurve` for BIP-340.

## License

MIT
