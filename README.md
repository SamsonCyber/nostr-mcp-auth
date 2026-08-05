# nostr-mcp-auth

**NIP-98 authentication for HTTP MCP.**  
Agents prove a Nostr identity. No proof, no tools.

Fail-closed. Offline verify. No relay on the hot path. Built for operators who want crypto identity on MCP without turning OAuth into a second product.

```bash
pip install -e .
nostr-mcp-auth quickstart
nostr-mcp-auth serve
# other terminal:
nostr-mcp-auth call --tool whoami
```

That is the whole loop.

---

## Why this exists

MCP over the network needs auth. Stock options are:

- **Nothing** (local stdio trust)
- **OAuth 2.1** (full IdP, right for some enterprises)
- **Shared API keys** (boring, leaked forever)

**nostr-mcp-auth** is a third rail: every request carries a short-lived **signed Nostr event** (NIP-98). The server checks the signature, URL, method, body hash, allowlist, and optional roles. If anything is wrong, tools never run.

You are not inventing passwords. You are binding MCP calls to **key possession**.

---

## 30-second plug-in

### 1. Install

```bash
git clone https://github.com/SamsonCyber/nostr-mcp-auth.git
cd nostr-mcp-auth
pip install -e .
```

### 2. Bootstrap identity + config

```bash
nostr-mcp-auth quickstart
```

Creates:

| File | Purpose |
|------|---------|
| `caller.nsec` | Secret key for the agent (do not commit) |
| `caller.npub` | Public identity |
| `mcp-auth.yaml` | Server config with that npub allowlisted |

### 3. Serve

```bash
nostr-mcp-auth serve
# http://127.0.0.1:8787/mcp
# http://127.0.0.1:8787/health   (no auth)
```

### 4. Call like an agent

```bash
nostr-mcp-auth call --tool whoami
nostr-mcp-auth call --tool protected_echo --arg text=hello
nostr-mcp-auth list-tools
```

### 5. Sanity check

```bash
nostr-mcp-auth doctor
```

---

## How agents authenticate

```
Agent / sidecar                 MCP server
     |                               |
     |  POST /mcp                    |
     |  Authorization: Nostr <evt>   |
     |  JSON-RPC tools/call          |
     |------------------------------>|
     |     verify NIP-98             |
     |     allowlist + roles         |
     |     then run tool             |
     |<------------------------------|
```

1. Build event kind **27235** with tags `u` (URL), `method`, optional `payload` (body SHA-256).
2. Sign with **nsec**.
3. Send `Authorization: Nostr <base64 event>`.
4. Server verifies offline. No Damus. No relay round-trip.

### Python (same path the CLI uses)

```python
from nostr_mcp_auth.client import call_tool

print(call_tool("http://127.0.0.1:8787/mcp", "caller.nsec", "whoami"))
```

See also `examples/python_agent.py`.

### Stock agent UIs (Claude Desktop, etc.)

They usually **cannot** sign NIP-98 themselves. Options:

1. Call MCP only through a **local signing sidecar** that holds `nsec` and forwards signed HTTP.
2. Keep high-risk tools behind this HTTP gate; use stdio only for local trust.

Unsigned / Bearer-only clients get **401**. That is the product working.

---

## What is protected

| Path | Auth |
|------|------|
| `GET /health` | Public |
| `GET /ready` | Public |
| `POST /mcp` | **Required** (`tools/list`, `tools/call`) |

Demo tools (prove the gate):

| Tool | Who |
|------|-----|
| `whoami` | Any allowlisted identity |
| `protected_echo` | Any allowlisted identity |
| `admin_ping` | Role `tools:admin` only |

Wire your real MCP tools behind the same gate pattern (or put this process as the network edge).

---

## Security posture (not marketing fluff)

| Check | Behavior |
|-------|----------|
| Missing / wrong auth | 401, **no tool side effects** |
| Bad signature / wrong kind | 401 |
| Clock skew outside window | 401 |
| URL or method mismatch | 401 |
| Body hash mismatch | 401 |
| Empty allowlist | 401 for everyone |
| Deny list | Wins over allow |
| Replay (same event id) | 401 (process-local cache) |
| Missing tool role | 403 |

Red-team notes: `docs/REDTEAM_REPORT.md`, `docs/REDTEAM_WAVE2_REPORT.md`, `docs/RESIDUAL_RISKS.md`.  
Full protocol: `docs/SPEC.md`.

**Defaults matter:** `open: false`, `trust_proxy: false`. Empty allowlist does **not** mean open.

---

## Config (minimal)

`mcp-auth.yaml` from quickstart already works. Shape:

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

Add more agents = generate more keys, append npubs to `allow_npubs`.

---

## CLI map

| Command | Job |
|---------|-----|
| `quickstart` | Identity + config in one shot |
| `serve` | Run authenticated MCP HTTP |
| `call` / `list-tools` | Signed client |
| `doctor` | Config + nsec + allowlist check |
| `gen-key` / `init` | Manual pieces if you skip quickstart |

---

## Install options

```bash
# from clone
pip install -e ".[dev]"

# tests
pytest -q
```

Requires Python 3.10+ and `coincurve` (BIP-340).

---

## What you are getting that is rare

Pieces of Nostr auth and pieces of MCP exist everywhere.  
A **fail-closed NIP-98 gate for HTTP MCP**, with operator CLI, signed client, allow/deny roles, replay defense, and a red-team test matrix, does not.

This is crypto identity for agent tools, not a social client.

---

## License

MIT · Spec and residual risks under `docs/`
