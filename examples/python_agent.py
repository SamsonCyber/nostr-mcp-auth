"""Minimal agent-style caller: sign NIP-98 and invoke a protected tool."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from nostr_mcp_auth.client import call_tool

# Usage: python python_agent.py [nsec_path] [mcp_url] [tool]
nsec = sys.argv[1] if len(sys.argv) > 1 else "caller.nsec"
url = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8787/mcp"
tool = sys.argv[3] if len(sys.argv) > 3 else "whoami"

if not Path(nsec).exists():
    raise SystemExit(f"missing nsec file: {nsec} (run: nostr-mcp-auth quickstart)")

result = call_tool(url, nsec, tool)
print(json.dumps(result, indent=2))
if result.get("status_code") != 200:
    raise SystemExit(1)
