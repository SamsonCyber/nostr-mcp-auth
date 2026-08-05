"""Scrub secrets from log and response surfaces (fail-closed for leakage)."""
from __future__ import annotations

import re

# nsec bech32 (data portion after hrp)
_NSEC_RE = re.compile(r"\bnsec1[0-9a-z]{20,}\b", re.IGNORECASE)
# Authorization: Nostr <token> or bare scheme + base64-ish token
_AUTH_HEADER_RE = re.compile(
    r"(?i)(?:authorization\s*[:=]\s*)?Nostr\s+[A-Za-z0-9+/_=-]{16,}"
)
# Long base64 blobs that look like encoded events (standalone)
_LONG_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b")
# 64 hex chars (could be sk or pubkey; scrub when labeled as secret)
_HEX64_LABELED_RE = re.compile(
    r"(?i)\b(?:nsec|private[_-]?key|sk|secret)\b[^\n]{0,40}\b([0-9a-f]{64})\b"
)
_HEX64_STANDALONE = re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE)

REDACTED = "[REDACTED]"


def scrub_secrets(text: str) -> str:
    """Remove common secret shapes from a string for safe logging."""
    if not text:
        return text
    out = str(text)
    out = _NSEC_RE.sub(REDACTED, out)
    out = _AUTH_HEADER_RE.sub(f"Nostr {REDACTED}", out)
    out = _HEX64_LABELED_RE.sub(lambda m: m.group(0).replace(m.group(1), REDACTED), out)
    out = _LONG_B64_RE.sub(REDACTED, out)
    return out


def looks_like_secret_material(
    text: str,
    *,
    private_key_hex: str | None = None,
    authorization: str | None = None,
    nsec: str | None = None,
) -> bool:
    """True if text contains known secret material (for tests and guards)."""
    if not text:
        return False
    lowered = text.lower()
    if private_key_hex and private_key_hex.lower() in lowered:
        return True
    if nsec and nsec.lower() in lowered:
        return True
    if authorization:
        # full header or bare token after scheme
        if authorization in text:
            return True
        parts = authorization.split(None, 1)
        if len(parts) == 2 and parts[1] and parts[1] in text:
            return True
    if _NSEC_RE.search(text):
        return True
    if re.search(r"(?i)Nostr\s+[A-Za-z0-9+/_=-]{40,}", text):
        return True
    return False


def safe_path_for_log(url: str, *, max_len: int = 200) -> str:
    """Log-safe request target: drop query string, cap length, scrub."""
    if not url:
        return ""
    base = url.split("?", 1)[0]
    if len(base) > max_len:
        base = base[: max_len - 3] + "..."
    return scrub_secrets(base)
