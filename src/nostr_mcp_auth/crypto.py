"""BIP-340 / NIP-01 crypto helpers (self-contained)."""
from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any


class CryptoError(Exception):
    pass


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def generate_private_key_hex() -> str:
    return secrets.token_hex(32)


def xonly_pubkey_hex(private_key_hex: str) -> str:
    from coincurve import PrivateKey, PublicKeyXOnly

    key = private_key_hex.strip().lower().removeprefix("0x")
    if len(key) != 64:
        raise CryptoError("private key must be 32-byte hex")
    pk = PrivateKey(bytes.fromhex(key))
    return PublicKeyXOnly.from_valid_secret(pk.secret).format().hex()


def sign_message32(private_key_hex: str, message32: bytes) -> str:
    from coincurve import PrivateKey

    if len(message32) != 32:
        raise CryptoError("message must be 32 bytes")
    key = private_key_hex.strip().lower().removeprefix("0x")
    return PrivateKey(bytes.fromhex(key)).sign_schnorr(message32).hex()


def verify_message32(pubkey_hex: str, signature_hex: str, message32: bytes) -> bool:
    from coincurve import PublicKeyXOnly

    if len(message32) != 32:
        return False
    try:
        pub = PublicKeyXOnly(bytes.fromhex(pubkey_hex.strip().lower()))
        sig = bytes.fromhex(signature_hex.strip().lower())
        if len(sig) != 64:
            return False
        return bool(pub.verify(sig, message32))
    except Exception:
        return False


def compute_event_id(
    pubkey: str,
    created_at: int,
    kind: int,
    tags: list[list[str]],
    content: str,
) -> str:
    serialized = json.dumps(
        [0, pubkey, created_at, kind, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256_hex(serialized)


def sign_event(private_key_hex: str, event: dict[str, Any]) -> dict[str, Any]:
    pubkey = xonly_pubkey_hex(private_key_hex)
    created_at = int(event["created_at"])
    kind = int(event["kind"])
    tags = list(event.get("tags") or [])
    content = str(event.get("content") or "")
    eid = compute_event_id(pubkey, created_at, kind, tags, content)
    sig = sign_message32(private_key_hex, bytes.fromhex(eid))
    return {
        "id": eid,
        "pubkey": pubkey,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": sig,
    }


def verify_event_id_and_sig(event: dict[str, Any]) -> bool:
    try:
        if not isinstance(event, dict):
            return False
        pubkey = str(event["pubkey"]).lower()
        # NIP-01 serialization uses JSON numbers for created_at/kind
        created_at = event["created_at"]
        kind = event["kind"]
        if isinstance(created_at, bool) or isinstance(kind, bool):
            return False
        if not isinstance(created_at, int) or not isinstance(kind, int):
            # reject stringy types that would alter JSON serialization vs int()
            return False
        tags = event.get("tags")
        if not isinstance(tags, list):
            return False
        content = event.get("content")
        if content is None:
            content = ""
        if not isinstance(content, str):
            return False
        expected = compute_event_id(pubkey, created_at, kind, tags, content)
        if str(event.get("id") or "").lower() != expected:
            return False
        return verify_message32(pubkey, str(event.get("sig") or ""), bytes.fromhex(expected))
    except Exception:
        return False


# --- minimal bech32 for npub/nsec ---

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data: bytes | list[int], frombits: int, tobits: int, pad: bool = True) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise CryptoError("invalid convertbits")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise CryptoError("invalid padding")
    return ret


def bech32_encode(hrp: str, data: list[int]) -> str:
    polymod = _polymod(_hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


def bech32_decode(bech: str) -> tuple[str, bytes]:
    bech = bech.strip()
    if bech.lower() != bech and bech.upper() != bech:
        raise CryptoError("mixed case bech32")
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1:
        raise CryptoError("invalid bech32")
    hrp = bech[:pos]
    data_part = bech[pos + 1 :]
    try:
        data = [_CHARSET.index(c) for c in data_part]
    except ValueError as exc:
        raise CryptoError("invalid bech32 character") from exc
    if _polymod(_hrp_expand(hrp) + data) != 1:
        raise CryptoError("invalid bech32 checksum")
    raw = bytes(_convertbits(data[:-6], 5, 8, pad=False))
    if len(raw) != 32:
        raise CryptoError("decoded length != 32")
    return hrp, raw


def npub_encode(pubkey_hex: str) -> str:
    return bech32_encode("npub", _convertbits(bytes.fromhex(pubkey_hex.strip().lower()), 8, 5))


def nsec_encode(private_key_hex: str) -> str:
    return bech32_encode("nsec", _convertbits(bytes.fromhex(private_key_hex.strip().lower()), 8, 5))


def normalize_pubkey(value: str) -> str:
    value = value.strip()
    if value.startswith("npub1"):
        hrp, raw = bech32_decode(value)
        if hrp != "npub":
            raise CryptoError("expected npub")
        return raw.hex()
    key = value.lower().removeprefix("0x")
    if len(key) != 64:
        raise CryptoError("pubkey must be npub or 64-hex")
    return key


def load_private_key(value: str) -> str:
    value = value.strip()
    if value.startswith("nsec1"):
        hrp, raw = bech32_decode(value)
        if hrp != "nsec":
            raise CryptoError("expected nsec")
        return raw.hex()
    # file path?
    from pathlib import Path

    p = Path(value)
    if p.is_file():
        return load_private_key(p.read_text(encoding="utf-8").strip())
    key = value.lower().removeprefix("0x")
    if len(key) != 64:
        raise CryptoError("private key must be nsec, hex, or file path")
    return key
