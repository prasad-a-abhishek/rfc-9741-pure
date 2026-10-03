"""
Hex / Base16 operators (.hex, .hexlc, .hexuc).

These are TOTAL functions — never raise on arbitrary input.
"""

from typing import Union

Result = Union[bytes, str]


def _err(msg: str) -> str:
    return f"ERROR:{msg}"


# ── shared ────────────────────────────────────────────────────────────────────

def _hex_bytes(target: str) -> bytes:
    """Decode a hex string (any case) to bytes.  Returns empty on failure."""
    clean = target.replace(" ", "").replace("-", "")
    if not clean:
        return b""
    try:
        return bytes.fromhex(clean)
    except Exception:
        return b""


# ── .hex ───────────────────────────────────────────────────────────────────────

def validate_hex(target: str, controller: bytes) -> bool:
    """
    Validate target is a hex-encoded representation of controller.
    Accepts both upper and lower case, with optional spaces/dashes.
    """
    if not isinstance(target, str) or not isinstance(controller, bytes):
        return False
    return _hex_bytes(target) == controller


def encode_hex(data: bytes) -> str:
    """Encode bytes to lower-case hex string."""
    if not isinstance(data, bytes):
        return _err("encode_hex requires bytes")
    return data.hex()


def decode_hex(target: str) -> bytes:
    """Decode a hex string to bytes.  Returns ERROR: string on failure."""
    if not isinstance(target, str):
        return _err(f"decode_hex requires str, got {type(target).__name__}")
    result = _hex_bytes(target)
    if result == b"" and target.replace(" ", "").replace("-", ""):
        return _err("decode_hex: invalid hex string")
    if not result and not target.replace(" ", "").replace("-", ""):
        return b""  # empty is valid
    return result


# ── .hexlc ────────────────────────────────────────────────────────────────────

def validate_hexlc(target: str, controller: bytes) -> bool:
    """
    Validate target is a lower-case-only hex representation of controller.
    Rejects upper-case characters.
    """
    if not isinstance(target, str) or not isinstance(controller, bytes):
        return False
    clean = target.replace(" ", "").replace("-", "")
    if clean != clean.lower():
        return False
    return _hex_bytes(target) == controller


# ── .hexuc ────────────────────────────────────────────────────────────────────

def validate_hexuc(target: str, controller: bytes) -> bool:
    """
    Validate target is an upper-case-only hex representation of controller.
    Rejects lower-case characters.
    """
    if not isinstance(target, str) or not isinstance(controller, bytes):
        return False
    clean = target.replace(" ", "").replace("-", "")
    if clean != clean.upper():
        return False
    return _hex_bytes(target) == controller
