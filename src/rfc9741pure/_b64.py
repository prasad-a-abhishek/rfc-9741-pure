"""
Base64url (.b64u) and Base64 classic (.b64c) operators.

These are TOTAL functions — never raise on arbitrary input.
"""

import base64
from typing import Union

Result = Union[bytes, str]


def _err(msg: str) -> str:
    return f"ERROR:{msg}"


# ── .b64u ─────────────────────────────────────────────────────────────────────

_B64URL_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

def validate_b64u(target: str, controller: bytes) -> bool:
    """Validate target is a base64url-encoded representation of controller.

    Per RFC 4648 §5, base64url uses the URL-safe alphabet and does NOT use
    padding. Strings containing '=' are rejected.
    """
    if not isinstance(target, str) or not isinstance(controller, bytes):
        return False
    # '=' is not part of the base64url alphabet — reject padded input
    if "=" in target:
        return False
    if not all(c in _B64URL_CHARS for c in target):
        return False
    try:
        # Decode by adding proper padding (multiple of 4 chars)
        pad_len = (4 - len(target) % 4) % 4
        decoded = base64.urlsafe_b64decode(target + "=" * pad_len)
        return decoded == controller
    except Exception:
        return False


def encode_b64u(data: bytes) -> str:
    """Encode bytes to base64url string without padding."""
    if not isinstance(data, bytes):
        return _err("encode_b64u requires bytes")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_b64u(target: str) -> bytes:
    """Decode a base64url string to bytes.  Returns ERROR: string on failure.

    Per RFC 4648 §5, base64url must not contain '=' padding characters.
    """
    if not isinstance(target, str):
        return _err(f"decode_b64u requires str, got {type(target).__name__}")
    # Reject padding — base64url per RFC 4648 §5 has no padding
    if "=" in target:
        return _err("decode_b64u: padding not allowed in base64url")
    if not all(c in _B64URL_CHARS for c in target):
        return _err("decode_b64u: invalid character")
    # Add padding to make length a multiple of 4 before decoding
    padding = (4 - len(target) % 4) % 4
    try:
        return base64.urlsafe_b64decode(target + "=" * padding)
    except Exception as e:
        return _err(f"decode_b64u: {e}")


# ── .b64c ─────────────────────────────────────────────────────────────────────

def validate_b64c(target: str, controller: bytes) -> bool:
    """Validate target is a base64-encoded (classic) representation of controller."""
    if not isinstance(target, str) or not isinstance(controller, bytes):
        return False
    try:
        decoded = base64.b64decode(target)
        return decoded == controller
    except Exception:
        return False


def encode_b64c(data: bytes) -> str:
    """Encode bytes to base64 string with padding."""
    if not isinstance(data, bytes):
        return _err("encode_b64c requires bytes")
    return base64.b64encode(data).decode("ascii")


def decode_b64c(target: str) -> bytes:
    """Decode a base64 string to bytes.  Returns ERROR: string on failure."""
    if not isinstance(target, str):
        return _err(f"decode_b64c requires str, got {type(target).__name__}")
    try:
        return base64.b64decode(target)
    except Exception as e:
        return _err(f"decode_b64c: {e}")
