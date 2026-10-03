"""
.base10 operator — decimal integer text representation.

These are TOTAL functions — never raise on arbitrary input.
"""

import re
from typing import Union

Result = Union[str, int]


def _err(msg: str) -> str:
    return f"ERROR:{msg}"


# Valid .base10 representations per RFC 9741:
#   /^-?([1-9][0-9]*|0)$/  (no leading zeros except solo zero)
_BASE10_RE = re.compile(r"^-?([1-9][0-9]*|0)$")


def validate_base10(target: str, controller: int) -> bool:
    """
    Validate target is the decimal string representation of controller.
    Rejects leading zeros (except '0' itself) and the '-0' form.
    """
    if not isinstance(target, str) or not isinstance(controller, int):
        return False
    # Reject -0 form
    if target == "-0":
        return False
    if not _BASE10_RE.match(target):
        return False
    try:
        return int(target) == controller
    except Exception:
        return False


def encode_base10(value: int) -> str:
    """Encode an integer to its decimal string representation."""
    if not isinstance(value, int):
        return _err("encode_base10 requires int")
    return str(value)


def decode_base10(target: str) -> int:
    """
    Decode a decimal string to an integer.
    Returns ERROR: string on invalid input.
    """
    if not isinstance(target, str):
        return _err(f"decode_base10 requires str, got {type(target).__name__}")
    if target == "-0":
        return _err(f"decode_base10: invalid format '{target}'")
    if not _BASE10_RE.match(target):
        return _err(f"decode_base10: invalid format '{target}'")
    try:
        return int(target)
    except Exception as e:
        return _err(f"decode_base10: {e}")
