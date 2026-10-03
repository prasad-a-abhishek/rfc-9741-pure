"""
.json operator — JSON text to Python object conversion.

These are TOTAL functions — never raise on arbitrary input.
"""

import json
from typing import Union, Any

Result = Union[Any, str]


def _err(msg: str) -> str:
    return f"ERROR:{msg}"


def validate_json(target: str, controller: Any) -> bool:
    """Validate target is a JSON serialization of controller."""
    if not isinstance(target, str):
        return False
    try:
        decoded = json.loads(target)
        return decoded == controller
    except Exception:
        return False


def encode_json(obj: Any) -> str:
    """Serialize a Python object to JSON string."""
    try:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    except Exception as e:
        return _err(f"encode_json: {e}")


def decode_json(target: str) -> Any:
    """
    Parse a JSON string to a Python object.
    Returns ERROR: string on failure.
    """
    if not isinstance(target, str):
        return _err(f"decode_json requires str, got {type(target).__name__}")
    try:
        return json.loads(target)
    except Exception as e:
        return _err(f"decode_json: {e}")
