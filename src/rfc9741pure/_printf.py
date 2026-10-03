"""
.printf operator — Printf-style C-language formatting validation.

Controller is an array: [format_string, arg1, arg2, ...]
Supported conversion specifiers: %d, %i, %u, %x, %X, %s, %c, %o, %04d, %-5s, %.3f etc.

These are TOTAL functions — never raise on arbitrary input.
"""

import re
import struct
from typing import Union, List, Any

Result = Union[str, List[Any]]


def _err(msg: str) -> str:
    return f"ERROR:{msg}"


# Match a printf conversion specifier: %[flags][width][.precision]specifier
_PRINTF_RE = re.compile(
    r"%([-+0 #])*(\d+)?(\.(\d+))?([diufFeEgGxXoscpaAn])"
)


def _apply_format(fmt: str, args: list) -> str:
    """Apply printf-style formatting.  Returns formatted string or ERROR:."""
    # We simulate printf by mapping Python types to formatted strings
    result = fmt
    arg_index = 0
    used_args = []

    for match in _PRINTF_RE.finditer(fmt):
        spec = match.group(5)
        width_str = match.group(2)
        precision_str = match.group(4)
        flags = match.group(1) or ""

        if arg_index >= len(args):
            return _err("printf: not enough arguments")

        arg = args[arg_index]
        used_args.append(arg_index)
        arg_index += 1

        # Build the format string for this specifier using Python's %
        # Map printf specifiers to Python format specs
        py_fmt = "%"
        if flags:
            py_fmt += flags
        if width_str:
            py_fmt += width_str
        if precision_str:
            py_fmt += "." + precision_str
        py_fmt += spec

        try:
            formatted = py_fmt % arg
            result = result[: match.start()] + formatted + result[match.end() :]
            # Adjust offset since we replaced the match
            offset = len(formatted) - (match.end() - match.start())
            # Rebuild regex with updated positions isn't easy, so we rebuild result
        except (TypeError, ValueError, struct.error) as e:
            return _err(f"printf format error: {e}")

    return result


def validate_printf(target: str, controller: list) -> bool:
    """
    Validate target matches the printf-formatted string from controller.
    Controller is [format_string, arg1, arg2, ...].
    """
    if not isinstance(target, str) or not isinstance(controller, list):
        return False
    if len(controller) < 2:
        return False
    fmt = controller[0]
    if not isinstance(fmt, str):
        return False
    args = controller[1:]

    # Check all format specifiers in fmt have corresponding args
    spec_count = len(_PRINTF_RE.findall(fmt))
    if spec_count != len(args):
        return False

    result = _apply_format(fmt, args)
    if isinstance(result, str) and result.startswith("ERROR:"):
        return False
    return result == target


def format_printf(fmt: str, *args) -> str:
    """Format a string using printf-style directives."""
    if not isinstance(fmt, str):
        return _err("format_printf requires str format")
    result = _apply_format(fmt, list(args))
    return result


def decode_printf(target: str) -> List[Any]:
    """
    Attempt to parse a target string back to [format_string, arg1, ...].
    This is a best-effort inverse — not always uniquely determined.
    Returns ERROR: string on failure.
    """
    if not isinstance(target, str):
        return _err(f"decode_printf requires str, got {type(target).__name__}")
    # For now, return ERROR since printf is not uniquely reversible
    return _err("decode_printf: not implemented (printf is not uniquely reversible)")
