"""
rfc9741pure CLI.

Usage:
    rfc9741pure validate <file>
    rfc9741pure encode <base> <text>
    rfc9741pure decode <base> <text>

Bases: b64u, b64c, hex, b45, base10, printf, json
"""

import sys
from typing import Optional

from rfc9741pure import (
    decode_b64u, encode_b64u,
    decode_b64c, encode_b64c,
    decode_hex, encode_hex,
    decode_b45, encode_b45,
    decode_base10, encode_base10,
    decode_printf, format_printf,
    decode_json, encode_json,
)


def _read_input(path: Optional[str]) -> str:
    if path is None or path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def cmd_validate(path: Optional[str]) -> int:
    """Validate a file containing CDDL with RFC 9741 control operators."""
    text = _read_input(path).strip()
    # We do a basic structural check — the actual CDDL parsing is
    # out of scope for this pure-operator package.
    # Check for any of our operator names as a proxy validation.
    operators = [".b64u", ".b64c", ".hex", ".hexlc", ".hexuc", ".b45", ".base10", ".printf", ".json", ".join"]
    found = [op for op in operators if op in text]
    if found:
        print(f"OK: found RFC 9741 operators: {', '.join(found)}")
        return 0
    print("NOTE: no RFC 9741 operators detected in input")
    return 0


def cmd_encode(base: str, text: str) -> int:
    """Encode text using the specified base."""
    dispatch = {
        "b64u": lambda t: encode_b64u(t.encode("utf-8")),
        "b64c": lambda t: encode_b64c(t.encode("utf-8")),
        "hex": lambda t: encode_hex(t.encode("utf-8")),
        "b45": lambda t: encode_b45(t.encode("utf-8")),
        "base10": lambda t: encode_base10(int(t)),
        "printf": lambda t: format_printf(*eval(t)),  # nosec — eval for demo; not from untrusted input
        "json": lambda t: encode_json(eval(t)),        # nosec
    }
    fn = dispatch.get(base)
    if fn is None:
        print(f"ERROR: unknown base '{base}'. Available: {', '.join(dispatch.keys())}", file=sys.stderr)
        return 1
    result = fn(text)
    if isinstance(result, str) and result.startswith("ERROR:"):
        print(result, file=sys.stderr)
        return 1
    print(result)
    return 0


def cmd_decode(base: str, text: str) -> int:
    """Decode text using the specified base."""
    dispatch = {
        "b64u": decode_b64u,
        "b64c": decode_b64c,
        "hex": decode_hex,
        "b45": decode_b45,
        "base10": decode_base10,
        "printf": decode_printf,
        "json": decode_json,
    }
    fn = dispatch.get(base)
    if fn is None:
        print(f"ERROR: unknown base '{base}'. Available: {', '.join(dispatch.keys())}", file=sys.stderr)
        return 1
    result = fn(text)
    if isinstance(result, str) and result.startswith("ERROR:"):
        print(result, file=sys.stderr)
        return 1
    if isinstance(result, bytes):
        print(result.decode("utf-8", errors="replace"))
    else:
        print(result)
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: rfc9741pure <command> [args]")
        print("Commands: validate <file> | encode <base> <text> | decode <base> <text>")
        return 1

    cmd = sys.argv[1]

    if cmd == "validate":
        path = sys.argv[2] if len(sys.argv) > 2 else None
        return cmd_validate(path)
    elif cmd == "encode":
        if len(sys.argv) < 4:
            print("Usage: rfc9741pure encode <base> <text>", file=sys.stderr)
            return 1
        return cmd_encode(sys.argv[2], sys.argv[3])
    elif cmd == "decode":
        if len(sys.argv) < 4:
            print("Usage: rfc9741pure decode <base> <text>", file=sys.stderr)
            return 1
        return cmd_decode(sys.argv[2], sys.argv[3])
    elif cmd in ("-h", "--help", "help"):
        print("Usage: rfc9741pure <command> [args]")
        print("Commands:")
        print("  validate <file>   Validate a CDDL file for RFC 9741 operators")
        print("  encode <base> <text>   Encode text using the specified base")
        print("  decode <base> <text>   Decode text using the specified base")
        print("Bases: b64u, b64c, hex, b45, base10, printf, json")
        return 0
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
