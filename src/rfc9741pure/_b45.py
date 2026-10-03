"""
Base45 (.b45) operator — RFC 9285.
Reference: https://www.rfc-editor.org/rfc/rfc9285.html

Encoding (RFC 9285 §4):
  For pairs of bytes [a,b]: n = a*256 + b; emit 3 chars [c,d,e] where
    n = c + d*45 + e*45*45  (c is least significant)
  For a single trailing byte [a]: emit 2 chars [c,d] where a = c + d*45

Decoding (RFC 9285 §4.2):
  Read value from alphabet; determine encoding length from value range.
"""

from typing import Union

Result = Union[bytes, str]

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
INV = {c: i for i, c in enumerate(ALPHABET)}


def _err(msg: str) -> str:
    return f"ERROR:{msg}"


def encode_b45(data: bytes) -> str:
    """Encode bytes to a base45 string per RFC 9285 §4."""
    if not isinstance(data, bytes):
        return _err("encode_b45 requires bytes")

    out = []
    i = 0
    n = len(data)

    # Process pairs of bytes (even-length groups)
    while i + 2 <= n:
        a, b = data[i], data[i + 1]
        # 16-bit value: a*256 + b
        value = a * 256 + b
        # Encode as 3 chars: value = c + d*45 + e*45^2
        c = value % 45
        d = (value // 45) % 45
        e = value // (45 * 45)
        out.append(ALPHABET[c])
        out.append(ALPHABET[d])
        out.append(ALPHABET[e])
        i += 2

    # Handle trailing byte if odd count
    if i < n:
        a = data[i]
        # 8-bit value: a = c + d*45
        c = a % 45
        d = a // 45
        out.append(ALPHABET[c])
        out.append(ALPHABET[d])

    return "".join(out)


def decode_b45(target: str) -> bytes:
    """Decode a base45 string to bytes per RFC 9285 §4.2."""
    if not isinstance(target, str):
        return _err(f"decode_b45 requires str, got {type(target).__name__}")
    if not target:
        return b""
    out = []
    i = 0
    L = len(target)
    while i < L:
        v0 = INV.get(target[i], -1)
        if v0 < 0:
            return _err(f"decode_b45: invalid character '{target[i]}'")
        if i + 2 <= L and i + 2 < L:
            # Might be 3-char group: check if value >= 90 (3-char indicator)
            v1 = INV.get(target[i + 1], -1)
            if v1 < 0:
                return _err(f"decode_b45: invalid character '{target[i+1]}'")
            if i + 2 < L:
                v2 = INV.get(target[i + 2], -1)
                if v2 < 0:
                    return _err(f"decode_b45: invalid character '{target[i+2]}'")
                # 3-char group: value = c + d*45 + e*45*45
                value = v0 + v1 * 45 + v2 * 45 * 45
                # F-002 fix: 3-char values MUST be < 65536 per RFC 9285 §4.2
                if value >= 65536:
                    return _err(f"decode_b45: 3-char value {value} exceeds 16-bit")
                try:
                    out.append((value >> 8) & 0xFF)  # high byte
                    out.append(value & 0xFF)          # low byte
                except ValueError:
                    return _err(f"decode_b45: invalid byte value {value}")
                i += 3
            else:
                # Only 2 chars left: must be 2-char encoding
                value = v0 + v1 * 45
                # F-001 fix: 2-char values must be < 256 (single byte)
                if value >= 256:
                    return _err(f"decode_b45: invalid value {value} from 2-char group")
                out.append(value)
                i += 2
        elif i + 1 == L:
            return _err("decode_b45: unexpected end of input")
        else:
            # 2 chars remaining
            v1 = INV.get(target[i + 1], -1)
            if v1 < 0:
                return _err(f"decode_b45: invalid character '{target[i+1]}'")
            value = v0 + v1 * 45
            out.append(value)
            i += 2
    try:
        return bytes(out)
    except ValueError:
        return _err(f"decode_b45: byte value(s) out of range in output")


def validate_b45(target: str, controller: bytes) -> bool:
    """Validate target is a base45-encoded representation of controller."""
    if not isinstance(target, str) or not isinstance(controller, bytes):
        return False
    decoded = decode_b45(target)
    if isinstance(decoded, str):  # error
        return False
    return decoded == controller
