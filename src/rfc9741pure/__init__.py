"""
rfc9741pure — Pure-Python RFC 9741 CDDL Additional Control Operators.

Implements validation and encoding functions for:
  .b64u   Base64url, no padding  (RFC 4648 §5)
  .b64c   Base64 classic, padding (RFC 4648 §4)
  .hex    Base16 / hex           (RFC 4648 §8)
  .b45    Base45                 (RFC 9285)
  .base10 Decimal integer text
  .printf Printf-style formatting
  .json   JSON → Python object

All public functions are TOTAL: they never raise on arbitrary input;
invalid inputs return structured error results.
"""

from rfc9741pure._b64 import (
    decode_b64u,
    encode_b64u,
    validate_b64u,
    decode_b64c,
    encode_b64c,
    validate_b64c,
)
from rfc9741pure._hex import (
    decode_hex,
    encode_hex,
    validate_hex,
    validate_hexlc,
    validate_hexuc,
)
from rfc9741pure._b45 import (
    decode_b45,
    encode_b45,
    validate_b45,
)
from rfc9741pure._base10 import (
    decode_base10,
    encode_base10,
    validate_base10,
)
from rfc9741pure._printf import (
    decode_printf,
    format_printf,
    validate_printf,
)
from rfc9741pure._json import (
    decode_json,
    encode_json,
    validate_json,
)

__all__ = [
    # b64u
    "decode_b64u",
    "encode_b64u",
    "validate_b64u",
    # b64c
    "decode_b64c",
    "encode_b64c",
    "validate_b64c",
    # hex
    "decode_hex",
    "encode_hex",
    "validate_hex",
    "validate_hexlc",
    "validate_hexuc",
    # b45
    "decode_b45",
    "encode_b45",
    "validate_b45",
    # base10
    "decode_base10",
    "encode_base10",
    "validate_base10",
    # printf
    "decode_printf",
    "format_printf",
    "validate_printf",
    # json
    "decode_json",
    "encode_json",
    "validate_json",
]

__version__ = "0.1.0"
