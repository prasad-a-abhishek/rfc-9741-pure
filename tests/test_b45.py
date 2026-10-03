"""
Tests for rfc9741pure._b45 module — RFC 9285 Base45 encoding.
"""

import pytest
from rfc9741pure._b45 import validate_b45, encode_b45, decode_b45


# ── validate_b45 ─────────────────────────────────────────────────────────────

class TestValidateB45:
    def test_empty(self):
        assert validate_b45("", b"") is True

    def test_bytes_empty_string(self):
        assert validate_b45("", b"") is True

    def test_non_string_target(self):
        assert validate_b45(123, b"AB") is False

    def test_non_bytes_controller(self):
        assert validate_b45("AB", "AB") is False

    def test_invalid_alphabet_chars(self):
        """Characters outside base45 alphabet are rejected."""
        assert validate_b45("AB!!", b"ABCD") is False


# ── encode_b45 ───────────────────────────────────────────────────────────────

class TestEncodeB45:
    def test_empty(self):
        assert encode_b45(b"") == ""

    def test_non_bytes(self):
        result = encode_b45("AB")
        assert isinstance(result, str) and result.startswith("ERROR:")

    def test_rfc9285_encoding(self):
        """encode_b45 produces RFC 9285 base45 encoded output.

        [0xde, 0xad, 0xbe, 0xef] groups as pairs:
          [0xde, 0xad] -> 57005 = 35 + 6*45 + 28*2025 -> c=35(Z), d=6(6), e=28(S) -> "Z6S"
          [0xbe, 0xef] -> 48879 = 9 + 6*45 + 24*2025 -> c=9(9), d=6(6), e=24(O) -> "96O"
        Full result: "Z6S96O"
        """
        result = encode_b45(b"\xde\xad\xbe\xef")
        assert result == "Z6S96O", f"expected 'Z6S96O', got {result!r}"

    def test_ascii_encoding(self):
        """ASCII bytes round-trip correctly through base45 encode/decode."""
        for s in ["", "A", "AB", "Hello", "Hello!"]:
            data = s.encode("ascii")
            enc = encode_b45(data)
            dec = decode_b45(enc)
            assert dec == data, f"round-trip failed for {s!r}"

    def test_single_bytes(self):
        """Single bytes (including values >= 45) encode and decode correctly.

        Per RFC 9285 §4, a single byte [a] encodes as 2 chars [c,d] where
        a = c + d*45 (c = a % 45, d = a // 45).
        """
        # 0x00 = 0 -> "00"
        assert encode_b45(b"\x00") == "00"
        # 0x01 = 1 -> "10"
        assert encode_b45(b"\x01") == "10"
        # 0x0e = 14 -> "E0"
        assert encode_b45(b"\x0e") == "E0"
        # 0xff = 255 = 30 + 5*45 -> "U5" (c=30=U, d=5)
        assert encode_b45(b"\xff") == "U5"


# ── decode_b45 ────────────────────────────────────────────────────────────────

class TestDecodeB45:
    def test_empty(self):
        assert decode_b45("") == b""

    def test_non_string(self):
        result = decode_b45(123)
        assert isinstance(result, str) and result.startswith("ERROR:")

    def test_invalid_alphabet(self):
        result = decode_b45("AB@@")
        assert isinstance(result, str) and result.startswith("ERROR:")

    def test_rfc9285_decoding(self):
        """decode_b45 decodes RFC 9285 base45 strings back to bytes.

        "Z6S96O" decodes as pairs:
          "Z6S" -> value = 35 + 6*45 + 28*2025 = 57005 -> [0xde, 0xad]
          "96O" -> value = 9 + 6*45 + 24*2025 = 48879 -> [0xbe, 0xef]
        """
        result = decode_b45("Z6S96O")
        assert result == b"\xde\xad\xbe\xef", f"got {result!r}"


# ── round-trip ────────────────────────────────────────────────────────────────

class TestB45RoundTrip:
    @pytest.mark.parametrize("data", [
        b"\xde\xad\xbe\xef",
        b"Hello",
        b"\x00\x01\x02\x03",
        b"\xff\xfe\xfd",
    ])
    def test_b45_roundtrip(self, data):
        enc = encode_b45(data)
        dec = decode_b45(enc)
        assert dec == data, f"round-trip failed for {data!r}: enc={enc!r}, dec={dec!r}"
