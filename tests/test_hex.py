"""
Tests for rfc9741pure._hex module.
"""

import pytest
from rfc9741pure._hex import (
    validate_hex, encode_hex, decode_hex,
    validate_hexlc, validate_hexuc,
)


# ── validate_hex ─────────────────────────────────────────────────────────────

class TestValidateHex:
    def test_basic(self):
        assert validate_hex("deadbeef", b"\xde\xad\xbe\xef") is True

    def test_mismatch(self):
        assert validate_hex("deadbeef", b"\x00\x00\x00\x00") is False

    def test_lowercase(self):
        assert validate_hex("DEADBEEF", b"\xde\xad\xbe\xef") is True

    def test_mixed_case(self):
        assert validate_hex("DeAdBeEf", b"\xde\xad\xbe\xef") is True

    def test_empty(self):
        assert validate_hex("", b"") is True

    def test_non_string_target(self):
        assert validate_hex(1234, b"\xde\xad") is False

    def test_non_bytes_controller(self):
        assert validate_hex("deadbeef", "de ad be ef") is False

    def test_with_spaces(self):
        assert validate_hex("de ad be ef", b"\xde\xad\xbe\xef") is True

    def test_with_dashes(self):
        assert validate_hex("de-ad-be-ef", b"\xde\xad\xbe\xef") is True


# ── encode_hex ────────────────────────────────────────────────────────────────

class TestEncodeHex:
    def test_basic(self):
        assert encode_hex(b"\xde\xad\xbe\xef") == "deadbeef"

    def test_empty(self):
        assert encode_hex(b"") == ""

    def test_preserves_case(self):
        assert encode_hex(b"\xab\xcd") == "abcd"

    def test_non_bytes(self):
        result = encode_hex("deadbeef")
        assert isinstance(result, str) and result.startswith("ERROR:")


# ── decode_hex ────────────────────────────────────────────────────────────────

class TestDecodeHex:
    def test_basic(self):
        assert decode_hex("deadbeef") == b"\xde\xad\xbe\xef"

    def test_uppercase(self):
        assert decode_hex("DEADBEEF") == b"\xde\xad\xbe\xef"

    def test_mixed_case(self):
        assert decode_hex("DeAdBeEf") == b"\xde\xad\xbe\xef"

    def test_empty(self):
        assert decode_hex("") == b""

    def test_with_spaces(self):
        assert decode_hex("de ad be ef") == b"\xde\xad\xbe\xef"

    def test_with_dashes(self):
        assert decode_hex("de-ad-be-ef") == b"\xde\xad\xbe\xef"

    def test_invalid_chars(self):
        result = decode_hex("deadjoke")
        assert isinstance(result, str) and result.startswith("ERROR:")

    def test_non_string(self):
        result = decode_hex(1234)
        assert isinstance(result, str) and result.startswith("ERROR:")


# ── validate_hexlc ───────────────────────────────────────────────────────────

class TestValidateHexLC:
    def test_valid_lowercase(self):
        assert validate_hexlc("deadbeef", b"\xde\xad\xbe\xef") is True

    def test_uppercase_rejected(self):
        assert validate_hexlc("DEADBEEF", b"\xde\xad\xbe\xef") is False

    def test_mixed_case_rejected(self):
        assert validate_hexlc("DeAdBeEf", b"\xde\xad\xbe\xef") is False

    def test_empty(self):
        assert validate_hexlc("", b"") is True

    def test_non_string_target(self):
        assert validate_hexlc(1234, b"\xde\xad") is False


# ── validate_hexuc ───────────────────────────────────────────────────────────

class TestValidateHexUC:
    def test_valid_uppercase(self):
        assert validate_hexuc("DEADBEEF", b"\xde\xad\xbe\xef") is True

    def test_lowercase_rejected(self):
        assert validate_hexuc("deadbeef", b"\xde\xad\xbe\xef") is False

    def test_mixed_case_rejected(self):
        assert validate_hexuc("DeAdBeEf", b"\xde\xad\xbe\xef") is False

    def test_empty(self):
        assert validate_hexuc("", b"") is True

    def test_non_string_target(self):
        assert validate_hexuc(1234, b"\xde\xad") is False


# ── round-trip ───────────────────────────────────────────────────────────────

class TestHexRoundTrip:
    @pytest.mark.parametrize("data", [
        b"", b"\x00", b"\xde\xad\xbe\xef",
        b"Hello", b"\xff\xfe\xfd\xfc",
    ])
    def test_hex_roundtrip(self, data):
        encoded = encode_hex(data)
        decoded = decode_hex(encoded)
        assert decoded == data
