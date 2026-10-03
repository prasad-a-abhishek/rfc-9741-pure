"""
Tests for rfc9741pure._base10 module.
"""

import pytest
from rfc9741pure._base10 import validate_base10, encode_base10, decode_base10


# ── validate_base10 ───────────────────────────────────────────────────────────

class TestValidateBase10:
    def test_basic_positive(self):
        assert validate_base10("42", 42) is True

    def test_zero(self):
        assert validate_base10("0", 0) is True

    def test_negative(self):
        assert validate_base10("-42", -42) is True

    def test_mismatch(self):
        assert validate_base10("42", 43) is False

    def test_no_leading_zero(self):
        assert validate_base10("042", 42) is False

    def test_zero_not_minus_zero(self):
        assert validate_base10("-0", 0) is False

    def test_non_string_target(self):
        assert validate_base10(42, 42) is False

    def test_non_int_controller(self):
        assert validate_base10("42", "42") is False

    def test_large_number(self):
        assert validate_base10("123456789012345", 123456789012345) is True

    def test_rejects_float_string(self):
        assert validate_base10("3.14", 3) is False

    def test_rejects_hex_style(self):
        assert validate_base10("0x42", 42) is False


# ── encode_base10 ─────────────────────────────────────────────────────────────

class TestEncodeBase10:
    def test_positive(self):
        assert encode_base10(42) == "42"

    def test_zero(self):
        assert encode_base10(0) == "0"

    def test_negative(self):
        assert encode_base10(-42) == "-42"

    def test_large(self):
        assert encode_base10(123456789012345) == "123456789012345"

    def test_non_int(self):
        result = encode_base10("42")
        assert isinstance(result, str) and result.startswith("ERROR:")


# ── decode_base10 ────────────────────────────────────────────────────────────

class TestDecodeBase10:
    def test_positive(self):
        assert decode_base10("42") == 42

    def test_zero(self):
        assert decode_base10("0") == 0

    def test_negative(self):
        assert decode_base10("-42") == -42

    def test_large(self):
        assert decode_base10("123456789012345") == 123456789012345

    def test_invalid_format(self):
        result = decode_base10("042")
        assert isinstance(result, str) and result.startswith("ERROR:")

    def test_invalid_negative_zero(self):
        result = decode_base10("-0")
        assert isinstance(result, str) and result.startswith("ERROR:")

    def test_non_string(self):
        result = decode_base10(42)
        assert isinstance(result, str) and result.startswith("ERROR:")

    def test_float_string(self):
        result = decode_base10("3.14")
        assert isinstance(result, str) and result.startswith("ERROR:")


# ── round-trip ───────────────────────────────────────────────────────────────

class TestBase10RoundTrip:
    @pytest.mark.parametrize("value", [0, 1, 42, -1, -42, 123456789, -987654321])
    def test_base10_roundtrip(self, value):
        encoded = encode_base10(value)
        decoded = decode_base10(encoded)
        assert decoded == value
