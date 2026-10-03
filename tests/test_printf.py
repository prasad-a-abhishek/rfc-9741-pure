"""
Tests for rfc9741pure._printf module.
"""

import pytest
from rfc9741pure._printf import validate_printf, format_printf, decode_printf


# ── validate_printf ───────────────────────────────────────────────────────────

class TestValidatePrintf:
    def test_basic_hex(self):
        assert validate_printf("0x0013", ["0x%04x", 19]) is True

    def test_hex_mismatch(self):
        assert validate_printf("0x0013", ["0x%04x", 20]) is False

    def test_decimal(self):
        assert validate_printf("42", ["%d", 42]) is True

    def test_decimal_mismatch(self):
        assert validate_printf("42", ["%d", 43]) is False

    def test_string(self):
        assert validate_printf("hello", ["%s", "hello"]) is True

    def test_string_mismatch(self):
        assert validate_printf("hello", ["%s", "world"]) is False

    def test_width_decimal(self):
        assert validate_printf("   42", ["%5d", 42]) is True

    def test_zero_pad_hex(self):
        assert validate_printf("00000013", ["%08x", 19]) is True

    def test_negative_decimal(self):
        assert validate_printf("-42", ["%d", -42]) is True

    def test_non_list_controller(self):
        assert validate_printf("42", "42") is False

    def test_non_string_format(self):
        assert validate_printf("42", [42, 42]) is False

    def test_too_few_args(self):
        assert validate_printf("42", ["%d %d", 42]) is False

    def test_too_many_args(self):
        assert validate_printf("42", ["%d", 42, 43]) is False

    def test_char_format(self):
        assert validate_printf("A", ["%c", 65]) is True

    def test_non_string_target(self):
        assert validate_printf(42, ["%d", 42]) is False


# ── format_printf ─────────────────────────────────────────────────────────────

class TestFormatPrintf:
    def test_hex(self):
        assert format_printf("%04x", 19) == "0013"

    def test_decimal(self):
        assert format_printf("%d", 42) == "42"

    def test_string(self):
        assert format_printf("%s", "hello") == "hello"

    def test_negative(self):
        assert format_printf("%d", -42) == "-42"

    def test_zero_pad(self):
        assert format_printf("%08d", 42) == "00000042"

    def test_non_string_format(self):
        result = format_printf(42, 19)
        assert isinstance(result, str) and result.startswith("ERROR:")


# ── decode_printf ─────────────────────────────────────────────────────────────

class TestDecodePrintf:
    def test_returns_error(self):
        result = decode_printf("0x0013")
        assert isinstance(result, str) and result.startswith("ERROR:")

    def test_non_string(self):
        result = decode_printf(42)
        assert isinstance(result, str) and result.startswith("ERROR:")
