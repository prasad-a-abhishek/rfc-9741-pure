"""
Tests for rfc9741pure._b64 module.

RFC 4648 §5 base64url (no padding) test vectors:
  ""          -> ""
  "f"         -> "Yg"
  "fo"        -> "Zm8"
  "foo"       -> "Zm9v"
  "foob"      -> "Zm9vYg"
  "fooba"     -> "Zm9vYmE"
  "foobar"    -> "Zm9vYmFy"

Classic base64 (with padding):
  "f"         -> "Zg=="
  "fo"        -> "Zm8="
  "foo"       -> "Zm9v"
  "foob"      -> "Zm9vYg=="
  "fooba"     -> "Zm9vYmE="
  "foobar"    -> "Zm9vYmFy"
"""

import pytest
from rfc9741pure._b64 import (
    validate_b64u, encode_b64u, decode_b64u,
    validate_b64c, encode_b64c, decode_b64c,
)


# ── validate_b64u ─────────────────────────────────────────────────────────────

class TestValidateB64U:
    @pytest.mark.parametrize("target,controller,expected", [
        ("", b"", True),
        ("Zg", b"f", True),         # RFC 4648 §5
        ("Zm8", b"fo", True),
        ("Zm9v", b"foo", True),
        ("Zm9vYg", b"foob", True),
        ("Zm9vYmE", b"fooba", True),
        ("Zm9vYmFy", b"foobar", True),
        # Mismatches
        ("Zg", b"o", False),
        ("Zm8", b"fo", True),  # correct
        ("Zm8", b"xx", False),
        ("", b"x", False),
    ])
    def test_valid_vectors(self, target, controller, expected):
        assert validate_b64u(target, controller) == expected

    def test_invalid_chars_rejected(self):
        """Non-base64url characters are rejected."""
        assert validate_b64u("Zg!!!", b"f") is False

    def test_wrong_padding_rejected(self):
        """Correct padding is required."""
        assert validate_b64u("Zg==", b"f") is False
        assert validate_b64u("Zm9v", b"f") is False

    def test_non_string_target(self):
        assert validate_b64u(12345, b"abc") is False

    def test_non_bytes_controller(self):
        assert validate_b64u("YWJj", "abc") is False

    def test_unicode_rejected(self):
        assert validate_b64u("Y\xf0Jj", b"abc") is False


# ── encode_b64u ────────────────────────────────────────────────────────────────

class TestEncodeB64U:
    def test_empty(self):
        assert encode_b64u(b"") == ""

    def test_f(self):
        assert encode_b64u(b"f") == "Zg"

    def test_foo(self):
        assert encode_b64u(b"foo") == "Zm9v"

    def test_foobar(self):
        assert encode_b64u(b"foobar") == "Zm9vYmFy"

    def test_no_padding(self):
        """base64url encoding has no padding."""
        assert "=" not in encode_b64u(b"f")
        assert "=" not in encode_b64u(b"fo")
        assert "=" not in encode_b64u(b"foo")

    def test_non_bytes(self):
        result = encode_b64u("abc")
        assert isinstance(result, str) and result.startswith("ERROR:")


# ── decode_b64u ───────────────────────────────────────────────────────────────

class TestDecodeB64U:
    @pytest.mark.parametrize("target,expected", [
        ("", b""),
        ("Zg", b"f"),
        ("Zm8", b"fo"),
        ("Zm9v", b"foo"),
        ("Zm9vYmFy", b"foobar"),
    ])
    def test_valid_roundtrip(self, target, expected):
        assert decode_b64u(target) == expected

    def test_invalid_chars(self):
        result = decode_b64u("Zg!!!")
        assert isinstance(result, str) and result.startswith("ERROR:")

    def test_wrong_padding(self):
        result = decode_b64u("Zg==")
        assert isinstance(result, str) and result.startswith("ERROR:")

    def test_non_string(self):
        result = decode_b64u(12345)
        assert isinstance(result, str) and result.startswith("ERROR:")


# ── validate_b64c ─────────────────────────────────────────────────────────────

class TestValidateB64C:
    @pytest.mark.parametrize("target,controller,expected", [
        ("", b"", True),
        ("Zg==", b"f", True),
        ("Zm8=", b"fo", True),
        ("Zm9v", b"foo", True),
        ("Zm9vYg==", b"foob", True),
        ("Zm9vYmE=", b"fooba", True),
        ("Zm9vYmFy", b"foobar", True),
        ("Zg==", b"o", False),
        ("", b"x", False),
    ])
    def test_valid_vectors(self, target, controller, expected):
        assert validate_b64c(target, controller) == expected

    def test_non_string_target(self):
        assert validate_b64c(12345, b"abc") is False

    def test_non_bytes_controller(self):
        assert validate_b64c("YWJj", "abc") is False


# ── encode_b64c ────────────────────────────────────────────────────────────────

class TestEncodeB64C:
    def test_empty(self):
        assert encode_b64c(b"") == ""

    def test_f(self):
        assert encode_b64c(b"f") == "Zg=="

    def test_foo(self):
        assert encode_b64c(b"foo") == "Zm9v"

    def test_has_padding(self):
        """Classic base64 has padding for non-3-byte groups."""
        assert "=" in encode_b64c(b"f")
        assert "=" in encode_b64c(b"fo")
        assert "=" not in encode_b64c(b"foo")

    def test_non_bytes(self):
        result = encode_b64c("abc")
        assert isinstance(result, str) and result.startswith("ERROR:")


# ── decode_b64c ───────────────────────────────────────────────────────────────

class TestDecodeB64C:
    @pytest.mark.parametrize("target,expected", [
        ("", b""),
        ("Zg==", b"f"),
        ("Zm8=", b"fo"),
        ("Zm9v", b"foo"),
        ("Zm9vYmFy", b"foobar"),
    ])
    def test_valid_roundtrip(self, target, expected):
        assert decode_b64c(target) == expected

    def test_invalid_chars(self):
        result = decode_b64c("Zg!!")
        assert isinstance(result, str) and result.startswith("ERROR:")

    def test_non_string(self):
        result = decode_b64c(12345)
        assert isinstance(result, str) and result.startswith("ERROR:")


# ── round-trip ─────────────────────────────────────────────────────────────────

class TestB64RoundTrip:
    @pytest.mark.parametrize("data", [
        b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar",
        b"Hello, World!", b"\x00\x01\x02", b"\xff\xfe\xfd",
    ])
    def test_b64u_roundtrip(self, data):
        encoded = encode_b64u(data)
        decoded = decode_b64u(encoded)
        assert decoded == data

    @pytest.mark.parametrize("data", [
        b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar",
        b"Hello, World!", b"\x00\x01\x02", b"\xff\xfe\xfd",
    ])
    def test_b64c_roundtrip(self, data):
        encoded = encode_b64c(data)
        decoded = decode_b64c(encoded)
        assert decoded == data
