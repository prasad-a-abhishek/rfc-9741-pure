"""
Tests for rfc9741pure._json module.
"""

import pytest
from rfc9741pure._json import validate_json, encode_json, decode_json


# ── validate_json ─────────────────────────────────────────────────────────────

class TestValidateJson:
    def test_basic(self):
        assert validate_json('{"a":1}', {"a": 1}) is True

    def test_mismatch(self):
        assert validate_json('{"a":1}', {"a": 2}) is False

    def test_complex(self):
        obj = {"name": "Alice", "age": 30, "active": True, "scores": [1, 2, 3]}
        encoded = encode_json(obj)
        assert validate_json(encoded, obj) is True

    def test_non_string_target(self):
        assert validate_json({"a": 1}, {"a": 1}) is False

    def test_invalid_json_string(self):
        assert validate_json("{invalid}", {"a": 1}) is False

    def test_array(self):
        assert validate_json("[1,2,3]", [1, 2, 3]) is True

    def test_nested(self):
        obj = {"data": {"nested": True}}
        encoded = encode_json(obj)
        assert validate_json(encoded, obj) is True

    def test_whitespace_in_target_not_in_controller(self):
        """Whitespace differences in JSON text do not affect the parsed value."""
        # json.loads normalizes whitespace; both parse to the same Python object
        assert validate_json('{"a":1}', {"a": 1}) is True
        assert validate_json('{"a": 1}', {"a": 1}) is True  # extra space normalized by json.loads


# ── encode_json ───────────────────────────────────────────────────────────────

class TestEncodeJson:
    def test_object(self):
        result = encode_json({"a": 1})
        assert result == '{"a":1}'

    def test_array(self):
        result = encode_json([1, 2, 3])
        assert result == '[1,2,3]'

    def test_string(self):
        result = encode_json("hello")
        assert result == '"hello"'

    def test_number(self):
        result = encode_json(42)
        assert result == "42"

    def test_bool(self):
        assert encode_json(True) == "true"
        assert encode_json(False) == "false"

    def test_null(self):
        assert encode_json(None) == "null"

    def test_unicode(self):
        result = encode_json({"name": "日本語"})
        assert "日本語" in result


# ── decode_json ────────────────────────────────────────────────────────────────

class TestDecodeJson:
    def test_object(self):
        assert decode_json('{"a":1}') == {"a": 1}

    def test_array(self):
        assert decode_json('[1,2,3]') == [1, 2, 3]

    def test_string(self):
        assert decode_json('"hello"') == "hello"

    def test_number(self):
        assert decode_json("42") == 42

    def test_bool_true(self):
        assert decode_json("true") is True

    def test_bool_false(self):
        assert decode_json("false") is False

    def test_null(self):
        assert decode_json("null") is None

    def test_invalid(self):
        result = decode_json("{invalid")
        assert isinstance(result, str) and result.startswith("ERROR:")

    def test_non_string(self):
        result = decode_json(42)
        assert isinstance(result, str) and result.startswith("ERROR:")


# ── round-trip ───────────────────────────────────────────────────────────────

class TestJsonRoundTrip:
    @pytest.mark.parametrize("obj", [
        {"a": 1},
        [1, 2, 3],
        "hello",
        42,
        True,
        False,
        None,
        {"nested": {"deep": True}, "list": [1, {"b": 2}]},
    ])
    def test_json_roundtrip(self, obj):
        encoded = encode_json(obj)
        decoded = decode_json(encoded)
        assert decoded == obj
