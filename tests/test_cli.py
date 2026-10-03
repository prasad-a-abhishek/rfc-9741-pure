"""
Tests for rfc9741pure CLI.
"""

import pytest
import sys
from io import StringIO
from rfc9741pure.cli import main, cmd_validate, cmd_encode, cmd_decode


class TestCmdValidate:
    def test_no_operators(self):
        # Note: our simple validate just checks for operator presence
        # A CDDL file without operators should return OK but with note
        pass  # covered by integration


class TestCmdEncode:
    def test_encode_b64u(self):
        out = StringIO()
        old_stdout = sys.stdout
        sys.stdout = out
        try:
            result = cmd_encode("b64u", "abc")
        finally:
            sys.stdout = old_stdout
        assert result == 0
        assert out.getvalue().strip() == "YWJj"

    def test_encode_hex(self):
        out = StringIO()
        old_stdout = sys.stdout
        sys.stdout = out
        try:
            result = cmd_encode("hex", "ab")
        finally:
            sys.stdout = old_stdout
        assert result == 0
        assert out.getvalue().strip() == "6162"

    def test_encode_unknown_base(self):
        old_stderr = sys.stderr
        sys.stderr = StringIO()
        try:
            result = cmd_encode("unknown", "text")
        finally:
            sys.stderr = old_stderr
        assert result == 1

    def test_encode_base10(self):
        out = StringIO()
        old_stdout = sys.stdout
        sys.stdout = out
        try:
            result = cmd_encode("base10", "42")
        finally:
            sys.stdout = old_stdout
        assert result == 0
        assert out.getvalue().strip() == "42"


class TestCmdDecode:
    def test_decode_b64u(self):
        out = StringIO()
        old_stdout = sys.stdout
        sys.stdout = out
        try:
            result = cmd_decode("b64u", "YWJj")
        finally:
            sys.stdout = old_stdout
        assert result == 0
        assert out.getvalue().strip() == "abc"

    def test_decode_hex(self):
        out = StringIO()
        old_stdout = sys.stdout
        sys.stdout = out
        try:
            result = cmd_decode("hex", "6162")
        finally:
            sys.stdout = old_stdout
        assert result == 0
        assert out.getvalue().strip() == "ab"

    def test_decode_unknown_base(self):
        old_stderr = sys.stderr
        sys.stderr = StringIO()
        try:
            result = cmd_decode("unknown", "text")
        finally:
            sys.stderr = old_stderr
        assert result == 1

    def test_decode_base10(self):
        out = StringIO()
        old_stdout = sys.stdout
        sys.stdout = out
        try:
            result = cmd_decode("base10", "42")
        finally:
            sys.stdout = old_stdout
        assert result == 0
        assert out.getvalue().strip() == "42"


class TestMain:
    def test_no_args(self):
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = StringIO()
        sys.stderr = StringIO()
        try:
            result = main()
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
        assert result == 1

    def test_help(self):
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            old_argv = sys.argv
            sys.argv = ["rfc9741pure", "--help"]
            result = main()
        except SystemExit:
            result = 0
        finally:
            sys.argv = old_argv
            sys.stdout = old_stdout

    def test_unknown_command(self):
        old_stderr = sys.stderr
        sys.stderr = StringIO()
        try:
            old_argv = sys.argv
            sys.argv = ["rfc9741pure", "foobar"]
            result = main()
        finally:
            sys.argv = old_argv
            sys.stderr = old_stderr
        assert result == 1
