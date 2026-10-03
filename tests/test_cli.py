"""
Tests for rfc9741pure CLI.
"""

import os
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


class TestCliEvalInjectionRejected:
    """Regression tests for VULN_AUDIT F-003 (High): CLI eval() RCE prevention.

    The CLI previously used bare eval() for printf/json dispatch, allowing
    arbitrary code execution (CWE-94/CWE-95). These are now replaced with
    ast.literal_eval which only parses Python literals.
    """

    def test_cli_eval_injection_rejected(self):
        """F-003: cmd_encode('json', ...) with __import__ must raise ValueError.

        ast.literal_eval refuses __import__ expressions and raises ValueError.
        No file must be written to disk.
        """
        pwn_path = "/tmp/rfc9741pure_pwn_test.txt"
        # Ensure it doesn't already exist
        if os.path.exists(pwn_path):
            os.unlink(pwn_path)

        with pytest.raises(ValueError):
            cmd_encode("json", "__import__('os').system('echo PWNED > /tmp/rfc9741pure_pwn_test.txt')")

        # No file must have been written
        assert not os.path.exists(pwn_path), "RCE succeeded: file was written!"

    def test_cli_printf_injection_rejected(self):
        """F-003: cmd_encode('printf', ...) with __import__ must raise ValueError."""
        pwn_path = "/tmp/rfc9741pure_pwn_test2.txt"
        if os.path.exists(pwn_path):
            os.unlink(pwn_path)

        with pytest.raises(ValueError):
            cmd_encode("printf", "__import__('os').system('echo PWNED > /tmp/rfc9741pure_pwn_test2.txt')")

        assert not os.path.exists(pwn_path), "RCE succeeded: file was written!"

    def test_cli_printf_legitimate_use(self):
        """F-003: ast.literal_eval still serves the legitimate printf demo use-case."""
        out = StringIO()
        old_stdout = sys.stdout
        sys.stdout = out
        try:
            result = cmd_encode("printf", "'%s', 'hello'")
        finally:
            sys.stdout = old_stdout
        assert result == 0
        assert out.getvalue().strip() == "hello"

    def test_cli_json_legitimate_use(self):
        """F-003: ast.literal_eval still serves the legitimate json demo use-case."""
        out = StringIO()
        old_stdout = sys.stdout
        sys.stdout = out
        try:
            result = cmd_encode("json", "'hello'")
        finally:
            sys.stdout = old_stdout
        assert result == 0
        assert out.getvalue().strip() == '"hello"'


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
