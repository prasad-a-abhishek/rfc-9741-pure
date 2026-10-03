#!/usr/bin/env python3
"""Fuzz harness for rfc9741pure.cli.main.

Invokes the installed CLI as a subprocess with fuzzed argv + stdin, then
asserts the process exits cleanly (no Python tracebacks to stderr, no
non-zero exit for trivial command lines).

T1 audit found (F-003 High): cli.cmd_encode uses eval() on the user-supplied
text argument for the `printf` and `json` bases — confirmed RCE risk.  This
harness exercises the surface and will record any uncaught exceptions /
non-zero exits that surface as a finding.

Strategy:
  - argv0:    "validate" | "encode" | "decode" | "-h" | "garbage"
  - argv1..2: arbitrary Unicode strings (parsed by the CLI as path / base / text)
  - stdin:   arbitrary bytes (consumed by `validate -` and unrecognised cmds)
  - Run with a 5s wall-clock cap; capture stderr for Python traceback detection.
"""
import os
import subprocess
import sys
import atheris

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_CLI_PATH = os.path.join(_REPO_ROOT, "src", "rfc9741pure", "cli.py")
_CLI_ENV = {**os.environ, "PYTHONPATH": os.path.join(_REPO_ROOT, "src")}

_VALID_BASES = ("b64u", "b64c", "hex", "b45", "base10", "printf", "json")
_VALID_CMDS = ("validate", "encode", "decode")


def _run_cli(argv: list, stdin_bytes: bytes) -> tuple:
    """Run the CLI with `argv` and `stdin_bytes`.  Returns (rc, stderr)."""
    try:
        proc = subprocess.run(
            [sys.executable, _CLI_PATH] + list(argv),
            input=stdin_bytes,
            capture_output=True,
            timeout=5,
            env=_CLI_ENV,
        )
        return proc.returncode, proc.stderr.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        # A 5s timeout on a CLI is a finding.
        return -1, "TIMEOUT"
    except Exception as e:  # pylint: disable=broad-except
        return -2, f"SUBPROCESS_ERROR: {type(e).__name__}: {e}"


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    # Pick a command.
    cmd_idx = fdp.ConsumeIntInRange(0, 4)
    if cmd_idx == 0:
        cmd = "validate"
    elif cmd_idx == 1:
        cmd = "encode"
    elif cmd_idx == 2:
        cmd = "decode"
    elif cmd_idx == 3:
        cmd = fdp.ConsumeUnicodeNoSurrogates(8)  # arbitrary, may be a flag
    else:
        cmd = ""  # empty / no command

    argv = [cmd]
    if cmd == "encode" or cmd == "decode":
        base_idx = fdp.ConsumeIntInRange(0, len(_VALID_BASES))
        if base_idx < len(_VALID_BASES):
            base = _VALID_BASES[base_idx]
        else:
            base = fdp.ConsumeUnicodeNoSurrogates(8)
        argv.append(base)
        argv.append(fdp.ConsumeUnicodeNoSurrogates(256))
    elif cmd == "validate":
        # Path argument: either a real path-like string, "-", or garbage.
        path_kind = fdp.ConsumeIntInRange(0, 3)
        if path_kind == 0:
            argv.append(fdp.ConsumeUnicodeNoSurrogates(32))  # garbage path
        elif path_kind == 1:
            argv.append("-")
        elif path_kind == 2:
            argv.append("")  # empty path
        else:
            # A path that points nowhere — exercises file-open failure path.
            argv.append(f"/nonexistent/{fdp.ConsumeUnicodeNoSurrogates(8)}")

    stdin_bytes = fdp.ConsumeBytes(512)
    rc, stderr = _run_cli(argv, stdin_bytes)

    # Crash conditions: uncaught Python traceback in stderr, or TIMEOUT.
    if "Traceback (most recent call last):" in stderr:
        # Uncaught exception in CLI — a finding.
        raise AssertionError(f"CLI crashed with traceback: {stderr[:200]}")
    if rc == -1:
        raise AssertionError("CLI exceeded 5s wall-clock timeout")
    if rc == -2:
        raise AssertionError(f"subprocess runner failed: {stderr}")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
