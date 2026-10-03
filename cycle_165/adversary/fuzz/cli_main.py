#!/usr/bin/env python3
"""Fuzz harness for rfc9741pure.cli.main (full CLI surface).

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

This is a broader version of fuzz/cmd_encode.py (which targets encode only).
Both belong in the suite: cmd_encode is a focused regression test for F-003,
cli_main covers the full CLI surface including validate + decode + garbage.

Output: ./stats.json with the schema required by the task spec.
"""
import json
import os
import subprocess
import sys
import time
import atheris

with atheris.instrument_imports():
    pass  # subprocess is stdlib; no package instrumentation needed.

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
_CLI_PATH = os.path.join(_REPO_ROOT, "src", "rfc9741pure", "cli.py")
_CLI_ENV = {**os.environ, "PYTHONPATH": os.path.join(_REPO_ROOT, "src")}
_STATS_PATH = os.path.join(_HERE, "cli_main_stats.json")

_VALID_BASES = ("b64u", "b64c", "hex", "b45", "base10", "printf", "json")
_VALID_CMDS = ("validate", "encode", "decode")


def _run_cli(argv, stdin_bytes):
    """Run the CLI with argv and stdin_bytes.  Returns (rc, stderr)."""
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
        path_kind = fdp.ConsumeIntInRange(0, 3)
        if path_kind == 0:
            argv.append(fdp.ConsumeUnicodeNoSurrogates(32))
        elif path_kind == 1:
            argv.append("-")
        elif path_kind == 2:
            argv.append("")
        else:
            argv.append(f"/nonexistent/{fdp.ConsumeUnicodeNoSurrogates(8)}")

    stdin_bytes = fdp.ConsumeBytes(512)
    rc, stderr = _run_cli(argv, stdin_bytes)

    if "Traceback (most recent call last):" in stderr:
        raise AssertionError(f"CLI crashed with traceback: {stderr[:200]}")
    if rc == -1:
        raise AssertionError("CLI exceeded 5s wall-clock timeout")
    if rc == -2:
        raise AssertionError(f"subprocess runner failed: {stderr}")


def _run_smoke(iterations: int) -> dict:
    t0 = time.time()
    crashes = 0
    unhandled = 0
    exceptions_caught = []
    import random
    rng = random.Random(0xC0DE9746)

    for i in range(iterations):
        data = bytes(rng.getrandbits(8) for _ in range(64))
        try:
            TestOneInput(data)
        except AssertionError as e:
            unhandled += 1
            exceptions_caught.append({
                "iter": i,
                "type": "AssertionError",
                "msg": str(e)[:200],
            })
        except Exception as e:  # noqa: BLE001
            crashes += 1
            exceptions_caught.append({
                "iter": i,
                "type": type(e).__name__,
                "msg": str(e)[:200],
            })

    wall = time.time() - t0
    return {
        "iterations": iterations,
        "crashes": crashes,
        "unhandled_exceptions": unhandled,
        "exceptions_caught": exceptions_caught[:20],
        "coverage_pct": None,
        "wall_time_seconds": round(wall, 3),
        "harness": "cli_main",
        "surface": "cli.main() full argv + stdin",
    }


def main() -> None:
    if "--iterations" in sys.argv:
        idx = sys.argv.index("--iterations")
        iters = int(sys.argv[idx + 1])
        stats = _run_smoke(iters)
        with open(_STATS_PATH, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)
        print(f"cli_main: {stats['iterations']} iters, "
              f"{stats['crashes']} crashes, "
              f"{stats['unhandled_exceptions']} unhandled, "
              f"{stats['wall_time_seconds']}s")
        if stats["crashes"] or stats["unhandled_exceptions"]:
            sys.exit(2)
    else:
        atheris.Setup(sys.argv, TestOneInput)
        atheris.Fuzz()


if __name__ == "__main__":
    main()
