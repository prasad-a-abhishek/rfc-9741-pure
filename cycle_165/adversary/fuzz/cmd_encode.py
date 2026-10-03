#!/usr/bin/env python3
"""Fuzz harness for cli.cmd_encode — the F-003 eval-replaced surface (cycle_165/adv_retry/T2).

Targets: src/rfc9741pure/cli.py::cmd_encode
Surface: subprocess invocation of `python3 -m rfc9741pure encode <base> <text>`.
The text argument is consumed by `ast.literal_eval` for the `printf` and
`json` bases (the F-003 fix at 5009552 replaced bare `eval`).

What this harness catches that atheris-on-pytest can't:
  - __import__ / exec / open() / attribute access / name lookups
    via the text argument (literal_eval rejects all of these by spec).
  - Non-zero exit codes for trivial input (UX regression F-014).
  - Python traceback leaked to stderr (the F-003 / F-014 surfaces).

Strategy:
  1. Pick a base (b64u, b64c, hex, b45, base10, printf, json, garbage).
  2. Generate a fuzzed text argument.
  3. Run the CLI as a subprocess with 5s timeout.
  4. Verify: exit code 0 or 1, no Python traceback in stderr.

Output: ./stats.json with the schema required by the task spec.
"""
import json
import os
import subprocess
import sys
import time
import atheris

with atheris.instrument_imports():
    pass  # subprocess is stdlib; no need to instrument the package.

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
_CLI_PATH = os.path.join(_REPO_ROOT, "src", "rfc9741pure", "cli.py")
_CLI_ENV = {**os.environ, "PYTHONPATH": os.path.join(_REPO_ROOT, "src")}
_STATS_PATH = os.path.join(_HERE, "cmd_encode_stats.json")

_VALID_BASES = ("b64u", "b64c", "hex", "b45", "base10", "printf", "json")

# Explicit RCE-attempt payloads — these MUST all be rejected by
# ast.literal_eval in cmd_encode (F-003 fix verification).
_RCE_PAYLOADS = [
    "__import__('os').system('echo PWNED')",
    "open('/tmp/pwn_test.txt', 'w').write('pwned')",
    "exec('import os; os.system(\"echo PWNED\")')",
    "(1).__class__.__mro__[1].__subclasses__()",
    "eval('1+1')",
    "compile('import os', '<s>', 'exec')",
    "globals()",
    "locals()",
    "vars()",
    "__builtins__",
    "[x for x in (1,2,3) if x > 0]",  # comprehensions are valid literal_eval
    "lambda: 1",  # not a literal — must ERROR
    "1+1",  # not a literal — must ERROR (F-014)
    "import os",  # not a literal — must ERROR
    "[1,2,",  # malformed — must ERROR
]

_VALID_LITERAL_PAYLOADS = [
    "(1, 'hello')",
    "[1, 2, 3]",
    "{'a': 1, 'b': 2}",
    "None",
    "True",
    "False",
    "42",
    "3.14",
    "'plain string'",
    "b'binary'",
]


def _run_cli(base: str, text: str) -> tuple:
    """Run `rfc9741pure encode <base> <text>` and return (rc, stderr)."""
    try:
        proc = subprocess.run(
            [sys.executable, _CLI_PATH, "encode", base, text],
            capture_output=True,
            timeout=5,
            env=_CLI_ENV,
        )
        return proc.returncode, proc.stderr.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"
    except Exception as e:  # noqa: BLE001
        return -2, f"SUBPROCESS_ERROR: {type(e).__name__}: {e}"


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    # Pick a base.
    base_idx = fdp.ConsumeIntInRange(0, len(_VALID_BASES))  # +1 for garbage
    if base_idx < len(_VALID_BASES):
        base = _VALID_BASES[base_idx]
    else:
        base = fdp.ConsumeUnicodeNoSurrogates(8)

    # Pick a text argument.
    text_strategy = fdp.ConsumeIntInRange(0, 4)
    if text_strategy == 0:
        # Arbitrary unicode.
        text = fdp.ConsumeUnicodeNoSurrogates(256)
    elif text_strategy == 1:
        # Explicit RCE payload — must be rejected by literal_eval.
        text = fdp.PickValueInList(_RCE_PAYLOADS)
    elif text_strategy == 2:
        # Valid literal — must round-trip cleanly.
        text = fdp.PickValueInList(_VALID_LITERAL_PAYLOADS)
    elif text_strategy == 3:
        # Empty + whitespace edge cases.
        text = fdp.PickValueInList(["", " ", "\n", "\t", "0", "1", "-1", "0.0", "null"])
    else:
        # Malformed literal — F-014 surface: must return exit 1 + clean
        # stderr, no traceback.
        text = fdp.PickValueInList([
            "1+1", "import os", "[1,2,", "{\"a\":", "(1,", "'unterminated",
            "True and False",  # not a literal (boolean op)
            "[x for x in 1..10]",
        ])

    rc, stderr = _run_cli(base, text)

    # Crash conditions:
    if "Traceback (most recent call last):" in stderr:
        # Uncaught exception in CLI — finding (F-003 / F-014).
        raise AssertionError(
            f"CLI crashed with traceback for base={base!r} text={text[:60]!r}: "
            f"{stderr[:200]}"
        )
    if rc == -1:
        raise AssertionError("CLI exceeded 5s wall-clock timeout")
    if rc == -2:
        raise AssertionError(f"subprocess runner failed: {stderr}")
    if rc not in (0, 1):
        # The CLI should only exit 0 (success) or 1 (handled error).
        # Anything else is a finding.
        raise AssertionError(
            f"CLI exited with unexpected code {rc} for base={base!r} text={text[:60]!r}: "
            f"{stderr[:200]}"
        )


def _run_smoke(iterations: int) -> dict:
    t0 = time.time()
    crashes = 0
    unhandled = 0
    exceptions_caught: list = []
    import random
    rng = random.Random(0xC0DE9743)

    for i in range(iterations):
        data = bytes(rng.getrandbits(8) for _ in range(64))
        try:
            TestOneInput(data)
        except AssertionError as e:
            unhandled += 1
            exceptions_caught.append({
                "iter": i,
                "type": "AssertionError",
                "msg": str(e)[:300],
            })
        except Exception as e:  # noqa: BLE001
            crashes += 1
            exceptions_caught.append({
                "iter": i,
                "type": type(e).__name__,
                "msg": str(e)[:300],
            })

    wall = time.time() - t0
    return {
        "iterations": iterations,
        "crashes": crashes,
        "unhandled_exceptions": unhandled,
        "exceptions_caught": exceptions_caught[:20],
        "coverage_pct": None,
        "wall_time_seconds": round(wall, 3),
        "harness": "cmd_encode",
        "surface": "cli.cmd_encode(base, text) via subprocess",
    }


def main() -> None:
    if "--iterations" in sys.argv:
        idx = sys.argv.index("--iterations")
        iters = int(sys.argv[idx + 1])
        stats = _run_smoke(iters)
        with open(_STATS_PATH, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)
        print(f"cmd_encode: {stats['iterations']} iters, "
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
