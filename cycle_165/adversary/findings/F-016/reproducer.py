#!/usr/bin/env python3
"""F-016 reproducer: cmd_encode base10 '<s>' uncaught ValueError.

Run from the worktree root:

    PYTHONPATH=src python3 cycle_165/adversary/findings/F-016/reproducer.py

Expected (buggy) behaviour: CLI prints a raw Python traceback to stderr and
exits 1. The library function decode_base10 is robust (returns
"ERROR:..." for invalid input) but cmd_encode skips it and calls
int(t) directly inside its dispatch lambda.

Other F-016 inputs (same unhandled-exception site, base='base10'):
    ''           — int('') raises "invalid literal for int() with base 10: ''"
    '\\n'         — int('\\n') raises "invalid literal for int() with base 10: '\\n'"
    'abc'        — int('abc') raises "invalid literal for int() with base 10: 'abc'"
    '1.5'        — int('1.5') raises (no implicit truncation; preserves user surprise)
    "{'a': 1}"   — int(dict) raises
    "<unicode BMP noise>" — int(<non-numeric unicode>) raises

All are reachable from the same `int(t)` call in cli.py:56.
"""
import subprocess
import sys

# Minimised payload: a single ASCII space character is enough to make
# int(' ') raise and leak the traceback.
TEXT = " "
EXTRA = [
    "",
    "\n",
    "abc",
    "1.5",
    "{'a': 1}",
]

def run_once(text: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "rfc9741pure.cli", "encode", "base10", text],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin"},
    )
    return proc.returncode, proc.stderr


def main() -> int:
    rc, stderr = run_once(TEXT)
    print(f"[primary payload={TEXT!r}] exit={rc}, stderr_len={len(stderr)}")
    print(f"--- stderr ---\n{stderr}--- end ---")

    if "Traceback (most recent call last):" in stderr:
        print(">>> F-016 REPRODUCED on primary payload")
    else:
        print(">>> F-016 NOT REPRODUCED on primary payload")
        return 2

    print()
    print("Re-running on a few other F-016 inputs (all should leak):")
    n_leaked = 0
    for t in EXTRA:
        rc, stderr = run_once(t)
        leaked = "Traceback (most recent call last):" in stderr
        n_leaked += int(leaked)
        print(f"  text={t!r:18} exit={rc} leaked={leaked}")
    print(f"{n_leaked}/{len(EXTRA)} secondary payloads also leak.")
    return 0 if n_leaked >= 1 else 3


if __name__ == "__main__":
    sys.exit(main())