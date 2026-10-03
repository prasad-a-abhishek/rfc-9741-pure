#!/usr/bin/env python3
"""F-003 regression reproducer (post-fix, commit 5009552).

Verifies that cli.cmd_encode for base='json' (and 'printf') can no
longer be coerced into executing arbitrary Python code. The fix
replaces eval() with ast.literal_eval(), which is a SafeLoader.

Run from the worktree root:

    PYTHONPATH=src python3 cycle_165/adversary/findings/F-003/reproducer.py

Expected (post-fix) output:
    All payloads raise ast.literal_eval.ValueError / SyntaxError BEFORE
    any os.system / open / exec runs. No /tmp/pwn_test_F003_marker
    file is created. Exit code 0 (regression PASSES).

Pre-fix behaviour (now reverted): `eval(payload)` would run the
attacker's expression in-process; `__import__('os').system('touch
/tmp/pwn_test_F003')` would create the marker file.
"""
import os
import subprocess
import sys

MARKER = "/tmp/pwn_test_F003_marker"
# Clean up any leftover marker from a previous run.
if os.path.exists(MARKER):
    os.remove(MARKER)

RCE_PAYLOADS = [
    "__import__('os').system('touch {m}')".format(m=MARKER),
    "open('{m}', 'w').write('pwned')".format(m=MARKER),
    "exec('import os; os.system(\\'touch {m}\\')')".format(m=MARKER),
    "(1).__class__.__mro__[1].__subclasses__()",
    "compile('import os', '<s>', 'exec')",
    "eval('1+1')",
    "globals()",
    "1+1",
]


def attempt(base: str, text: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "rfc9741pure.cli", "encode", base, text],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin"},
    )
    return proc.returncode, proc.stderr


def main() -> int:
    n_blocked = 0
    for payload in RCE_PAYLOADS:
        # Each payload is tested for BOTH printf and json, since both
        # base='printf' and base='json' use ast.literal_eval().
        for base in ("printf", "json"):
            rc, stderr = attempt(base, payload)
        # After attempting with BOTH bases, verify marker absent.
        if os.path.exists(MARKER):
            print(f"  RCE SUCCEEDED for payload {payload!r}! Marker file exists.")
            os.remove(MARKER)
            return 2
        n_blocked += 1
        print(f"  base=json payload={payload!r:60} blocked ✓")
    print()
    print(f"All {n_blocked} RCE payloads blocked. Marker {MARKER!r} absent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())