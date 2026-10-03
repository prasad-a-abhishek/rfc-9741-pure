#!/usr/bin/env python3
"""F-014 reproducer: cmd_encode json '<s>' uncaught ValueError.

Run from the worktree root (where src/rfc9741pure/cli.py lives):

    PYTHONPATH=src python3 cycle_165/adversary/findings/F-014/reproducer.py

Expected (buggy) behaviour: CLI prints a raw Python traceback to stderr and
exits with code 1 (NOT a clean "ERROR:..." stderr line as the rest of the
CLI does for handled errors).

Other F-014 inputs that reproduce on the SAME unhandled-exception site:
    PYTHONPATH=src python3 -m rfc9741pure.cli encode printf 'import os'
    PYTHONPATH=src python3 -m rfc9741pure.cli encode printf '[1,2,'
    PYTHONPATH=src python3 -m rfc9741pure.cli encode json   '(1,'
    PYTHONPATH=src python3 -m rfc9741pure.cli encode json   "{'a':"
    PYTHONPATH=src python3 -m rfc9741pure.cli encode json   "'unterminated"
    PYTHONPATH=src python3 -m rfc9741pure.cli encode json   "True and False"
    PYTHONPATH=src python3 -m rfc9741pure.cli encode json   'globals()'
    PYTHONPATH=src python3 -m rfc9741pure.cli encode printf '[x for x in 1..10]'
"""
import subprocess
import sys

# The 3-character text "1+1" is the F-014 minimised payload for the json base.
TEXT = "1+1"
BASE = "json"

proc = subprocess.run(
    [sys.executable, "-m", "rfc9741pure.cli", "encode", BASE, TEXT],
    capture_output=True,
    text=True,
    env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin"},
)
print(f"--- exit code: {proc.returncode} ---")
print(f"--- stdout (len={len(proc.stdout)}) ---")
print(repr(proc.stdout))
print(f"--- stderr (len={len(proc.stderr)}) ---")
print(proc.stderr)

# Failure indicator: the substring "Traceback (most recent call last):" appears
# in stderr. A correctly-handled cmd_encode error would print "ERROR:..." and
# exit 1 WITHOUT a traceback.
if "Traceback (most recent call last):" in proc.stderr:
    print(">>> F-014 REPRODUCED: CLI leaked Python traceback to stderr")
    sys.exit(0)
print(">>> F-014 NOT REPRODUCED: CLI produced clean ERROR stderr")
sys.exit(2)