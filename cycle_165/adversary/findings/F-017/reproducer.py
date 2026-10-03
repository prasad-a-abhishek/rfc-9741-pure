#!/usr/bin/env python3
"""F-017 reproducer: atheris FDP.ConsumeUnicodeNoSurrogates produces a string
with an embedded NUL byte, subprocess.run raises ValueError before the CLI
is even invoked.

This is HARNESS-ONLY instrumentation noise. The library itself handles NUL
bytes correctly (see analysis.md). The reproducer demonstrates that:

    1. subprocess.run() rejects argv elements containing NUL bytes (this is
       a POSIX argument-termination guard, not a library bug).
    2. The rfc9741pure library functions decode_b45, encode_b45, validate_b45
       all handle NUL bytes correctly and return structured results.

Run from the worktree root:

    python3 cycle_165/adversary/findings/F-017/reproducer.py

Expected output:
    [1] subprocess.run(...) raises ValueError("embedded null byte")
    [2] decode_b45(chr(0))  -> "ERROR:decode_b45: invalid character '\\x00'"
    [3] validate_b45('AB', b'a\\x00') -> False
    [4] encode_b45(b'a\\x00b')       -> "$BC82"
"""
import subprocess
import sys

from rfc9741pure import decode_b45, encode_b45, validate_b45

# --- Part 1: reproduce the F-017 failure mode (subprocess NUL guard) ---
TEXT = "a\x00b"
print(f"[1] Attempting subprocess.run with argv element {TEXT!r}:")
try:
    subprocess.run([sys.executable, "-c", "print('hi')", TEXT])
except ValueError as e:
    print(f"    raised ValueError: {e}  <-- F-017 noise")
except Exception as e:  # noqa: BLE001
    print(f"    raised {type(e).__name__}: {e}")

# --- Part 2: confirm the library is NUL-safe (this is what makes F-017
#     "harness-only" / "NOT a library bug") ---
print()
print("[2] Library-side NUL handling (should be clean, no exception):")
print(f"    decode_b45(chr(0))  -> {decode_b45(chr(0))!r}")
_v = validate_b45("AB", b"a\x00")
print(f"    validate_b45('AB', b'a\\x00')  -> {_v}")
_e = encode_b45(b"a\x00b")
print(f"    encode_b45(b'a\\x00b')  -> {_e!r}")

print()
print(">>> F-017 is harness-only. Library is NUL-tolerant. No remediation")
print(">>> needed in the library; future campaigns should strip NUL from")
print(">>> fuzz text in the harness before passing to subprocess.run.")
sys.exit(0)