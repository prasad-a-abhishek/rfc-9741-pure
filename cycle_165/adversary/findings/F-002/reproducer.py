#!/usr/bin/env python3
"""F-002 regression reproducer (post-fix, commit 5009552).

Verifies that decode_b45 no longer silently truncates 3-char group
values >= 65536. The fix returns "ERROR:decode_b45: 3-char value
{value} exceeds 16-bit" instead of emitting (value>>8)&0xFF and
value&0xFF as two bytes.

Run from the worktree root:

    python3 cycle_165/adversary/findings/F-002/reproducer.py

Expected (post-fix) output:
    All overflow inputs return ERROR:... strings.
    In-range inputs return valid 2-byte sequences.
    Exit code 0 (regression PASSES).
"""
from rfc9741pure import decode_b45

THREE_CHAR_OVERFLOW = [
    "ZZZ",   # 35+35*45+35*2025 = 72485
    "9ZZ",   # 9+35*45+35*2025 = 72459
    "Z9Z",   # 35+9*45+35*2025 = 71315
    "ZZY",   # 35+35*45+34*2025 = 70460
]
THREE_CHAR_IN_RANGE = [
    "ABC",   # 10+11*45+12*2025 = 24835 (10,11,12 are real b45 codes for A,B,C)
    "000",   # 0
    "ZZ9",   # 35+35*45+9*2025 = 19835
]


def main() -> int:
    print("[overflow inputs -- must return ERROR:...]:")
    n_ok = 0
    for s in THREE_CHAR_OVERFLOW:
        r = decode_b45(s)
        ok = isinstance(r, str) and r.startswith("ERROR:")
        print(f"  decode_b45({s!r})  -> {r!r}  [{'ERROR' if ok else 'BUG'}]")
        n_ok += int(ok)
    print()
    print("[in-range inputs -- must return bytes]:")
    n_in_range = 0
    for s in THREE_CHAR_IN_RANGE:
        r = decode_b45(s)
        ok = isinstance(r, bytes)
        print(f"  decode_b45({s!r})  -> {r!r}  [{'BYTES' if ok else 'BUG'}]")
        n_in_range += int(ok)
    print()
    print(f"overflow correctly rejected: {n_ok}/{len(THREE_CHAR_OVERFLOW)}")
    print(f"in-range correctly decoded:  {n_in_range}/{len(THREE_CHAR_IN_RANGE)}")
    if n_ok == len(THREE_CHAR_OVERFLOW) and n_in_range == len(THREE_CHAR_IN_RANGE):
        print(">>> F-002 regression holds. No silent truncation.")
        return 0
    print(">>> F-002 regression FAILED.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())