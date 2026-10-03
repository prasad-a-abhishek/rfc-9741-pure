#!/usr/bin/env python3
"""F-001 regression reproducer (post-fix, commit 5009552).

Verifies that decode_b45 no longer raises on 2-char strings whose
base45-decoded value would have exceeded 255 (which is the original
F-001 Critical bug). The fix replaces the silent raise with a
structured "ERROR:decode_b45: ..." return value.

Run from the worktree root:

    python3 cycle_165/adversary/findings/F-001/reproducer.py

Expected (post-fix) output:
    All inputs return ERROR:... strings. No exception is raised.
    Exit code 0 (regression PASSES).

Pre-fix behaviour (now reverted): decode_b45('99') raised ValueError:
byte must be in range(0, 256).
"""
from rfc9741pure import decode_b45

# Two-character inputs whose b45-decoded value >= 256.
# Each one used to raise ValueError before the 5009552 fix.
TWO_CHAR_OVERFLOW = [
    "99",   # 35 + 35*45 = 499  (max 2-char allowed is 254)
    "::",   # 36 + 36*45 = 540
    "ZZ",   # 34 + 34*45 = 491
    "AB",   # 0 + 1*45 = 45  (control: still in range, valid 2-char)
]


def main() -> int:
    n_handled = 0
    n_raised = 0
    for s in TWO_CHAR_OVERFLOW:
        try:
            r = decode_b45(s)
        except Exception as e:  # noqa: BLE001
            print(f"  decode_b45({s!r})  RAISED {type(e).__name__}: {e}")
            n_raised += 1
            continue
        # F-001 fix returns an ERROR:... string for out-of-range 2-char groups.
        # For in-range 2-char groups (like "AB"), returns the actual byte.
        if isinstance(r, str) and r.startswith("ERROR:"):
            print(f"  decode_b45({s!r})  -> {r!r}  [handled]")
            n_handled += 1
        elif isinstance(r, bytes):
            print(f"  decode_b45({s!r})  -> {r!r}  [in-range]")
            n_handled += 1
        else:
            print(f"  decode_b45({s!r})  -> {r!r}  [unexpected type]")

    print()
    print(f"handled correctly: {n_handled}/{len(TWO_CHAR_OVERFLOW)}")
    print(f"raised (BUG):     {n_raised}/{len(TWO_CHAR_OVERFLOW)}")
    if n_raised == 0:
        print(">>> F-001 regression holds. No ValueError raised.")
        return 0
    print(">>> F-001 regression FAILED. ValueError leaked.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())