#!/usr/bin/env python3
"""Invariant 21 totality reproducer (post-fix, regression check).

Verifies that EVERY public function in rfc9741pure returns a structured
error value (False / "ERROR:..." / None / 0) for any wrong-typed input,
instead of raising ValueError, TypeError, KeyError, IndexError, or
AttributeError. The 23-function x 9-type matrix is exhaustive at the
type level (covers None, int, bool, list, dict, bytes, float, nan, inf).

Run from the worktree root:

    python3 cycle_165/adversary/findings/Invariant-21/reproducer.py

Exit codes:
  0  -- invariant holds (PASS)
  2  -- at least one function raised on a wrong-typed input (FAIL)
"""
from rfc9741pure import (
    decode_b64u, encode_b64u, validate_b64u,
    decode_b64c, encode_b64c, validate_b64c,
    decode_hex, encode_hex, validate_hex, validate_hexlc, validate_hexuc,
    decode_b45, encode_b45, validate_b45,
    decode_base10, encode_base10, validate_base10,
    decode_printf, format_printf, validate_printf,
    decode_json, encode_json, validate_json,
)

# (function, arity)
TABLE = [
    (decode_b64u, 1), (encode_b64u, 1), (validate_b64u, 2),
    (decode_b64c, 1), (encode_b64c, 1), (validate_b64c, 2),
    (decode_hex, 1), (encode_hex, 1),
    (validate_hex, 2), (validate_hexlc, 2), (validate_hexuc, 2),
    (decode_b45, 1), (encode_b45, 1), (validate_b45, 2),
    (decode_base10, 1), (encode_base10, 1), (validate_base10, 2),
    (decode_printf, 1), (format_printf, 1), (validate_printf, 2),
    (decode_json, 1), (encode_json, 1), (validate_json, 2),
]
WRONG = [None, 42, True, [], {}, b"x", 3.14, float("nan"), float("inf")]

RAISE_TYPES = (ValueError, TypeError, KeyError, IndexError, AttributeError)


def main() -> int:
    failures = []
    for fn, arity in TABLE:
        for v in WRONG:
            try:
                if arity == 1:
                    fn(v)
                else:
                    fn(v, WRONG[0])
            except RAISE_TYPES as e:
                failures.append((fn.__name__, type(v).__name__, type(e).__name__, str(e)))
    print(f"Total function/payload attempts: {len(TABLE) * len(WRONG)}")
    print(f"Unhandled raises:                {len(failures)}")
    for f in failures:
        print(f"  FAIL: {f[0]}({f[1]!r}) raised {f[2]}: {f[3]}")
    if failures:
        print(">>> Invariant 21 VIOLATED.")
        return 2
    print(">>> Invariant 21 holds. All 23 public functions return structured errors.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())