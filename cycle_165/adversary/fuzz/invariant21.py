#!/usr/bin/env python3
"""Fuzz harness for Invariant 21 (totality over arbitrary input).

Invariant 21 contract: every public function must accept any input type and
return a structured error (False / "ERROR:...\" / None) — never raise
AttributeError, TypeError, or any other uncaught exception.

This harness feeds each of the 23 public encode/validate functions one of
nine intentionally-wrong-typed objects and asserts the function returns
without raising.

Public functions under test (from rfc9741pure.__all__):
  b64u:  decode_b64u, encode_b64u, validate_b64u
  b64c:  decode_b64c, encode_b64c, validate_b64c
  hex:   decode_hex, encode_hex, validate_hex, validate_hexlc, validate_hexuc
  b45:   decode_b45, encode_b45, validate_b45
  base10: decode_base10, encode_base10, validate_base10
  printf: decode_printf, format_printf, validate_printf
  json:  decode_json, encode_json, validate_json

Output: ./stats.json with the schema required by the task spec.
"""
import json
import os
import sys
import time
import atheris

with atheris.instrument_imports():
    import rfc9741pure  # noqa: F401
    from rfc9741pure import (
        decode_b64u, encode_b64u, validate_b64u,
        decode_b64c, encode_b64c, validate_b64c,
        decode_hex, encode_hex, validate_hex, validate_hexlc, validate_hexuc,
        decode_b45, encode_b45, validate_b45,
        decode_base10, encode_base10, validate_base10,
        decode_printf, format_printf, validate_printf,
        decode_json, encode_json, validate_json,
    )

_HERE = os.path.dirname(os.path.abspath(__file__))
_STATS_PATH = os.path.join(_HERE, "invariant21_stats.json")


# A library that respects Invariant 21 must return, not raise, for any of these.
_WRONG_TYPE_PAYLOADS = [
    None,
    42,
    True,
    [],
    {},
    b"x",
    3.14,
    float("nan"),
    float("inf"),
]


def _pick_payload(fdp):
    idx = fdp.ConsumeIntInRange(0, len(_WRONG_TYPE_PAYLOADS) - 1)
    return _WRONG_TYPE_PAYLOADS[idx]


def _pick_function(fdp):
    """Pick which public function to attack.  Returns (fn, arity)."""
    table = [
        # arity 1: decode / encode
        (decode_b64u, 1),
        (encode_b64u, 1),
        (decode_b64c, 1),
        (encode_b64c, 1),
        (decode_hex, 1),
        (encode_hex, 1),
        (decode_b45, 1),
        (encode_b45, 1),
        (decode_base10, 1),
        (encode_base10, 1),
        (decode_printf, 1),
        (format_printf, 1),     # called with one payload arg
        (decode_json, 1),
        (encode_json, 1),
        # arity 2: validate(target, controller)
        (validate_b64u, 2),
        (validate_b64c, 2),
        (validate_hex, 2),
        (validate_hexlc, 2),
        (validate_hexuc, 2),
        (validate_b45, 2),
        (validate_base10, 2),
        (validate_printf, 2),
        (validate_json, 2),
    ]
    idx = fdp.ConsumeIntInRange(0, len(table) - 1)
    return table[idx]


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    fn, arity = _pick_function(fdp)
    payload = _pick_payload(fdp)
    try:
        if arity == 1:
            fn(payload)
        else:
            # For arity-2 validates, feed two different wrong-typed payloads.
            payload2 = _pick_payload(fdp)
            fn(payload, payload2)
    except (ValueError, TypeError, KeyError, IndexError, AttributeError):
        # These are findings — let atheris record them as crashes.
        raise


def _run_smoke(iterations: int) -> dict:
    t0 = time.time()
    crashes = 0
    unhandled = 0
    exceptions_caught: list = []
    import random
    rng = random.Random(0xC0DE9745)

    for i in range(iterations):
        data = bytes(rng.getrandbits(8) for _ in range(32))
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
        "harness": "invariant21",
        "surface": "23 public functions x 9 wrong-typed payloads",
    }


def main() -> None:
    if "--iterations" in sys.argv:
        idx = sys.argv.index("--iterations")
        iters = int(sys.argv[idx + 1])
        stats = _run_smoke(iters)
        with open(_STATS_PATH, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)
        print(f"invariant21: {stats['iterations']} iters, "
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
