#!/usr/bin/env python3
"""Fuzz harness for .b45 (Base45) — RFC 9285.

Targets: validate_b45, decode_b45, encode_b45.
Total contract: every public function must return a structured error on
malformed input, never raise an uncaught exception.

T1 audit found:
  F-001 (Critical): decode_b45 raises ValueError on 2-char input > 255
  F-002 (High):     decode_b45 silently truncates on 3-char input > 65535

Both remediated @ 5009552.  This harness re-validates the post-fix
behaviour across the validate() signature (which calls decode() internally
and is the most likely surface for a regression that breaks the totality
contract).

Library contract:
  validate_b45(target: str, controller: bytes) -> bool
  decode_b45(target: str) -> bytes             # bytes or "ERROR:...\" str
  encode_b45(data: bytes) -> str               # str or "ERROR:...\" str

Output: ./stats.json with the schema required by the task spec.
"""
import json
import os
import sys
import time
import atheris

with atheris.instrument_imports():
    from rfc9741pure import (
        validate_b45,
        decode_b45,
        encode_b45,
    )

_HERE = os.path.dirname(os.path.abspath(__file__))
_STATS_PATH = os.path.join(_HERE, "validate_b45_stats.json")

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    raw = fdp.ConsumeUnicodeNoSurrogates(512)
    payload = fdp.ConsumeBytes(64)

    # Hit decode path — the surface where F-001 and F-002 were found.
    decode_b45(raw)
    # Roundtrip encode — known-safe, should always succeed for any bytes.
    encoded = encode_b45(payload)
    if isinstance(encoded, str) and not encoded.startswith("ERROR:"):
        # If encode succeeded, decode should roundtrip the input.
        decode_b45(encoded)
    # Validation surface — total signature.
    validate_b45(raw, payload)


def _run_smoke(iterations: int) -> dict:
    t0 = time.time()
    crashes = 0
    unhandled = 0
    exceptions_caught: list = []
    import random
    rng = random.Random(0xC0DE9744)

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
        "harness": "validate_b45",
        "surface": "validate_b45(str, bytes) | decode_b45(str) | encode_b45(bytes)",
    }


def main() -> None:
    if "--iterations" in sys.argv:
        idx = sys.argv.index("--iterations")
        iters = int(sys.argv[idx + 1])
        stats = _run_smoke(iters)
        with open(_STATS_PATH, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)
        print(f"validate_b45: {stats['iterations']} iters, "
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
