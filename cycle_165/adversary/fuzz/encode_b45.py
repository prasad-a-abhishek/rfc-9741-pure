#!/usr/bin/env python3
"""Fuzz harness for encode_b45 — the dedi cated encode surface (cycle_165/adv_retry/T2).

Targets: encode_b45(bytes) -> str | "ERROR:..." str
Total contract: NEVER raise; always return str (which is the encoded form
or a structured "ERROR:..." string).

Surface mapping:
  - empty bytes         -> ""
  - 1-byte input        -> 2-char output (the trailing-byte branch)
  - 2-byte input        -> 3-char output
  - 4-byte input        -> 6-char output (2 pairs)
  - long input (256 B)  -> 384-char output
  - surrogate bytes     -> valid in 0..255 range, so any byte is fine
  - Type confusion:     -> ERROR (must not raise TypeError or AttributeError)
  - Roundtrip:          -> encode(decode(x)) should not crash

Output: ./stats.json with the schema required by the task spec.
"""
import json
import os
import sys
import time
import atheris

with atheris.instrument_imports():
    from rfc9741pure import encode_b45, decode_b45  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))
_STATS_PATH = os.path.join(_HERE, "encode_b45_stats.json")

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    # Pick a surface strategy.
    strategy = fdp.ConsumeIntInRange(0, 5)
    if strategy == 0:
        # Empty bytes.
        payload = b""
    elif strategy == 1:
        # Single byte — exercises the trailing-byte branch.
        payload = bytes([fdp.ConsumeIntInRange(0, 255)])
    elif strategy == 2:
        # Two bytes — the most common 3-char encoded form.
        payload = bytes([
            fdp.ConsumeIntInRange(0, 255),
            fdp.ConsumeIntInRange(0, 255),
        ])
    elif strategy == 3:
        # Arbitrary length up to 64 bytes.
        n = fdp.ConsumeIntInRange(0, 64)
        payload = fdp.ConsumeBytes(n)
    elif strategy == 4:
        # "Surrogate-ish" bytes — bytes in 0xD8..0xDF (UTF-16 surrogate
        # range) are perfectly valid for base45; this just confirms
        # encode_b45 doesn't care about UTF-8 semantics.
        payload = bytes([fdp.ConsumeIntInRange(0xD8, 0xDF)] * 4)
    else:
        # Long input — 256 bytes (max realistic for one round-trip).
        payload = fdp.ConsumeBytes(256)

    # Contract: total function — must NEVER raise, return str.
    result = encode_b45(payload)
    assert isinstance(result, str), (
        f"encode_b45 returned unexpected type {type(result).__name__}: {result!r}"
    )
    if not result.startswith("ERROR:"):
        # If encode succeeded, decode the result and check it doesn't crash.
        # Per RFC 9285 §4 round-trip is lossless for any bytes input.
        decoded = decode_b45(result)
        if isinstance(decoded, bytes):
            assert decoded == payload, (
                f"round-trip mismatch: encoded {payload!r} -> {result!r} -> {decoded!r}"
            )

    # Also fuzz the type-confusion surface: pass non-bytes.
    bad_kind = fdp.ConsumeIntInRange(0, 3)
    if bad_kind == 0:
        try:
            encode_b45("not bytes")  # type: ignore[arg-type]
        except Exception as e:  # noqa: BLE001
            # Must be a structured ERROR string, not an uncaught exception.
            # The contract says return "ERROR:..."; raising is a finding.
            raise AssertionError(
                f"encode_b45 raised {type(e).__name__} on str input: {e}"
            )
    elif bad_kind == 1:
        try:
            encode_b45(None)  # type: ignore[arg-type]
        except Exception as e:  # noqa: BLE001
            raise AssertionError(
                f"encode_b45 raised {type(e).__name__} on None input: {e}"
            )
    elif bad_kind == 2:
        try:
            encode_b45([1, 2, 3])  # type: ignore[arg-type]
        except Exception as e:  # noqa: BLE001
            raise AssertionError(
                f"encode_b45 raised {type(e).__name__} on list input: {e}"
            )
    # bad_kind == 3: skip type-confusion this iter.


def _run_smoke(iterations: int) -> dict:
    t0 = time.time()
    crashes = 0
    unhandled = 0
    exceptions_caught: list = []
    import random
    rng = random.Random(0xC0DE9742)

    for i in range(iterations):
        data = bytes(rng.getrandbits(8) for _ in range(96))
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
        "harness": "encode_b45",
        "surface": "encode_b45(bytes) -> str | ERROR",
    }


def main() -> None:
    if "--iterations" in sys.argv:
        idx = sys.argv.index("--iterations")
        iters = int(sys.argv[idx + 1])
        stats = _run_smoke(iters)
        with open(_STATS_PATH, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)
        print(f"encode_b45: {stats['iterations']} iters, "
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
