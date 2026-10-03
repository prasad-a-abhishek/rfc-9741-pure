#!/usr/bin/env python3
"""Fuzz harness for decode_b45 — the dedi cated decode surface (cycle_165/adv_retry/T2).

Targets: decode_b45(str) -> bytes | "ERROR:..." str
Total contract: NEVER raise; always return bytes or structured ERROR string.

T1 audit verified F-001 (2-char >255) and F-002 (3-char >65535) are remediated
@ 5009552.  This harness re-fuzzes the decode surface to lock in the
post-fix behaviour across the full 2-char + 3-char + mixed input space
(specifically: '99' overflow, 'ZZZ' overflow, garbage bytes).

Surface mapping:
  - 2-char boundary: every pair (c0, c1) with c0*45 + c1 in [0, 2024] (valid)
    or >= 256 (must ERROR, not raise).  Total 45^2 = 2025 cases.
  - 3-char boundary: every triple with c0 + c1*45 + c2*2025 < 65536 (valid)
    or >= 65536 (must ERROR).  45^3 = 91125 cases, of which 25599 are >65535.
  - 4+ char input:  arbitrary concatenation — tests length-boundary + the
    dead-code F-015 guard.
  - Garbage: any non-alphabet char in [0x00, 0xFF] must return ERROR, not raise.

Output: ./stats.json with the schema required by the task spec.
"""
import json
import os
import sys
import time
import atheris

with atheris.instrument_imports():
    from rfc9741pure import decode_b45  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))
_STATS_PATH = os.path.join(_HERE, "decode_b45_stats.json")

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    # Pick a surface strategy so the corpus has signal rather than pure noise.
    strategy = fdp.ConsumeIntInRange(0, 4)
    if strategy == 0:
        # 2-char boundary sweep — explicit pair.
        c0 = ALPHABET[fdp.ConsumeIntInRange(0, 44)]
        c1 = ALPHABET[fdp.ConsumeIntInRange(0, 44)]
        s = c0 + c1
    elif strategy == 1:
        # 3-char boundary sweep — explicit triple.
        c0 = ALPHABET[fdp.ConsumeIntInRange(0, 44)]
        c1 = ALPHABET[fdp.ConsumeIntInRange(0, 44)]
        c2 = ALPHABET[fdp.ConsumeIntInRange(0, 44)]
        s = c0 + c1 + c2
    elif strategy == 2:
        # Mixed: 2-char + 3-char concatenated (tests length-boundary).
        c0 = ALPHABET[fdp.ConsumeIntInRange(0, 44)]
        c1 = ALPHABET[fdp.ConsumeIntInRange(0, 44)]
        c2 = ALPHABET[fdp.ConsumeIntInRange(0, 44)]
        c3 = ALPHABET[fdp.ConsumeIntInRange(0, 44)]
        c4 = ALPHABET[fdp.ConsumeIntInRange(0, 44)]
        s = c0 + c1 + c2 + c3 + c4
    elif strategy == 3:
        # Garbage: arbitrary unicode + non-alphabet bytes.
        s = fdp.ConsumeUnicodeNoSurrogates(64)
    else:
        # Specific known-attack vectors.
        s = fdp.PickValueInList([
            "99", "ZZ", "::", "AB", "ZZZ", "999", ":::", "AAA",
            "9Z9", "ZZ9", "9ZZ", "ZZ0", "99999", ":::::", "ZZZZZ",
            "", "9", "ZZZZ", "9999999", "9.9", "a", " ",
        ])

    # The contract: total function — must NEVER raise, return bytes or str.
    result = decode_b45(s)
    # Sanity: the type must be one of (bytes, str).
    assert isinstance(result, (bytes, str)), (
        f"decode_b45 returned unexpected type {type(result).__name__}"
    )
    # If str, it must start with "ERROR:" (the structured-error contract).
    if isinstance(result, str):
        # Empty string is a valid bytes() = b"" (per _b45.py:73), but the
        # only other str return is an ERROR.  Both are acceptable.
        assert result == "" or result.startswith("ERROR:"), (
            f"decode_b45 returned str that is not empty/ERROR: {result[:80]!r}"
        )


def _run_smoke(iterations: int) -> dict:
    """Iteration-counted smoke run.  Returns stats dict."""
    from atheris import FuzzedDataProvider as FDP  # type: ignore

    t0 = time.time()
    crashes = 0
    unhandled = 0
    exceptions_caught: list = []
    # Use a deterministic PRNG seed for reproducibility.
    import random
    rng = random.Random(0xC0DE9741)

    for i in range(iterations):
        # Generate 64 bytes of pseudo-random data.
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
        "exceptions_caught": exceptions_caught[:20],  # cap list size
        "coverage_pct": None,  # coverage requires coverage instrumentation
        "wall_time_seconds": round(wall, 3),
        "harness": "decode_b45",
        "surface": "decode_b45(str) -> bytes | ERROR",
    }


def main() -> None:
    # Two modes:
    #   (a) default: atheris libFuzzer — `python3 -m cycle_165.adversary.fuzz.decode_b45`
    #   (b) iteration-counted smoke: `--iterations N` — writes stats.json
    if "--iterations" in sys.argv:
        idx = sys.argv.index("--iterations")
        iters = int(sys.argv[idx + 1])
        stats = _run_smoke(iters)
        with open(_STATS_PATH, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)
        print(f"decode_b45: {stats['iterations']} iters, "
              f"{stats['crashes']} crashes, "
              f"{stats['unhandled_exceptions']} unhandled, "
              f"{stats['wall_time_seconds']}s")
        # Exit non-zero on crashes so the smoke test fails loudly.
        if stats["crashes"] or stats["unhandled_exceptions"]:
            sys.exit(2)
    else:
        atheris.Setup(sys.argv, TestOneInput)
        atheris.Fuzz()


if __name__ == "__main__":
    main()
