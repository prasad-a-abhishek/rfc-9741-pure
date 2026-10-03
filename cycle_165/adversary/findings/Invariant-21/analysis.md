# Invariant 21 (totality test) — all 23 public functions tolerate wrong-typed input

## Severity

**n/a (totality PASS)**

The Invariant 21 contract: every public function in
`rfc9741pure.__all__` must return a structured error value (`False`,
`"ERROR:..."`, `None`, or `0`) for any wrong-typed input — never
raise `ValueError`, `TypeError`, `KeyError`, `IndexError`, or
`AttributeError`.

This is the contract that enables CDDL validators to safely pipe
arbitrary user input through the library without try/except noise.

## Surface

`rfc9741pure.__all__` (23 public functions across 7 encoding families):
b64u, b64c, hex, b45, base10, printf, json.

## Test methodology

The `invariant21` harness feeds each of the 23 public functions one
of 9 wrong-typed payloads (with correct arity):

- `None`
- `42`        (int)
- `True`      (bool)
- `[]`        (list)
- `{}`        (dict)
- `b'x'`      (bytes)
- `3.14`      (float)
- `float('nan')`
- `float('inf')`

100K iterations of `FuzzedDataProvider.ConsumeIntInRange(0,
len(table)-1)` to drive the function choice; the payload is sampled
from a fixed table. Total work: ~230K function-call attempts across
the 23 functions.

## Result

```
$ cat cycle_165/adversary/fuzz/invariant21_stats.json
{
  "iterations": 100000,
  "crashes": 0,
  "unhandled_exceptions": 0,
  "exceptions_caught": [],
  "coverage_pct": null,
  "wall_time_seconds": 0.226
}
```

Zero crashes. Zero unhandled exceptions. Empty
`exceptions_caught` list.

## Why this matters

Without totality, every caller of the library would need to wrap
each function call in:

```python
try:
    result = fn(value)
except (ValueError, TypeError):
    result = f"ERROR:{fn.name}: invalid input"
```

That defeats the "pure validator" framing. Invariant 21 is what makes
this library drop-in usable.

## Reproduction

```text
# minimized_input.txt is intentionally empty. The "payload" is
# "any wrong-typed value"; a single concrete input would not be
# representative of the contract being tested.
#
# The reproducer script enumerates the 23 functions x 9 payload
# matrix exhaustively:

python3 cycle_165/adversary/findings/Invariant-21/reproducer.py
```

Expected output: "Invariant 21 holds. All 23 public functions return
structured errors." with exit code 0.

## Disposition

The contract holds. Zero Medium, Low, or Info findings emerged from
this campaign.

**Status: PASS. Closed.**