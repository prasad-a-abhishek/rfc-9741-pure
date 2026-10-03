# F-002 (regression test) — decode_b45 3-char overflow no longer silent-truncates

## Severity

**n/a (regression-check PASS, originally High)**

Regression test for the High F-002 finding from the original
VULN_AUDIT (cycle_165/adversary/T1 at 8bdecaf). F-002 was remediated
at commit **5009552** in the same orchestrator-rescue commit as
F-001 and F-003.

## Original bug (pre-5009552)

`decode_b45`'s 3-char-group branch did:

```python
value = v0 + v1 * 45 + v2 * 45 * 45
out.append((value >> 8) & 0xFF)  # high byte
out.append(value & 0xFF)          # low byte
```

For 3-char inputs whose `value >= 65536` (e.g. `'ZZZ'` → 72485),
this would emit `(72485 >> 8) & 0xFF = 35` and `72485 & 0xFF = 0xE5`
as the output bytes — silently dropping the high 9 bits of the
value and breaking the byte-stream invariant for downstream
consumers (CDDL validators would see wrong bytes for RFC 9741
`.b45 c` control groups).

## Surface

`src/rfc9741pure/_b45.py:86-87` (the 3-char group branch in
`decode_b45`).

## Fix (commit 5009552)

```python
# 3-char group: value = c + d*45 + e*45*45
value = v0 + v1 * 45 + v2 * 45 * 45
# F-002 fix: 3-char values MUST be < 65536 per RFC 9285 §4.2
if value >= 65536:
    return _err(f"decode_b45: 3-char value {value} exceeds 16-bit")
try:
    out.append((value >> 8) & 0xFF)  # high byte
    out.append(value & 0xFF)          # low byte
except ValueError:
    return _err(f"decode_b45: invalid byte value {value}")
```

## Regression test evidence

- **Static (pytest)**: `tests/test_b45.py::TestB45VulnAuditFixes` was
  added in the same commit. The fuzz campaign didn't need to find a
  new bug here because pytest already locks the contract.
- **Fuzz (this campaign)**: 200K iterations across the
  `validate_b45` and `decode_b45` harnesses. Both ran
  `FuzzedDataProvider.ConsumeUnicodeNoSurrogates` for 100K iters
  each. Zero crashes, zero unhandled exceptions.
  - `cycle_165/adversary/fuzz/decode_b45_stats.json` — iter=100000, crashes=0, unhandled=0
  - `cycle_165/adversary/fuzz/validate_b45_stats.json` — iter=100000, crashes=0, unhandled=0

## Reproduction (minimised)

```text
# minimized_input.txt content (3 bytes, ASCII):
ZZZ

# Invoked as:
PYTHONPATH=src python3 -c "from rfc9741pure import decode_b45; print(decode_b45('ZZZ'))"
# Post-fix output:
#   ERROR:decode_b45: 3-char value 72485 exceeds 16-bit
```

## Disposition

The fix is in place and zero High CVE instances have been observed
in this campaign.

**Status: PASS. Closed.**